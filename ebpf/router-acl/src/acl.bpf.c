// SPDX-License-Identifier: GPL-2.0-only
/*
 * acl.bpf.c - mydist TC eBPF ACL (router-acl).
 *
 * See src/acl_common.h for the redlines, the hook layout and why the IPv4
 * table is keyed by the *remote endpoint*. Short version:
 *
 *   ingress (WAN) : the filter. Drops unsolicited inbound, marks what it
 *                   approved when it learned the flow itself.
 *   egress  (WAN) : the learner. Records what the LAN (and the router) sent out
 *                   so the ingress side can recognise the replies.
 *
 * It does not do NAT, does not read einat's maps, never redirects. Anything it
 * is not sure about is passed through as TC_ACT_UNSPEC so fw4 still gets to
 * decide -- the ACL is a pre-filter, never the last word on protocols it does
 * not model.
 *
 * Compiled twice from this one file:
 *   -DACL_BUILD_INGRESS  -> acl_ingress.bpf.o  (attach: ingress pref 90)
 *   -DACL_BUILD_EGRESS   -> acl_egress.bpf.o   (attach: egress  pref 90)
 * Each object defines the same maps; LIBBPF_PIN_BY_NAME makes the second load
 * reuse the first one's maps, so cfg/stats/flow tables are shared.
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "acl_common.h"

/* must match ACL_BPF_SECTION in acl_common.h; SEC() stringises so it cannot be
 * passed a macro. The init script uses the macro, so keep the two in sync. */
#define ACL_SEC_NAME "classifier"

/* AF_* are frozen ABI values; linux/bpf.h does not drag in linux/socket.h */
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* Ethertypes and IP protocol numbers we need. linux/if_ether.h covers the first
 * two on any sane toolchain; the rest are frozen ABI so spell them out rather
 * than depending on which UAPI headers are installed. */
#ifndef ETH_P_IP
#define ETH_P_IP	0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6	0x86DD
#endif
#define ETH_P_8021Q	0x8100
#define ETH_P_8021AD	0x88A8

#define IPPROTO_ICMP_	1
#define IPPROTO_TCP_	6
#define IPPROTO_UDP_	17
#define IPPROTO_ICMPV6_	58

/* ICMPv4 */
#define ICMP_ECHOREPLY_		0
#define ICMP_DEST_UNREACH_	3
#define ICMP_ECHO_		8
#define ICMP_TIME_EXCEEDED_	11
#define ICMP_PARAMETERPROB_	12

/* ICMPv6 */
#define ICMPV6_DEST_UNREACH_	1
#define ICMPV6_PKT_TOOBIG_	2
#define ICMPV6_TIME_EXCEED_	3
#define ICMPV6_PARAMPROB_	4
#define ICMPV6_ECHO_REQUEST_	128
#define ICMPV6_ECHO_REPLY_	129
#define ICMPV6_MLD_QUERY_	130
#define ICMPV6_MLD_REPORT_	131
#define ICMPV6_MLD_DONE_	132
#define ICMPV6_ROUTER_SOLICIT_	133
#define ICMPV6_ROUTER_ADVERT_	134
#define ICMPV6_NEIGH_SOLICIT_	135
#define ICMPV6_NEIGH_ADVERT_	136
#define ICMPV6_REDIRECT_	137

#define IPV4_MIN_IHL	20
#define IPV4_MAX_IHL	60

/* Minimal ICMP headers. linux/icmp.h is not in the UAPI set the BPF build uses
 * and we only need the first eight bytes anyway. */
struct acl_icmphdr {
	__u8	type;
	__u8	code;
	__be16	checksum;
	union {
		struct { __be16 id; __be16 sequence; } echo;
		__be32	gateway;
		__u8	reserved[4];
	} un;
};

struct acl_icmp6hdr {
	__u8	type;
	__u8	code;
	__be16	checksum;
	union {
		struct { __be16 id; __be16 sequence; } echo;
		__be32	data;
		__u8	reserved[4];
	} un;
};

/* ------------------------------------------------------------------ maps */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct acl_config);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, AS_MAX);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_stats SEC(".maps");

/* IPv4 per-flow state for flows the box started, learned on egress. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct acl_v4_key);
	__type(value, struct acl_v4_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_v4_flows SEC(".maps");

/* Explicit allow list. A plain hash, not LRU: it must not be evicted. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct acl_port_key);
	__type(value, struct acl_port_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_ports SEC(".maps");

/* IPv6 per-flow state, stored in the LAN->WAN direction. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct acl_v6_key);
	__type(value, struct acl_v6_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} acl_v6_flows SEC(".maps");

/* ------------------------------------------------------------------ helpers */

static __always_inline void stat_add(__u32 idx, __u64 v)
{
	__u64 *p = bpf_map_lookup_elem(&acl_stats, &idx);

	if (p)
		*p += v;
}

/* read the config once per packet; also enforces the killer switch */
static __always_inline struct acl_config *acl_cfg_get(void)
{
	__u32 zero = 0;
	struct acl_config *c = bpf_map_lookup_elem(&acl_cfg, &zero);

	if (!c || c->mode == ACL_MODE_OFF)
		return NULL;
	return c;
}

/* Ethernet header, with one level of VLAN unwrapped. Returns the L3 offset or
 * -1 if the frame is too short to be sure. */
static __always_inline int acl_l3_off(void *data, void *data_end, __u16 *proto)
{
	struct ethhdr *eth = data;
	__u32 off = sizeof(*eth);
	__be16 *tag;

	if ((void *)(eth + 1) > data_end)
		return -1;
	*proto = bpf_ntohs(eth->h_proto);

	if (*proto == ETH_P_8021Q || *proto == ETH_P_8021AD) {
		tag = data + off;
		if ((void *)(tag + 2) > data_end)
			return -1;
		*proto = bpf_ntohs(tag[1]);
		off += 4;
	}
	return (int)off;
}

static __always_inline int acl_l4_ports(void *l4, void *data_end, __u8 proto,
					__be16 *sp, __be16 *dp)
{
	if (proto == IPPROTO_TCP_) {
		struct tcphdr *t = l4;

		if ((void *)(t + 1) > data_end)
			return -1;
		*sp = t->source;
		*dp = t->dest;
		return 0;
	}
	if (proto == IPPROTO_UDP_) {
		struct udphdr *u = l4;

		if ((void *)(u + 1) > data_end)
			return -1;
		*sp = u->source;
		*dp = u->dest;
		return 0;
	}
	return -1;
}

static __always_inline int acl_v4_expired(struct acl_config *cfg, __u64 now,
					  __u64 last, __u16 proto)
{
	__u64 t;

	if (proto == IPPROTO_TCP_)
		t = (__u64)cfg->tcp_timeout_ms * 1000000ULL;
	else if (proto == IPPROTO_UDP_)
		t = (__u64)cfg->udp_timeout_ms * 1000000ULL;
	else
		t = (__u64)cfg->icmp_timeout_ms * 1000000ULL;

	return now - last > t;
}

/* Is this protocol/port pair explicitly allowed for this scope? port 0 means
 * "every port of this protocol". */
static __always_inline int acl_port_allowed(__u16 family, __u16 proto, __u16 scope,
					    __be16 port)
{
	struct acl_port_key pk;
	struct acl_port_val *pv;

	pk.family = family;
	pk.proto = proto;
	pk.scope = scope;
	pk.port = port;
	pv = bpf_map_lookup_elem(&acl_ports, &pk);
	if (pv)
		return 1;

	pk.port = 0;
	pv = bpf_map_lookup_elem(&acl_ports, &pk);
	return pv ? 1 : 0;
}

/* Is this destination inside one of the configured LAN prefixes? Only used by
 * the opt-in `fullcone` path: it is the one check that cannot tell "einat
 * un-SNATed this into the LAN" from "somebody forged a LAN destination", which
 * is why it is off by default.
 *
 * The prefixes are unrolled on purpose. With a runtime loop the verifier could
 * not bound the index by the array size (it saw the fifth iteration touch
 * offset 76 of a 72-byte map value) and rejected the whole program with
 * EACCES: "invalid access to map value, value_size=72 off=76". That took
 * acl_ingress off the WAN entirely -- the guard, the port allow-list and the
 * bypass marks were all missing while the service looked "enabled". Constant
 * indices need no range proof, so each access is accepted on its own. */
static __always_inline int acl_lan_v4_match(struct acl_config *cfg, __be32 daddr)
{
	if (!cfg->fullcone)
		return 0;

	_Static_assert(ACL_MAX_LAN_V4 == 4,
		       "acl_lan_v4_match is unrolled for four prefixes");

	if (cfg->lan_count > 0 &&
	    (daddr & cfg->lan_v4[0].mask) == cfg->lan_v4[0].net)
		return 1;
	if (cfg->lan_count > 1 &&
	    (daddr & cfg->lan_v4[1].mask) == cfg->lan_v4[1].net)
		return 1;
	if (cfg->lan_count > 2 &&
	    (daddr & cfg->lan_v4[2].mask) == cfg->lan_v4[2].net)
		return 1;
	if (cfg->lan_count > 3 &&
	    (daddr & cfg->lan_v4[3].mask) == cfg->lan_v4[3].net)
		return 1;

	return 0;
}

/*
 * Apply the mark. Only called for traffic that we learned ourselves and only in
 * BYPASS mode. Marking is what lets fw4's raw chain notrack the flow and its
 * forward chain accept the reply without a ct state match.
 */
static __always_inline int acl_verdict(struct __sk_buff *skb,
				       struct acl_config *cfg, int mark_it)
{
	if (mark_it && cfg->mode == ACL_MODE_BYPASS) {
		skb->mark = cfg->mark;
		stat_add(AS_MARKED, 1);
	}
	return TC_ACT_UNSPEC;
}

/* Quoted-packet lookup for an ICMPv4 error. The quoted packet is one we sent,
 * so its *destination* is the remote endpoint -- exactly the key the egress
 * learner wrote. The remote side is untouched by einat's SNAT, so this works
 * whether or not einat also rewrote the quoted header. */
static __always_inline int acl_v4_inner_key(void *data_end, void *l4,
					    struct acl_v4_key *k)
{
	__u8 *q = l4 + 8;
	struct iphdr *iph;
	__u32 ihl;
	void *il4;
	struct acl_icmphdr *ic;

	__builtin_memset(k, 0, sizeof(*k));

	if (q + sizeof(*iph) > (__u8 *)data_end)
		return -1;
	iph = (struct iphdr *)q;
	if (iph->version != 4)
		return -1;
	ihl = (__u32)iph->ihl * 4;
	if (ihl < IPV4_MIN_IHL || ihl > IPV4_MAX_IHL)
		return -1;
	il4 = q + ihl;

	if (iph->protocol == IPPROTO_TCP_ || iph->protocol == IPPROTO_UDP_) {
		__be16 sp, dp;

		if (acl_l4_ports(il4, data_end, iph->protocol, &sp, &dp) < 0)
			return -1;
		k->proto = iph->protocol;
		k->ip = iph->daddr;
		k->port = dp;
		return 0;
	}
	if (iph->protocol == IPPROTO_ICMP_) {
		ic = il4;
		if ((void *)(ic + 1) > data_end)
			return -1;
		k->proto = IPPROTO_ICMP_;
		k->ip = iph->daddr;
		k->port = ic->un.echo.id;
		return 0;
	}
	return -1;
}

/* ------------------------------------------------------------------ ingress */

#ifdef ACL_BUILD_INGRESS

static __always_inline int acl_ingress_v4(struct __sk_buff *skb,
					  struct acl_config *cfg,
					  void *data, void *data_end,
					  __u32 off, __u64 now)
{
	struct iphdr *iph = data + off;
	struct acl_icmphdr *ic;
	struct acl_v4_key k = {};
	struct acl_v4_val *v;
	__u32 ihl;
	void *l4;
	__u16 sport = 0, dport = 0;
	__u16 frag;

	stat_add(AS_INGRESS_PKT, 1);

	if ((void *)(iph + 1) > data_end) {
		stat_add(AS_INGRESS_DROP, 1);
		return TC_ACT_SHOT;
	}
	ihl = (__u32)iph->ihl * 4;
	if (ihl < IPV4_MIN_IHL || ihl > IPV4_MAX_IHL) {
		stat_add(AS_INGRESS_DROP, 1);
		return TC_ACT_SHOT;
	}
	l4 = (void *)iph + ihl;
	if (l4 > data_end) {
		stat_add(AS_INGRESS_DROP, 1);
		return TC_ACT_SHOT;
	}

	/* Non-first fragments carry no L4 header. Passing them is safe: they are
	 * useless without a first fragment, and that one is filtered here. */
	frag = bpf_ntohs(iph->frag_off);
	if ((frag & 0x1fff) != 0)
		return TC_ACT_UNSPEC;

	if (iph->protocol == IPPROTO_TCP_ || iph->protocol == IPPROTO_UDP_) {
		if (acl_l4_ports(l4, data_end, iph->protocol, &sport, &dport) < 0) {
			stat_add(AS_INGRESS_DROP, 1);
			return TC_ACT_SHOT;
		}
		/* The remote endpoint is the one field einat's un-SNAT does not
		 * touch, so it is what the egress learner keyed on. Keying on
		 * the port instead cannot work: einat's SNAT on the way out and
		 * its un-SNAT on the way back change the port, so the two hooks
		 * never see the same number. */
		k.proto = iph->protocol;
		k.ip = iph->saddr;
		k.port = sport;
		v = bpf_map_lookup_elem(&acl_v4_flows, &k);
		if (v && !acl_v4_expired(cfg, now, v->last_seen_ns, iph->protocol)) {
			v->last_seen_ns = now;
			v->packets++;
			stat_add(AS_INGRESS_MAPPED, 1);
			return acl_verdict(skb, cfg, v->forwarded);
		}
		if (acl_port_allowed(AF_INET, iph->protocol, ACL_SCOPE_FORWARD, dport)) {
			stat_add(AS_INGRESS_FORWARD, 1);
			return acl_verdict(skb, cfg, 0);
		}
		if (acl_port_allowed(AF_INET, iph->protocol, ACL_SCOPE_INPUT, dport)) {
			stat_add(AS_INGRESS_INPUT, 1);
			return acl_verdict(skb, cfg, 0);
		}
		/* Opt-in full cone: einat un-SNATed this into the LAN, so a
		 * third party that learned the mapping elsewhere can reach it.
		 * Off by default because this cannot tell that apart from a
		 * forged LAN destination. */
		if (acl_lan_v4_match(cfg, iph->daddr)) {
			stat_add(AS_INGRESS_FULLCONE, 1);
			return acl_verdict(skb, cfg, 1);
		}
		stat_add(AS_INGRESS_DROP, 1);
		return TC_ACT_SHOT;
	}

	if (iph->protocol == IPPROTO_ICMP_) {
		ic = l4;
		if ((void *)(ic + 1) > data_end) {
			stat_add(AS_INGRESS_DROP, 1);
			return TC_ACT_SHOT;
		}
		if (ic->type == ICMP_ECHO_) {
			if (cfg->allow_v4_echo) {
				stat_add(AS_INGRESS_ECHO, 1);
				return acl_verdict(skb, cfg, 0);
			}
			stat_add(AS_INGRESS_DROP, 1);
			return TC_ACT_SHOT;
		}
		if (ic->type == ICMP_ECHOREPLY_) {
			k.proto = IPPROTO_ICMP_;
			k.ip = iph->saddr;
			k.port = ic->un.echo.id;
			v = bpf_map_lookup_elem(&acl_v4_flows, &k);
			if (v && !acl_v4_expired(cfg, now, v->last_seen_ns,
						 IPPROTO_ICMP_)) {
				v->last_seen_ns = now;
				v->packets++;
				stat_add(AS_INGRESS_MAPPED, 1);
				return acl_verdict(skb, cfg, v->forwarded);
			}
			stat_add(AS_INGRESS_DROP, 1);
			return TC_ACT_SHOT;
		}
		if (ic->type == ICMP_DEST_UNREACH_ ||
		    ic->type == ICMP_TIME_EXCEEDED_ ||
		    ic->type == ICMP_PARAMETERPROB_) {
			if (acl_v4_inner_key(data_end, l4, &k) == 0) {
				v = bpf_map_lookup_elem(&acl_v4_flows, &k);
				if (v && !acl_v4_expired(cfg, now, v->last_seen_ns,
							 k.proto)) {
					v->last_seen_ns = now;
					v->packets++;
					stat_add(AS_INGRESS_ICMP_ERR, 1);
					return acl_verdict(skb, cfg, v->forwarded);
				}
			}
			stat_add(AS_INGRESS_DROP, 1);
			return TC_ACT_SHOT;
		}
		/* Other ICMP types are left to fw4. */
		return TC_ACT_UNSPEC;
	}

	/* GRE/ESP/SCTP/... : only if explicitly listed, else let fw4 decide. */
	if (acl_port_allowed(AF_INET, iph->protocol, ACL_SCOPE_FORWARD, 0) ||
	    acl_port_allowed(AF_INET, iph->protocol, ACL_SCOPE_INPUT, 0))
		return acl_verdict(skb, cfg, 0);
	return TC_ACT_UNSPEC;
}

static __always_inline int acl_v6_inner_key(void *data_end, void *l4,
					    struct acl_v6_key *k)
{
	__u8 *q = l4 + 8;
	struct ipv6hdr *ip6h;
	__be16 sp, dp;

	if (q + sizeof(*ip6h) > (__u8 *)data_end)
		return -1;
	ip6h = (struct ipv6hdr *)q;
	if (ip6h->version != 6)
		return -1;
	/* No extension header walking: if the quoted packet has one we simply
	 * fail the lookup and the caller falls back to dropping. */
	if (ip6h->nexthdr != IPPROTO_TCP_ && ip6h->nexthdr != IPPROTO_UDP_)
		return -1;
	if (acl_l4_ports(q + sizeof(*ip6h), data_end, ip6h->nexthdr,
			 &sp, &dp) < 0)
		return -1;

	__builtin_memset(k, 0, sizeof(*k));
	__builtin_memcpy(k->src, &ip6h->saddr, 16);
	__builtin_memcpy(k->dst, &ip6h->daddr, 16);
	k->sport = sp;
	k->dport = dp;
	k->proto = ip6h->nexthdr;
	return 0;
}

static __always_inline int acl_ingress_v6(struct __sk_buff *skb,
					  struct acl_config *cfg,
					  void *data, void *data_end,
					  __u32 off, __u64 now)
{
	struct ipv6hdr *ip6h = data + off;
	struct acl_icmp6hdr *ic6;
	struct acl_v6_key k = {}, rk = {};
	struct acl_v6_val *v;
	void *l4;
	__u16 sport = 0, dport = 0;

	stat_add(AS_V6_INGRESS_PKT, 1);

	if ((void *)(ip6h + 1) > data_end) {
		stat_add(AS_V6_INGRESS_DROP, 1);
		return TC_ACT_SHOT;
	}
	l4 = (void *)ip6h + sizeof(*ip6h);
	if (l4 > data_end) {
		stat_add(AS_V6_INGRESS_DROP, 1);
		return TC_ACT_SHOT;
	}

	/* Extension headers (including fragments) and protocols we do not model
	 * are handed to fw4. fw4 is still fully in the path for anything that is
	 * not marked, so this is a pass-through, not a hole. */
	if (ip6h->nexthdr == IPPROTO_TCP_ || ip6h->nexthdr == IPPROTO_UDP_) {
		if (acl_l4_ports(l4, data_end, ip6h->nexthdr, &sport, &dport) < 0) {
			stat_add(AS_V6_INGRESS_DROP, 1);
			return TC_ACT_SHOT;
		}
		/* the reply: reverse of the stored LAN->WAN tuple */
		__builtin_memcpy(rk.src, &ip6h->daddr, 16);
		__builtin_memcpy(rk.dst, &ip6h->saddr, 16);
		rk.sport = dport;
		rk.dport = sport;
		rk.proto = ip6h->nexthdr;
		v = bpf_map_lookup_elem(&acl_v6_flows, &rk);
		if (v && !acl_v4_expired(cfg, now, v->last_seen_ns, rk.proto)) {
			v->last_seen_ns = now;
			v->packets++;
			stat_add(AS_V6_INGRESS_STATE, 1);
			return acl_verdict(skb, cfg, v->forwarded);
		}
		if (acl_port_allowed(AF_INET6, ip6h->nexthdr, ACL_SCOPE_FORWARD, dport) ||
		    acl_port_allowed(AF_INET6, ip6h->nexthdr, ACL_SCOPE_INPUT, dport)) {
			stat_add(AS_V6_INGRESS_FORWARD, 1);
			return acl_verdict(skb, cfg, 0);
		}
		stat_add(AS_V6_INGRESS_DROP, 1);
		return TC_ACT_SHOT;
	}

	if (ip6h->nexthdr == IPPROTO_ICMPV6_) {
		ic6 = l4;
		if ((void *)(ic6 + 1) > data_end) {
			stat_add(AS_V6_INGRESS_DROP, 1);
			return TC_ACT_SHOT;
		}
		switch (ic6->type) {
		case ICMPV6_ROUTER_SOLICIT_:
		case ICMPV6_ROUTER_ADVERT_:
		case ICMPV6_NEIGH_SOLICIT_:
		case ICMPV6_NEIGH_ADVERT_:
		case ICMPV6_REDIRECT_:
			/* essential for IPv6 to work at all as a client */
			stat_add(AS_V6_INGRESS_ICMP6, 1);
			return acl_verdict(skb, cfg, 0);
		case ICMPV6_ECHO_REQUEST_:
			if (cfg->allow_v6_echo) {
				stat_add(AS_V6_INGRESS_ICMP6, 1);
				return acl_verdict(skb, cfg, 0);
			}
			stat_add(AS_V6_INGRESS_DROP, 1);
			return TC_ACT_SHOT;
		case ICMPV6_ECHO_REPLY_:
			__builtin_memcpy(rk.src, &ip6h->daddr, 16);
			__builtin_memcpy(rk.dst, &ip6h->saddr, 16);
			rk.sport = ic6->un.echo.id;
			rk.dport = ic6->un.echo.id;
			rk.proto = IPPROTO_ICMPV6_;
			v = bpf_map_lookup_elem(&acl_v6_flows, &rk);
			if (v && !acl_v4_expired(cfg, now, v->last_seen_ns,
						 IPPROTO_ICMPV6_)) {
				v->last_seen_ns = now;
				v->packets++;
				stat_add(AS_V6_INGRESS_STATE, 1);
				return acl_verdict(skb, cfg, v->forwarded);
			}
			stat_add(AS_V6_INGRESS_DROP, 1);
			return TC_ACT_SHOT;
		case ICMPV6_DEST_UNREACH_:
		case ICMPV6_PKT_TOOBIG_:
		case ICMPV6_TIME_EXCEED_:
		case ICMPV6_PARAMPROB_:
			if (acl_v6_inner_key(data_end, l4, &k) == 0) {
				v = bpf_map_lookup_elem(&acl_v6_flows, &k);
				if (v && !acl_v4_expired(cfg, now, v->last_seen_ns,
							 k.proto)) {
					v->last_seen_ns = now;
					v->packets++;
					stat_add(AS_V6_INGRESS_ICMP6, 1);
					return acl_verdict(skb, cfg, v->forwarded);
				}
			}
			stat_add(AS_V6_INGRESS_DROP, 1);
			return TC_ACT_SHOT;
		default:
			/* MLD and friends: link-local, leave to fw4. */
			return TC_ACT_UNSPEC;
		}
	}

	/* next header we do not model: hand to fw4 */
	return TC_ACT_UNSPEC;
}

SEC("classifier")
int acl_ingress(struct __sk_buff *skb)
{
	struct acl_config *cfg = acl_cfg_get();
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u16 proto;
	int off;
	__u64 now;

	if (!cfg)
		return TC_ACT_UNSPEC;

	now = bpf_ktime_get_ns();

	off = acl_l3_off(data, data_end, &proto);
	if (off < 0) {
		stat_add(AS_INGRESS_NONIP, 1);
		return TC_ACT_UNSPEC;
	}
	if (proto == ETH_P_IP)
		return acl_ingress_v4(skb, cfg, data, data_end, (__u32)off, now);
	if (proto == ETH_P_IPV6)
		return acl_ingress_v6(skb, cfg, data, data_end, (__u32)off, now);

	stat_add(AS_INGRESS_NONIP, 1);
	return TC_ACT_UNSPEC;
}

#endif /* ACL_BUILD_INGRESS */

/* ------------------------------------------------------------------ egress */

#ifdef ACL_BUILD_EGRESS

/* skb->sk is NULL for forwarded traffic and non-NULL when a local socket
 * generated it. Only forwarded flows get marked on the return path, so the
 * router's own connections keep full fw4 input filtering. */
static __always_inline __u32 acl_forwarded(struct __sk_buff *skb)
{
	return skb->sk == NULL ? 1 : 0;
}

static __always_inline void acl_learn_v4(struct __sk_buff *skb, __u64 now,
					 __u16 proto, __be32 ip, __be16 port)
{
	struct acl_v4_key k = {};
	struct acl_v4_val *v;
	__u32 fwd = acl_forwarded(skb);

	k.proto = proto;
	k.ip = ip;
	k.port = port;

	v = bpf_map_lookup_elem(&acl_v4_flows, &k);
	if (v) {
		v->last_seen_ns = now;
		v->packets++;
		v->forwarded = fwd;
	} else {
		struct acl_v4_val nv = {
			.last_seen_ns = now,
			.packets = 1,
			.forwarded = fwd,
		};

		bpf_map_update_elem(&acl_v4_flows, &k, &nv, BPF_NOEXIST);
	}
	stat_add(AS_EGRESS_LEARN, 1);
}

static __always_inline void acl_learn_v6(struct __sk_buff *skb, __u64 now,
					 struct ipv6hdr *ip6h,
					 __be16 sport, __be16 dport)
{
	struct acl_v6_key k = {};
	struct acl_v6_val *v;
	__u32 fwd = acl_forwarded(skb);

	__builtin_memcpy(k.src, &ip6h->saddr, 16);
	__builtin_memcpy(k.dst, &ip6h->daddr, 16);
	k.sport = sport;
	k.dport = dport;
	k.proto = ip6h->nexthdr;

	v = bpf_map_lookup_elem(&acl_v6_flows, &k);
	if (v) {
		v->last_seen_ns = now;
		v->packets++;
		v->forwarded = fwd;
	} else {
		struct acl_v6_val nv = {
			.last_seen_ns = now,
			.packets = 1,
			.forwarded = fwd,
		};

		bpf_map_update_elem(&acl_v6_flows, &k, &nv, BPF_NOEXIST);
	}
	stat_add(AS_V6_EGRESS_LEARN, 1);
}

static __always_inline int acl_egress_v4(struct __sk_buff *skb, void *data,
					 void *data_end, __u32 off, __u64 now)
{
	struct iphdr *iph = data + off;
	struct acl_icmphdr *ic;
	__u32 ihl;
	void *l4;
	__u16 sport = 0, dport = 0;

	stat_add(AS_EGRESS_PKT, 1);

	if ((void *)(iph + 1) > data_end)
		return TC_ACT_UNSPEC;
	ihl = (__u32)iph->ihl * 4;
	if (ihl < IPV4_MIN_IHL || ihl > IPV4_MAX_IHL)
		return TC_ACT_UNSPEC;
	l4 = (void *)iph + ihl;
	if (l4 > data_end)
		return TC_ACT_UNSPEC;

	if (iph->protocol == IPPROTO_TCP_ || iph->protocol == IPPROTO_UDP_) {
		if (acl_l4_ports(l4, data_end, iph->protocol, &sport, &dport) < 0)
			return TC_ACT_UNSPEC;
		/* key on the remote endpoint: it is what the reply will come
		 * from, and einat's SNAT does not touch it */
		acl_learn_v4(skb, now, iph->protocol, iph->daddr, dport);
		return TC_ACT_UNSPEC;
	}
	if (iph->protocol == IPPROTO_ICMP_) {
		ic = l4;
		if ((void *)(ic + 1) > data_end)
			return TC_ACT_UNSPEC;
		/* the echo id plays the role of the port for the reply lookup */
		if (ic->type == ICMP_ECHO_)
			acl_learn_v4(skb, now, IPPROTO_ICMP_, iph->daddr,
				     ic->un.echo.id);
		return TC_ACT_UNSPEC;
	}
	return TC_ACT_UNSPEC;
}

static __always_inline int acl_egress_v6(struct __sk_buff *skb, void *data,
					 void *data_end, __u32 off, __u64 now)
{
	struct ipv6hdr *ip6h = data + off;
	struct acl_icmp6hdr *ic6;
	void *l4;
	__u16 sport = 0, dport = 0;

	stat_add(AS_V6_EGRESS_PKT, 1);

	if ((void *)(ip6h + 1) > data_end)
		return TC_ACT_UNSPEC;
	l4 = (void *)ip6h + sizeof(*ip6h);
	if (l4 > data_end)
		return TC_ACT_UNSPEC;

	if (ip6h->nexthdr == IPPROTO_TCP_ || ip6h->nexthdr == IPPROTO_UDP_) {
		if (acl_l4_ports(l4, data_end, ip6h->nexthdr, &sport, &dport) < 0)
			return TC_ACT_UNSPEC;
		acl_learn_v6(skb, now, ip6h, sport, dport);
		return TC_ACT_UNSPEC;
	}
	if (ip6h->nexthdr == IPPROTO_ICMPV6_) {
		ic6 = l4;
		if ((void *)(ic6 + 1) > data_end)
			return TC_ACT_UNSPEC;
		if (ic6->type == ICMPV6_ECHO_REQUEST_)
			acl_learn_v6(skb, now, ip6h, ic6->un.echo.id,
				     ic6->un.echo.id);
		return TC_ACT_UNSPEC;
	}
	return TC_ACT_UNSPEC;
}

SEC("classifier")
int acl_egress(struct __sk_buff *skb)
{
	struct acl_config *cfg = acl_cfg_get();
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u16 proto;
	int off;
	__u64 now;

	if (!cfg)
		return TC_ACT_UNSPEC;

	now = bpf_ktime_get_ns();

	off = acl_l3_off(data, data_end, &proto);
	if (off < 0) {
		stat_add(AS_EGRESS_NONIP, 1);
		return TC_ACT_UNSPEC;
	}
	if (proto == ETH_P_IP)
		return acl_egress_v4(skb, data, data_end, (__u32)off, now);
	if (proto == ETH_P_IPV6)
		return acl_egress_v6(skb, data, data_end, (__u32)off, now);

	stat_add(AS_EGRESS_NONIP, 1);
	return TC_ACT_UNSPEC;
}

#endif /* ACL_BUILD_EGRESS */

char _license[] SEC("license") = "GPL";
