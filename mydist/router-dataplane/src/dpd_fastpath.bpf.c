// SPDX-License-Identifier: GPL-2.0-only
/*
 * dpd_fastpath.bpf.c - mydist TC *ingress* eBPF fastpath.
 *
 * See src/dpd_common.h for the redlines and the hook layout. Short version:
 * ingress-only, no NAT, no conntrack, does not read einat maps, always yields
 * with TC_ACT_UNSPEC unless it has genuinely taken over a packet.
 *
 * Modes (dpd_cfg.mode):
 *   OBSERVE      do the work but never touch the packet  -> zero risk
 *   STATELESS    every packet: fib -> redirect_neigh
 *   STATEFUL     first packet learns and yields, later packets redirect
 *   NEIGH_PROBE  #14: does bpf_redirect_neigh actually work on this iface?
 *
 * Compile-time default is OBSERVE; the runtime default lives in
 * files/dpd_fastpath.config and is pushed into dpd_cfg by the init script.
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

#include "dpd_common.h"

/* must match DPD_BPF_SECTION in dpd_common.h; SEC() stringises so it cannot be
 * passed a macro. The init script uses the macro, so keep the two in sync. */
#define DPD_SEC_NAME "classifier"

#ifndef DPD_MODE_DEFAULT
#define DPD_MODE_DEFAULT 1 /* DPD_MODE_OBSERVE */
#endif

/* AF_* are frozen ABI values and linux/bpf.h does not drag in linux/socket.h,
 * so spell them out rather than depending on which UAPI headers are installed. */
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* linux/if_ether.h no longer carries struct vlan_hdr in 6.18; define the two
 * fields we need locally so we do not depend on header layout. */
struct dpd_vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

/* IPv4 fragment flags, spelled out for the same reason as AF_INET above:
 * linux/ip.h keeps them as FP_* / IP_OFFSET under different names depending on
 * the tree, and this must not silently become 0. */
#define DPD_IP_MF		0x2000	/* more fragments			*/
#define DPD_IP_OFFMASK		0x1fff	/* fragment offset field		*/

/* ------------------------------------------------------------------ maps */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dpd_config);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpd_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, ST__MAX);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpd_stats SEC(".maps");

/* Mode B: self-learned shortcut table. Populated by nothing but us. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct dpd_flow_key);
	__type(value, struct dpd_flow_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpd_flows SEC(".maps");

/* per-ifindex L2 capabilities, filled in from userspace (IFF_NOARP & co) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpd_iface SEC(".maps");

/* dpd_vlans: optional segment allow-list, u16 VLAN id -> u8 1.
 *
 * Only consulted when dpd_cfg.policy == DPD_POLICY_VLANS_ONLY. Managed with
 * `dpdctl vlan add|del|list`; the list is written by the init script from
 * files/dpd_fastpath.config so it survives a reboot without dpdctl being run.
 * This is the "which segments may I accelerate" safety axis: an empty list
 * means nothing is eligible in vlans_only mode. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, DPD_VLAN_MAP_MAX);
	__type(key, __u16);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpd_vlans SEC(".maps");

/* ------------------------------------------------------------------ helpers */

static __always_inline void stat_add(__u32 idx, __u64 v)
{
	__u64 *p = bpf_map_lookup_elem(&dpd_stats, &idx);

	if (p)
		*p += v;
}

/* read the config once per packet; also enforces the killer switch */
static __always_inline struct dpd_config *dpd_get_cfg(void)
{
	__u32 zero = 0;
	struct dpd_config *cfg = bpf_map_lookup_elem(&dpd_cfg, &zero);

	/* if the map is somehow absent, do nothing at all */
	if (!cfg || !cfg->enable || cfg->mode == DPD_MODE_OFF)
		return NULL;
	return cfg;
}

/*
 * Decrement IPv4 TTL and repair the header checksum incrementally.
 *
 * The kernel implementation is csum_replace2(ptr, from, to) applied to the
 * checksum field, which has the net effect  sum += from - to  in ones
 * complement arithmetic (see net/core/filter.c:bpf_l3_csum_replace).
 *
 * The 16-bit word that changes is {ttl, protocol} at IP-header offset 8 (an
 * even offset, as the helper requires). One TTL step changes it by exactly one
 * unit in memory byte order, so passing the two values with the protocol byte
 * zeroed out makes the delta exact and endian independent:
 *
 *   bpf_htons(ttl << 8)        on LE == (protocol<<8)|ttl with protocol 0
 *
 * bpf_htons() is identity on big endian, where the memory-order word really is
 * (ttl<<8)|protocol, so the delta stays 1 in ones complement on both.
 *
 * The reference is ip_decrease_ttl() in net/ipv4/ip_forward.c, which does
 * "iph->check += htons(0x0100)", i.e. the same +1 in raw u16 space.
 *
 * Returns 0 on success, 1 if the caller must drop (TTL would reach 0),
 * -1 if the packet is too short to touch.
 */
static __always_inline int dpd_dec_ttl_v4(struct __sk_buff *skb, void *data,
					  void *data_end, __u32 l3_off)
{
	struct iphdr *iph = data + l3_off;
	__u16 w_old, w_new;

	if ((void *)(iph + 1) > data_end)
		return -1;
	if (iph->ttl <= 1)
		return 1;

	w_old = bpf_htons((__u16)iph->ttl << 8);
	w_new = bpf_htons((__u16)(iph->ttl - 1) << 8);
	iph->ttl -= 1;
	bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check),
			    w_old, w_new, 2);
	return 0;
}

static __always_inline int dpd_dec_hop_v6(void *data, void *data_end, __u32 l3_off)
{
	struct ipv6hdr *ip6h = data + l3_off;

	if ((void *)(ip6h + 1) > data_end)
		return -1;
	if (ip6h->hop_limit <= 1)
		return 1;
	ip6h->hop_limit -= 1;
	/* IPv6 has no header checksum to repair */
	return 0;
}

/*
 * May this packet be taken over?
 *
 * Every gate exists because taking a packet over skips NETFILTER, not just the
 * routing lookup: anything netfilter would have *rewritten* on the LAN->WAN
 * path is silently lost, and the return path becomes nobody's business except
 * einat's. So:
 *
 *   IPv4 only   Taking over an IPv4 flow is fine while einat is attached: einat
 *               owns NAT on the WAN's TCX hooks and is conntrack-free, and its
 *               init injects a blanket WAN->LAN accept into fw4, so the reply of
 *               an accelerated flow still lands on the LAN. IPv6 has no NAT in
 *               this baseline (no NAT66, by design) and the reply would arrive
 *               untracked, so fw4's forward chain would reject it. Never
 *               accelerate v6 -- return TC_ACT_UNSPEC and let the stack handle
 *               it. (files/dpd-fastpath.sh additionally refuses to accelerate
 *               unless einat is actually attached.)
 *
 *   port 53     dns_redirect=1 is the shipped default: fw4 DNATs every LAN->WAN
 *               :53 packet to the router itself so dnsmasq/SmartDNS answers it
 *               and a client with a hardcoded resolver (8.8.8.8) still gets the
 *               router's answers. That rewrite is netfilter, i.e. *behind* this
 *               hook. Measured in QEMU on 2026-10-17 with a client whose
 *               resolv.conf said 223.5.5.5: with acceleration on, DNS
 *               resolution timed out (curl (28) Resolving timed out after
 *               12000 ms) and every HTTPS flow then failed; with acceleration
 *               off the very same client resolved instantly. A silent DNS-only
 *               breakage is not a trade this design gets to make, and DNS is
 *               noise in the acceleration budget, so :53 yields.
 *
 *   fragments   The L4 header only exists in the first fragment, so there is no
 *               honest flow key (bogus ports in Mode B) and nothing to gate the
 *               :53 check on. The whole fragment stream goes to the stack, which
 *               is also what einat needs to create its binding.
 *
 *   VLAN policy When dpd_cfg.policy is DPD_POLICY_VLANS_ONLY, only VLAN ids in
 *               dpd_vlans may be taken over; an untagged packet never is. This
 *               is fail-closed on purpose: the operator naming segments is the
 *               whole point of the mode.
 *
 * Every refusal is counted, so a "why is nothing accelerated" question is
 * answerable from `dpdctl stats` without a packet capture.
 *
 * Returns 1 if the packet may be redirected, 0 if the caller must yield.
 */
static __always_inline int dpd_is_dns(__u8 proto, __be16 dport)
{
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return 0;
	/* dport is 0 when the L4 header was not parseable, and we already
	 * refuse fragments, so a 0 here can never alias port 53. */
	return bpf_ntohs(dport) == 53;
}

static __always_inline int dpd_may_accelerate(const struct dpd_config *cfg,
					      __u8 family, __u16 vlan_id,
					      __u8 tagged, __u8 proto,
					      __be16 dport)
{
	if (family != AF_INET) {
		stat_add(ST_V6_SKIP, 1);
		return 0;
	}
	if (dpd_is_dns(proto, dport)) {
		stat_add(ST_DNS_SKIP, 1);
		return 0;
	}
	if (cfg->policy == DPD_POLICY_VLANS_ONLY) {
		__u8 *ok = NULL;

		if (tagged)
			ok = bpf_map_lookup_elem(&dpd_vlans, &vlan_id);
		if (!ok) {
			stat_add(ST_VLAN_SKIP, 1);
			return 0;
		}
	}
	return 1;
}

/*
 * Hand the packet to the device.
 *   AUTO        - redirect_neigh unless the iface says NOARP/POINTOPOINT
 *                 (ppp is exactly that: no neighbour table, and the L2 header
 *                 must not be rewritten)
 *   FORCE_NEIGH - always redirect_neigh
 *   FORCE_DEV   - always bpf_redirect(ifindex, 0)  (ppp / veth)
 *
 * no_neigh is a FACT learned from bpf_fib_lookup: the helper could only find the
 * route with BPF_FIB_LOOKUP_SKIP_NEIGH, i.e. there is no neighbour entry for this
 * egress. That happens on ppp/tunnel devices, where the emit path must be
 * bpf_redirect() rather than bpf_redirect_neigh(), and it must hold even if
 * userspace never taught dpd_iface (the flags used to be the only source of this
 * knowledge, and on a PPPoE box they arrive too late or not at all).
 *
 * Measured 2026-10-18 on a PPPoE WAN (bare QEMU, pppoe-server as peer): with this
 * path, 9 packets of a client ping+HTTP flow were redirected (redirect_ok +9) and
 * the peer's access log recorded the request -- i.e. bpf_redirect() to a ppp
 * device delivers. Before the FIB retry nothing was emitted at all, because every
 * lookup answered NO_NEIGH.
 */
static __always_inline int dpd_emit(struct __sk_buff *skb, __u32 ifindex,
				    struct dpd_config *cfg, int no_neigh)
{
	__u32 *p = bpf_map_lookup_elem(&dpd_iface, &ifindex);
	__u32 flags = p ? *p : 0;
	int r;

	if (cfg->redirect == DPD_REDIR_FORCE_NEIGH)
		goto neigh;
	if (cfg->redirect == DPD_REDIR_FORCE_DEV)
		goto dev;
	if (no_neigh)
		goto dev;
	if (flags & (DPD_IF_F_NOARP | DPD_IF_F_POINTOPOINT))
		goto dev;

neigh:
	/* WHAT THESE COUNTERS MEAN, because the name lies: this helper returns
	 * TC_ACT_REDIRECT as soon as it has accepted the packet. The FIB lookup
	 * and the neighbour resolution happen afterwards, in
	 * skb_do_redirect() -> __bpf_redirect_neigh() -> bpf_out_neigh_v4(),
	 * and every failure there is a silent kfree_skb (verified in
	 * net/core/filter.c of the 6.18.55 tree on 2026-10-17). So
	 * ST_NEIGH_OK counts *requests accepted*, never packets delivered. The
	 * only honest delivery evidence is traffic: the device counters
	 * (eth1 tx_packets / tx_dropped) or the peer answering. */
	r = bpf_redirect_neigh(ifindex, NULL, 0, 0);
	if (r == TC_ACT_REDIRECT) {
		stat_add(ST_NEIGH_OK, 1);
		return TC_ACT_REDIRECT;
	}
	stat_add(ST_NEIGH_FAIL, 1);
	/* The helper failed (no neighbour, no route, ...). A TC program may only
	 * return a TC_ACT_* code; handing back a negative errno would be an action
	 * the kernel does not define. Yield, so the packet takes the normal path. */
	return TC_ACT_UNSPEC;

dev:
	r = bpf_redirect(ifindex, 0);
	if (r == TC_ACT_REDIRECT) {
		stat_add(ST_REDIRECT_OK, 1);
		return TC_ACT_REDIRECT;
	}
	return TC_ACT_UNSPEC;
}

/* ------------------------------------------------------------------ program */

SEC(DPD_SEC_NAME)
int dpd_fastpath(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct dpd_config *cfg;
	struct bpf_fib_lookup fib = {};
	struct dpd_flow_key fkey = {};
	struct dpd_flow_val *fval;
	struct ethhdr *eth;
	__u32 l3_off = sizeof(*eth);
	__u16 h_proto;
	__u16 vlan_id = 0;	/* the 802.1Q/802.1AD VID, if tagged	*/
	__u8 tagged = 0;
	__u8 l4;
	int no_neigh = 0;	/* FIB needed SKIP_NEIGH: no neighbour	*/
	int ret;

	cfg = dpd_get_cfg();
	if (!cfg)
		return TC_ACT_UNSPEC;

	stat_add(ST_PKT_TOTAL, 1);
	stat_add(ST_BYTES, skb->len);

	eth = data;
	if ((void *)(eth + 1) > data_end) {
		stat_add(ST_NON_IP, 1);
		return TC_ACT_UNSPEC;
	}
	h_proto = bpf_ntohs(eth->h_proto);

	if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
		struct dpd_vlan_hdr *vh = data + l3_off;

		if ((void *)(vh + 1) > data_end) {
			stat_add(ST_NON_IP, 1);
			return TC_ACT_UNSPEC;
		}
		h_proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
		vlan_id = bpf_ntohs(vh->h_vlan_TCI) & 0x0fff;
		tagged = 1;
		l3_off += sizeof(*vh);
	}

	fib.ifindex = skb->ifindex;
	fkey.ifindex = skb->ifindex;

	if (h_proto == ETH_P_IP) {
		struct iphdr *iph = data + l3_off;
		__u32 ihl;

		if ((void *)(iph + 1) > data_end)
			goto non_ip;
		if (iph->version != 4 || iph->ihl < 5 || iph->ihl > 15)
			goto non_ip;
		ihl = (__u32)iph->ihl * 4;
		if ((void *)iph + ihl > data_end)
			goto non_ip;

		/* fragments: see dpd_may_accelerate() -- no honest L4 header,
		 * no honest flow key, nothing to gate the :53 check on. */
		if (iph->frag_off & bpf_htons(DPD_IP_MF | DPD_IP_OFFMASK)) {
			stat_add(ST_FRAG_SKIP, 1);
			return TC_ACT_UNSPEC;
		}

		fib.family = AF_INET;
		fib.l4_protocol = iph->protocol;
		fib.tot_len = bpf_ntohs(iph->tot_len);
		fib.ipv4_src = iph->saddr;
		fib.ipv4_dst = iph->daddr;
		l4 = iph->protocol;
		fkey.family = AF_INET;
		fkey.proto = iph->protocol;
		fkey.saddr[3] = iph->saddr;
		fkey.daddr[3] = iph->daddr;

		if (l4 == IPPROTO_TCP) {
			struct tcphdr *th = (void *)iph + ihl;

			if ((void *)(th + 1) <= data_end) {
				fib.sport = th->source;
				fib.dport = th->dest;
				fkey.sport = th->source;
				fkey.dport = th->dest;
			}
		} else if (l4 == IPPROTO_UDP) {
			struct udphdr *uh = (void *)iph + ihl;

			if ((void *)(uh + 1) <= data_end) {
				fib.sport = uh->source;
				fib.dport = uh->dest;
				fkey.sport = uh->source;
				fkey.dport = uh->dest;
			}
		}
	} else if (h_proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6h = data + l3_off;

		if ((void *)(ip6h + 1) > data_end)
			goto non_ip;

		fib.family = AF_INET6;
		fib.l4_protocol = ip6h->nexthdr;
		fib.tot_len = bpf_ntohs(ip6h->payload_len) + sizeof(*ip6h);
		__builtin_memcpy(fib.ipv6_src, ip6h->saddr.in6_u.u6_addr32,
				 sizeof(fib.ipv6_src));
		__builtin_memcpy(fib.ipv6_dst, ip6h->daddr.in6_u.u6_addr32,
				 sizeof(fib.ipv6_dst));
		__builtin_memcpy(fkey.saddr, ip6h->saddr.in6_u.u6_addr32,
				 sizeof(fkey.saddr));
		__builtin_memcpy(fkey.daddr, ip6h->daddr.in6_u.u6_addr32,
				 sizeof(fkey.daddr));
		l4 = ip6h->nexthdr;
		fkey.family = AF_INET6;
		fkey.proto = ip6h->nexthdr;
	} else {
		goto non_ip;
	}

	/* ---- Mode B: try the self-learned shortcut first ---- */
	if (cfg->mode == DPD_MODE_STATEFUL) {
		__u64 now = bpf_ktime_get_ns();
		__u64 ttl_ns = (__u64)cfg->flow_ttl_ms * 1000000ULL;

		fval = bpf_map_lookup_elem(&dpd_flows, &fkey);
		if (fval && fval->egress_ifindex &&
		    now - fval->last_seen_ns < ttl_ns) {
			__u32 egress = fval->egress_ifindex;

			stat_add(ST_FLOW_HIT, 1);
			fval->last_seen_ns = now;
			/* a remembered "no neighbour" egress must not go through
			 * bpf_redirect_neigh() on the shortcut path either */
			no_neigh = !!(fval->flags & DPD_FLOW_F_NO_NEIGH);
			if (!dpd_may_accelerate(cfg, fkey.family, vlan_id, tagged,
						fkey.proto, fkey.dport))
				return TC_ACT_UNSPEC;
			if (fkey.family == AF_INET) {
				ret = dpd_dec_ttl_v4(skb, data, data_end, l3_off);
			} else {
				ret = dpd_dec_hop_v6(data, data_end, l3_off);
			}
			if (ret > 0) {
				stat_add(ST_TTL_DROP, 1);
				return TC_ACT_SHOT;
			}
			if (ret < 0)
				return TC_ACT_UNSPEC;
			return dpd_emit(skb, egress, cfg, no_neigh);
		}
		stat_add(ST_FLOW_MISS, 1);
	}

	/* ---- FIB lookup, shared by every mode ---- */
	ret = bpf_fib_lookup(skb, &fib, sizeof(fib), 0);
	if (ret == BPF_FIB_LKUP_RET_NO_NEIGH) {
		/* ppp and tunnels have no neighbour table, so the first pass
		 * answers NO_NEIGH even though the route is right there. Ask for
		 * the route only; the emit path for such a device is
		 * bpf_redirect(ifindex), which needs no L2 header.
		 *
		 * Measured 2026-10-18 on a PPPoE WAN before this retry: every
		 * packet of a working client flow ended in fib_fail (fib_ok 0,
		 * fib_fail 29), so the acceleration never fired on ppp at all. */
		stat_add(ST_FIB_RETRY, 1);
		no_neigh = 1;
		ret = bpf_fib_lookup(skb, &fib, sizeof(fib),
				     BPF_FIB_LOOKUP_SKIP_NEIGH);
	}
	if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
		stat_add(ST_FIB_FAIL, 1);
		return TC_ACT_UNSPEC;
	}
	stat_add(ST_FIB_OK, 1);

	/* never accelerate traffic that is local to this box */
	if (!fib.ifindex || fib.ifindex == skb->ifindex) {
		stat_add(ST_LOCAL, 1);
		return TC_ACT_UNSPEC;
	}

	/* ---- Mode 0: observe only. never touch the packet. ---- */
	if (cfg->mode == DPD_MODE_OBSERVE)
		return TC_ACT_UNSPEC;

	/* ---- Mode B: learn the shortcut, let this packet take the slow path -- */
	if (cfg->mode == DPD_MODE_STATEFUL) {
		struct dpd_flow_val nv = {};

		/* never learn entries we would refuse to use anyway */
		if (!dpd_may_accelerate(cfg, fkey.family, vlan_id, tagged,
					fkey.proto, fkey.dport))
			return TC_ACT_UNSPEC;

		nv.egress_ifindex = fib.ifindex;
		nv.last_seen_ns = bpf_ktime_get_ns();
		nv.flags = no_neigh ? DPD_FLOW_F_NO_NEIGH : 0;
		__builtin_memcpy(nv.dmac, fib.dmac, ETH_ALEN);
		bpf_map_update_elem(&dpd_flows, &fkey, &nv, BPF_ANY);
		stat_add(ST_FLOW_WRITE, 1);
		return TC_ACT_UNSPEC;
	}

	/* ---- Mode A (and the #14 probe): take the packet over now. ---- */
	if (!dpd_may_accelerate(cfg, fkey.family, vlan_id, tagged,
				fkey.proto, fkey.dport))
		return TC_ACT_UNSPEC;

	if (fkey.family == AF_INET)
		ret = dpd_dec_ttl_v4(skb, data, data_end, l3_off);
	else
		ret = dpd_dec_hop_v6(data, data_end, l3_off);
	if (ret > 0) {
		stat_add(ST_TTL_DROP, 1);
		return TC_ACT_SHOT;
	}
	if (ret < 0)
		return TC_ACT_UNSPEC;

	return dpd_emit(skb, fib.ifindex, cfg, no_neigh);

non_ip:
	stat_add(ST_NON_IP, 1);
	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
