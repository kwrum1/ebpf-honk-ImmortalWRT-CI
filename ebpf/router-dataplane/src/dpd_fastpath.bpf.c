// SPDX-License-Identifier: GPL-2.0-only
/*
 * dpd_fastpath.bpf.c - ebpf TC *ingress* eBPF fastpath.
 *
 * See src/dpd_common.h for the redlines and the hook layout. Short version:
 * ingress-only, no NAT, no conntrack, does not read einat maps, always yields
 * with TC_ACT_UNSPEC unless it has genuinely taken over a packet.
 *
 * Modes (dpd_cfg.mode):
 *   OBSERVE      do the work but never touch the packet  -> zero risk
 *   STATELESS    every packet: fib -> emit
 *   STATEFUL     first packet learns and yields, later packets emit from cache
 *   NEIGH_PROBE  #14: does bpf_redirect_neigh actually work on this iface?
 *
 * "emit" is dpd_emit_cached(): the emit class (L2 header + bpf_redirect / plain
 * bpf_redirect / bpf_redirect_neigh) is decided once, when the flow is learned,
 * and stored in the flow entry, so a hit does no interface lookup and no second
 * FIB lookup. On a plain Ethernet egress it writes the L2 header that
 * bpf_fib_lookup() already produced and calls bpf_redirect(), which skips the
 * route+neighbour lookup that bpf_redirect_neigh() repeats for every packet.
 *
 * Per-packet map lookups on the hit path (ABI 9): dpd_cfg, dpd_stats,
 * dpd_flows. Nothing else -- no dpd_iface, no dpd_wans, no second stats
 * lookup per counter.
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
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dpd_stat_val);
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

/* multi-WAN uplinks; one entry holds the whole table (see dpd_common.h) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dpd_wan_tbl);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpd_wans SEC(".maps");

/* ------------------------------------------------------------------ helpers */

/* One lookup gets the whole counter block for this CPU. Callers hold the
 * pointer and bump several counters with it; nothing between those bumps may
 * modify a map (only bpf_fib_lookup()/bpf_redirect*() run on that path, and
 * they do not touch dpd_stats). */
static __always_inline struct dpd_stat_val *dpd_stat(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&dpd_stats, &zero);
}

#define DPD_INC(s, i)		do { if (s) (s)->v[i]++; } while (0)
#define DPD_ADD(s, i, n)	do { if (s) (s)->v[i] += (n); } while (0)

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

/*
 * DHCP belongs to the local server, never to a next hop.
 *
 * A DISCOVER is 0.0.0.0:68 -> 255.255.255.255:67. bpf_fib_lookup() answers
 * happily (the default route matches a broadcast destination), and
 * bpf_redirect_neigh() then ships the packet out the WAN -- netfilter and
 * odhcpd are skipped, so no offer is ever produced. Measured on 2026-10-27:
 * two DISCOVERs -> pkt_total +2, fib_ok +2, neigh_ok +2, client got no lease;
 * stopping dpd made the same client lease 192.168.10.204 immediately.
 *
 * Both directions are checked because the server's reply (67 -> 68) must also
 * stay on the LAN.
 */
static __always_inline int dpd_is_dhcp(__u8 proto, __be16 sport, __be16 dport)
{
	if (proto != IPPROTO_UDP)
		return 0;
	return bpf_ntohs(sport) == 67 || bpf_ntohs(sport) == 68 ||
	       bpf_ntohs(dport) == 67 || bpf_ntohs(dport) == 68;
}

/*
 * Non-unicast destinations must be delivered locally (or flooded by the
 * bridge), never routed to a next hop: DHCP, service discovery and the ARP
 * proxy all depend on that. 0.0.0.0/8 cannot be a unicast destination either.
 */
static __always_inline int dpd_is_nonunicast(const struct dpd_flow_key *k)
{
	if (k->family == AF_INET) {
		__u32 d = bpf_ntohl(k->daddr[3]);

		if (d == 0xffffffffu)	/* limited broadcast	*/
			return 1;
		if ((d >> 28) == 0xeu)	/* 224.0.0.0/4		*/
			return 1;
		if ((d >> 24) == 0u)	/* 0.0.0.0/8		*/
			return 1;
		return 0;
	}
	return (bpf_ntohl(k->daddr[0]) >> 24) == 0xffu;	/* ff00::/8 */
}

/*
 * The VLAN policy axis, on its own: it is the only gate whose input (the
 * operator's config and the dpd_vlans map) can change while a flow is live, so
 * it is the only one the Mode B hit path has to re-check. The other gates
 * (DNS / DHCP / non-unicast / IPv6) read fields that are *in the flow key*, and
 * an entry is only learned after they passed, so re-running them on a hit can
 * only produce the same answer -- see the comment on the hit path.
 */
static __always_inline int dpd_policy_ok(const struct dpd_config *cfg,
					 __u16 vlan_id, __u8 tagged,
					 struct dpd_stat_val *st)
{
	if (cfg->policy != DPD_POLICY_VLANS_ONLY)
		return 1;
	if (tagged && bpf_map_lookup_elem(&dpd_vlans, &vlan_id))
		return 1;
	DPD_INC(st, ST_VLAN_SKIP);
	return 0;
}

/*
 * Cheap gates, evaluated BEFORE bpf_fib_lookup(). None of them needs a route:
 * they read only the flow key, the VLAN id and the config. Running them first
 * means DNS, DHCP, non-unicast and (unless enabled) IPv6 traffic never pay for
 * a route lookup they could only ever fail.
 *
 * IPv6 is opt-in (`cfg->ipv6`). The caller only produces a v6 flow key for
 * plain TCP/UDP, unicast, non-fragment packets with no extension headers, so
 * this function only has to apply the same port gates as v4 plus the DHCPv6
 * pair (546/547), which is the v6 service that must stay local.
 */
static __always_inline int dpd_may_accelerate(const struct dpd_config *cfg,
					      __u16 vlan_id, __u8 tagged,
					      const struct dpd_flow_key *k,
					      struct dpd_stat_val *st)
{
	if (k->family == AF_INET6 && !cfg->ipv6) {
		DPD_INC(st, ST_V6_SKIP);
		return 0;
	}
	if (dpd_is_dns(k->proto, k->dport)) {
		DPD_INC(st, ST_DNS_SKIP);
		return 0;
	}
	if (dpd_is_dhcp(k->proto, k->sport, k->dport) ||
	    (k->family == AF_INET6 &&
	     (bpf_ntohs(k->sport) == 546 || bpf_ntohs(k->sport) == 547 ||
	      bpf_ntohs(k->dport) == 546 || bpf_ntohs(k->dport) == 547))) {
		DPD_INC(st, ST_DHCP_SKIP);
		return 0;
	}
	if (dpd_is_nonunicast(k)) {
		DPD_INC(st, ST_BCAST_SKIP);
		return 0;
	}
	return dpd_policy_ok(cfg, vlan_id, tagged, st);
}

/* ------------------------------------------------------------- multi-WAN */

/* FNV-1a over the parts of the 5-tuple that identify the flow. Salted per WAN
 * by the caller so the rendezvous scores are independent. */
static __always_inline __u32 dpd_flow_hash(const struct dpd_flow_key *k,
					   __u32 salt)
{
	__u32 h = 2166136261u ^ salt;

	h = (h ^ k->saddr[3]) * 16777619u;
	h = (h ^ k->daddr[3]) * 16777619u;
	h = (h ^ (((__u32)bpf_ntohs(k->sport) << 16) |
		  bpf_ntohs(k->dport))) * 16777619u;
	h = (h ^ ((__u32)k->proto << 8 | k->family)) * 16777619u;
	h ^= h >> 16;
	return h;
}

static __always_inline struct dpd_wan_tbl *dpd_wan_tbl(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&dpd_wans, &zero);
}

/* Is this ingress device one of the uplinks? (downlink hook traffic must not be
 * re-hashed back out another uplink). Unrolled: the verifier cannot bound a
 * loop that contains map lookups, and "infinite loop detected" is what that
 * looks like at load time. */
static __always_inline int dpd_is_uplink(__u32 ifindex)
{
	struct dpd_wan_tbl *t = dpd_wan_tbl();

	if (!t)
		return 0;
#define DPD_UP_CHK(i)							\
	if ((i) < t->count && t->wan[i].ifindex == ifindex)		\
		return 1;
	DPD_UP_CHK(0) DPD_UP_CHK(1) DPD_UP_CHK(2) DPD_UP_CHK(3)
	DPD_UP_CHK(4) DPD_UP_CHK(5) DPD_UP_CHK(6) DPD_UP_CHK(7)
#undef DPD_UP_CHK
	return 0;
}

/*
 * Weighted rendezvous over the healthy uplinks. Returns a 0-based index or -1.
 *
 * Rendezvous (highest random weight) is used instead of a modulo: adding or
 * removing a WAN, or changing a weight, only moves the flows that hash to the
 * affected node, and the choice is a pure function of the 5-tuple, so two
 * packets of one flow never disagree.
 */
static __always_inline int dpd_pick_wan(const struct dpd_flow_key *k)
{
	struct dpd_wan_tbl *t = dpd_wan_tbl();
	__u64 best = 0;
	int best_i = -1;

	if (!t)
		return -1;
#define DPD_PICK(i) do {						\
	struct dpd_wan *w = &t->wan[i];					\
	if ((i) < t->count && w->ifindex && w->weight &&		\
	    (w->flags & DPD_WAN_F_UP)) {				\
		__u32 h = dpd_flow_hash(k, 0x9e3779b9u * ((i) + 1));	\
		__u64 score = (__u64)h * w->weight;			\
		if (score > best) {					\
			best = score;					\
			best_i = i;					\
		}							\
	}								\
} while (0)
	DPD_PICK(0); DPD_PICK(1); DPD_PICK(2); DPD_PICK(3);
	DPD_PICK(4); DPD_PICK(5); DPD_PICK(6); DPD_PICK(7);
#undef DPD_PICK
	return best_i;
}

/* Copy one entry out of the table by value. Unrolled compares instead of
 * t->wan[wi]: a variable offset into a map value is exactly the kind of thing
 * the verifier rejects, and 28 bytes on the stack is free. */
static __always_inline int dpd_wan_get(__u32 wi, struct dpd_wan *out)
{
	struct dpd_wan_tbl *t = dpd_wan_tbl();

	if (!t)
		return -1;
#define DPD_WAN_CP(i)						\
	if (wi == (i)) {					\
		*out = t->wan[i];				\
		return 0;					\
	}
	DPD_WAN_CP(0) DPD_WAN_CP(1) DPD_WAN_CP(2) DPD_WAN_CP(3)
	DPD_WAN_CP(4) DPD_WAN_CP(5) DPD_WAN_CP(6) DPD_WAN_CP(7)
#undef DPD_WAN_CP
	return -1;
}

/*
 * Hand the packet to the device.
 *   AUTO        - write the L2 header we already have and bpf_redirect() when
 *                 the egress is plain Ethernet; redirect_neigh otherwise
 *   FORCE_NEIGH - always redirect_neigh
 *   FORCE_DEV   - always bpf_redirect(ifindex, 0)  (ppp / veth, header untouched)
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

/* is this a plausible 6-byte MAC? bpf_fib_lookup() only fills dmac/smac when it
 * really found a neighbour and an egress dev_addr, so all-zero means "do not
 * trust this header" and the caller falls back to redirect_neigh(). */
static __always_inline int dpd_mac_ok(const __u8 *m)
{
	return (m[0] | m[1] | m[2] | m[3] | m[4] | m[5]) != 0;
}

/*
 * Emit on a plain Ethernet egress without asking the kernel to look anything up
 * again.
 *
 * bpf_redirect_neigh() returns TC_ACT_REDIRECT immediately; the real work
 * happens afterwards in skb_do_redirect() -> __bpf_redirect_neigh() ->
 * bpf_out_neigh_v4(), which runs ip_route_output_flow() *and* resolves the
 * neighbour for that packet, then builds the L2 header from the neighbour entry
 * and the egress dev_addr. Both of those answers are already in the
 * bpf_fib_lookup result we just did: dmac is the neighbour's ha, smac is the
 * egress device's dev_addr. So the same frame can be produced here with two
 * 6-byte copies and bpf_redirect(ifindex, 0), which is exactly what the
 * neighbour output path does with them (net/core/neighbour.c: neigh_output() ->
 * dev_hard_header() -> dev_queue_xmit()).
 *
 * What this removes per packet: one full FIB lookup, one neighbour table lookup
 * (plus the dst_entry/refcount dance around it), and one skb_dst_set(). It is
 * hardware independent -- it is kernel dataplane work, not a NIC feature.
 *
 * When it is NOT used (the caller decides, see the l2_ok/no_neigh conditions):
 *   - the ingress frame was VLAN tagged: the tag lives in the frame and an
 *     egress that is itself a VLAN sub-interface would push a second one;
 *   - there was no neighbour (ppp, tunnels) -- nothing to write;
 *   - the egress device is stacked (DPD_IF_F_LOWER: vlan/veth/macvlan/tunnel),
 *     where dev_hard_header() does more than copy twelve bytes;
 *   - dmac/smac came back zero, i.e. do not trust them.
 * In all of those cases the caller keeps bpf_redirect_neigh().
 *
 * Returns TC_ACT_REDIRECT when it took the packet, -1 when the caller must fall
 * back. Counted as ST_REDIRECT_OK, like every other bpf_redirect() emit.
 */
static __always_inline int dpd_emit_l2(struct __sk_buff *skb, __u32 ifindex,
				       const __u8 *dmac, const __u8 *smac,
				       struct dpd_stat_val *st)
{
	/* re-derived here rather than passed in: the pointer has to be a fresh
	 * PTR_TO_PACKET with a range check on this path, and an `eth` argument
	 * that survives through the FIB/flow-map code confuses the verifier
	 * ("invalid mem access 'scalar'" on the store). Two loads, no cost. */
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return -1;
	if (!dpd_mac_ok(dmac) || !dpd_mac_ok(smac))
		return -1;

	__builtin_memcpy(eth->h_dest, dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, smac, ETH_ALEN);

	if (bpf_redirect(ifindex, 0) != TC_ACT_REDIRECT)
		return -1;
	DPD_INC(st, ST_REDIRECT_OK);
	return TC_ACT_REDIRECT;
}

/*
 * Decide ONCE, at learn time, how this flow will be emitted. The result is
 * stored in dpd_flow_val.flags, so the hit path needs neither a dpd_iface
 * lookup nor the AUTO re-decision that used to run for every packet.
 *
 *   FORCE_NEIGH -> 0                      (neigh)
 *   FORCE_DEV   -> DEV
 *   NO_NEIGH    -> DEV                    (ppp/tunnel: no L2 header to write)
 *   NOARP/PPP   -> DEV
 *   stacked dev -> 0                      (dev_hard_header does real work)
 *   plain eth   -> L2                     (only when a tagged frame is not in
 *                                          play and dmac/smac are usable)
 */
static __always_inline __u16 dpd_emit_class(struct dpd_config *cfg,
					    __u32 ifindex, int no_neigh,
					    __u8 l2_ok)
{
	__u32 flags = 0;
	__u32 *p;

	if (cfg->redirect == DPD_REDIR_FORCE_NEIGH)
		return 0;
	if (cfg->redirect == DPD_REDIR_FORCE_DEV)
		return DPD_FLOW_F_DEV;
	if (no_neigh)
		return DPD_FLOW_F_DEV;

	p = bpf_map_lookup_elem(&dpd_iface, &ifindex);
	if (p)
		flags = *p;
	if (flags & (DPD_IF_F_NOARP | DPD_IF_F_POINTOPOINT))
		return DPD_FLOW_F_DEV;
	if (l2_ok && !(flags & DPD_IF_F_LOWER))
		return DPD_FLOW_F_L2;
	return 0;
}

/* Emit with a class that was already decided (hit path and stateless path). */
static __always_inline int dpd_emit_cached(struct __sk_buff *skb, __u32 ifindex,
					   __u16 fflags, const __u8 *dmac,
					   const __u8 *smac,
					   struct dpd_stat_val *st)
{
	int r;

	if (fflags & DPD_FLOW_F_L2) {
		r = dpd_emit_l2(skb, ifindex, dmac, smac, st);
		if (r == TC_ACT_REDIRECT)
			return r;
		return TC_ACT_UNSPEC;
	}

	if (fflags & (DPD_FLOW_F_DEV | DPD_FLOW_F_NO_NEIGH)) {
		if (bpf_redirect(ifindex, 0) == TC_ACT_REDIRECT) {
			DPD_INC(st, ST_REDIRECT_OK);
			return TC_ACT_REDIRECT;
		}
		return TC_ACT_UNSPEC;
	}

	/* WHAT THESE COUNTERS MEAN, because the name lies: this helper returns
	 * TC_ACT_REDIRECT as soon as it has accepted the packet. The FIB lookup
	 * and the neighbour resolution happen afterwards, in
	 * skb_do_redirect() -> __bpf_redirect_neigh() -> bpf_out_neigh_v4(),
	 * and every failure there is a silent kfree_skb (verified in
	 * net/core/filter.c of the 6.18.55 tree on 2026-10-17). So
	 * ST_NEIGH_OK counts *requests accepted*, never packets delivered. The
	 * only honest delivery evidence is traffic: the device counters
	 * (eth1 tx_packets / tx_dropped) or the peer answering. */
	if (bpf_redirect_neigh(ifindex, NULL, 0, 0) == TC_ACT_REDIRECT) {
		DPD_INC(st, ST_NEIGH_OK);
		return TC_ACT_REDIRECT;
	}
	DPD_INC(st, ST_NEIGH_FAIL);
	/* The helper failed (no neighbour, no route, ...). A TC program may only
	 * return a TC_ACT_* code; handing back a negative errno would be an action
	 * the kernel does not define. Yield, so the packet takes the normal path. */
	return TC_ACT_UNSPEC;
}

/* Flow timestamp maintenance: refresh at most once per cfg->flow_refresh_ms.
 * 0 keeps the exact "every packet" behaviour. */
static __always_inline void dpd_touch(struct dpd_flow_val *fval, __u32 now,
				      __u32 refresh_ms)
{
	if (!refresh_ms || (__u32)(now - fval->last_seen_ms) >= refresh_ms)
		fval->last_seen_ms = now;
}

/* ------------------------------------------------------------------ program */

SEC(DPD_SEC_NAME)
int dpd_fastpath(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct dpd_config *cfg;
	struct dpd_flow_key fkey = {};
	struct dpd_stat_val *st;
	struct ethhdr *eth;
	__u32 l3_off = sizeof(*eth);
	__u16 h_proto;
	__u16 vlan_id = 0;	/* the 802.1Q/802.1AD VID, if tagged	*/
	__u8 tagged = 0;
	int ret;

	cfg = dpd_get_cfg();
	if (!cfg)
		return TC_ACT_UNSPEC;

	st = dpd_stat();
	DPD_INC(st, ST_PKT_TOTAL);
	DPD_ADD(st, ST_BYTES, skb->len);

	eth = data;
	if ((void *)(eth + 1) > data_end) {
		DPD_INC(st, ST_NON_IP);
		return TC_ACT_UNSPEC;
	}
	h_proto = bpf_ntohs(eth->h_proto);

	if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
		struct dpd_vlan_hdr *vh = data + l3_off;

		if ((void *)(vh + 1) > data_end) {
			DPD_INC(st, ST_NON_IP);
			return TC_ACT_UNSPEC;
		}
		h_proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
		vlan_id = bpf_ntohs(vh->h_vlan_TCI) & 0x0fff;
		tagged = 1;
		l3_off += sizeof(*vh);
	}

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
			DPD_INC(st, ST_FRAG_SKIP);
			return TC_ACT_UNSPEC;
		}

		fkey.family = AF_INET;
		fkey.proto = iph->protocol;
		fkey.saddr[3] = iph->saddr;
		fkey.daddr[3] = iph->daddr;

		if (iph->protocol == IPPROTO_TCP) {
			struct tcphdr *th = (void *)iph + ihl;

			if ((void *)(th + 1) <= data_end) {
				fkey.sport = th->source;
				fkey.dport = th->dest;
			}
		} else if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *uh = (void *)iph + ihl;

			if ((void *)(uh + 1) <= data_end) {
				fkey.sport = uh->source;
				fkey.dport = uh->dest;
			}
		}
	} else if (h_proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6h = data + l3_off;
		__u32 l4_off;
		__u8 nxt;

		if ((void *)(ip6h + 1) > data_end)
			goto non_ip;
		if (!cfg->ipv6) {
			DPD_INC(st, ST_V6_SKIP);
			return TC_ACT_UNSPEC;
		}
		nxt = ip6h->nexthdr;
		/* Extension headers and fragments: the L4 header is not where a
		 * 5-tuple assumes it is. Refuse instead of guessing (44 =
		 * fragment, 0/43/60 = hop-by-hop/routing/dest-opts). */
		if (nxt == IPPROTO_FRAGMENT || nxt == 0 || nxt == 43 || nxt == 60) {
			DPD_INC(st, ST_V6_SKIP);
			return TC_ACT_UNSPEC;
		}
		if (nxt != IPPROTO_TCP && nxt != IPPROTO_UDP) {
			DPD_INC(st, ST_V6_SKIP);
			return TC_ACT_UNSPEC;
		}
		l4_off = l3_off + sizeof(*ip6h);
		if (nxt == IPPROTO_TCP) {
			struct tcphdr *th = data + l4_off;

			if ((void *)(th + 1) > data_end) {
				DPD_INC(st, ST_NON_IP);
				return TC_ACT_UNSPEC;
			}
			fkey.sport = th->source;
			fkey.dport = th->dest;
		} else {
			struct udphdr *uh = data + l4_off;

			if ((void *)(uh + 1) > data_end) {
				DPD_INC(st, ST_NON_IP);
				return TC_ACT_UNSPEC;
			}
			fkey.sport = uh->source;
			fkey.dport = uh->dest;
		}
		fkey.family = AF_INET6;
		fkey.proto = nxt;
		__builtin_memcpy(fkey.saddr, ip6h->saddr.in6_u.u6_addr32,
				 sizeof(fkey.saddr));
		__builtin_memcpy(fkey.daddr, ip6h->daddr.in6_u.u6_addr32,
				 sizeof(fkey.daddr));
	} else {
		goto non_ip;
	}

	/* ---- Mode B: try the self-learned shortcut first ---- */
	if (cfg->mode == DPD_MODE_STATEFUL) {
		__u32 now = (__u32)(bpf_ktime_get_ns() / 1000000ULL);
		__u32 ttl = cfg->flow_ttl_ms;
		struct dpd_flow_val *fval;
		__s32 age;

		/* the freshness test is a *signed* difference: last_seen_ms is a
		 * 32-bit truncation, so an absolute compare would expire every
		 * flow once per 49.7 days. A negative age means the timestamp is
		 * "in the future" (that only happens across that wrap for an
		 * entry nobody refreshed) and is treated as expired. */
		if (ttl > 86400000u)	/* one day: keep the cast in range */
			ttl = 86400000u;

		fval = bpf_map_lookup_elem(&dpd_flows, &fkey);
		age = fval ? (__s32)(now - fval->last_seen_ms) : 0;
		if (fval && fval->egress_ifindex && age >= 0 &&
		    age < (__s32)ttl &&
		    /* epoch: a topology change (link, address, route,
		     * neighbour, WAN re-pick) bumps cfg->epoch and every entry
		     * learned before it stops matching. This one byte compare
		     * replaces the per-packet dpd_wans + dpd_iface re-validation
		     * the hit path used to do. */
		    (fval->wan & DPD_FLOW_EPOCH_MASK) ==
			((cfg->epoch & 0xff) << 8)) {
			__u32 primed = (fval->flags & DPD_FLOW_PRIME_MASK) >>
				       DPD_FLOW_PRIME_SHIFT;

			/*
			 * Prime the direction: the entry is usable, but the
			 * first DPD_FLOW_PRIME hits are handed to the stack
			 * instead of being redirected.
			 *
			 * Why this is not just politeness: taking over the
			 * second packet of a TCP flow means netfilter never
			 * sees the final ACK, so the conntrack entry stays in
			 * SYN_RECV and expires on the 120 s syn_recv timer
			 * while a bulk flow is still running (measured
			 * 2026-10-27: a 12.4 GB download left packets=1
			 * bytes=60 in the table). Letting one more packet per
			 * direction through completes the handshake.
			 */
			if (primed < DPD_FLOW_PRIME) {
				fval->flags = (fval->flags & ~DPD_FLOW_PRIME_MASK) |
					      ((primed + 1) << DPD_FLOW_PRIME_SHIFT);
				dpd_touch(fval, now, cfg->flow_refresh_ms);
				/* not counted as a hit: ST_FLOW_HIT keeps
				 * meaning "packets this program took over". */
				return TC_ACT_UNSPEC;
			}

			DPD_INC(st, ST_FLOW_HIT);
			dpd_touch(fval, now, cfg->flow_refresh_ms);

			/* Only the VLAN policy is re-checked here: every other
			 * gate reads a field of the flow key, and the entry was
			 * only written after those passed. The policy can be
			 * changed by the operator while a flow is live. */
			if (!dpd_policy_ok(cfg, vlan_id, tagged, st))
				return TC_ACT_UNSPEC;

			if (fkey.family == AF_INET)
				ret = dpd_dec_ttl_v4(skb, data, data_end, l3_off);
			else
				ret = dpd_dec_hop_v6(data, data_end, l3_off);
			if (ret > 0) {
				DPD_INC(st, ST_TTL_DROP);
				return TC_ACT_SHOT;
			}
			if (ret < 0)
				return TC_ACT_UNSPEC;

			/* count v6 takeovers separately, so "is IPv6 actually
			 * accelerated here" is answerable from dpdctl */
			if (fkey.family == AF_INET6)
				DPD_INC(st, ST_V6_OK);

			return dpd_emit_cached(skb, fval->egress_ifindex,
					       fval->flags, fval->dmac,
					       fval->smac, st);
		}
		DPD_INC(st, ST_FLOW_MISS);
	}

	/* Every gate below needs no route: family, :53, DHCP, non-unicast and
	 * the VLAN policy all read the flow key or the config. Running them
	 * before bpf_fib_lookup() is what keeps DNS/broadcast/v6 traffic from
	 * paying for an acceleration it can never get. */
	if (!dpd_may_accelerate(cfg, vlan_id, tagged, &fkey, st))
		return TC_ACT_UNSPEC;

	/* ---- FIB lookup, shared by every mode ---- */
	{
		struct bpf_fib_lookup fib = {};
		struct iphdr *iph = data + l3_off;
		__u32 ihl;
		int no_neigh = 0;	/* FIB needed SKIP_NEIGH: no neighbour */

		if ((void *)(iph + 1) > data_end)
			return TC_ACT_UNSPEC;
		ihl = (__u32)iph->ihl * 4;

		fib.ifindex = skb->ifindex;
		fib.family = fkey.family;
		fib.l4_protocol = fkey.proto;
		fib.sport = fkey.sport;
		fib.dport = fkey.dport;
		if (fkey.family == AF_INET) {
			fib.tot_len = bpf_ntohs(iph->tot_len);
			fib.ipv4_src = fkey.saddr[3];
			fib.ipv4_dst = fkey.daddr[3];
		} else {
			struct ipv6hdr *ip6h = data + l3_off;

			fib.tot_len = bpf_ntohs(ip6h->payload_len) +
				      sizeof(*ip6h);
			__builtin_memcpy(fib.ipv6_src, fkey.saddr,
					 sizeof(fib.ipv6_src));
			__builtin_memcpy(fib.ipv6_dst, fkey.daddr,
					 sizeof(fib.ipv6_dst));
		}

		/*
		 * GRO/GSO: the header carries the *aggregate* length (up to 64
		 * KB), which is larger than the MTU. bpf_fib_lookup() then
		 * answers FRAG_NEEDED and the packet is refused -- so the bulk
		 * of the bytes (the coalesced segments) never took the fast
		 * path. Measured 2026-10-27 with GRO on: fib_ok 100k vs
		 * fib_fail 145k, i.e. 60% of packets went the slow path; with
		 * GRO off fib_fail fell to 0 but throughput dropped from 4.5 to
		 * 0.95 Gbit/s because the packet count tripled.
		 *
		 * The MTU test only has to hold for ONE segment, and a segment
		 * is not gso_size: gso_size is the payload length, without the
		 * IP and L4 headers (this is what ABI 9 fixed -- using
		 * gso_size alone under-counted the segment by 28..60 bytes and
		 * could let a segment that really exceeds the MTU through).
		 *   TCP: ihl + th->doff*4 + gso_size
		 *   UDP: ihl + 8          + gso_size
		 * If the L4 header is not parseable, fall back to ihl+payload.
		 */
		if (skb->gso_size && fkey.family == AF_INET) {
			__u32 seg = ihl + skb->gso_size;

			if (fkey.proto == IPPROTO_TCP) {
				struct tcphdr *th = (void *)iph + ihl;

				if ((void *)(th + 1) <= data_end)
					seg += (__u32)th->doff * 4;
			} else if (fkey.proto == IPPROTO_UDP) {
				seg += 8;
			}
			if (seg < fib.tot_len)
				fib.tot_len = (__u16)seg;
		}

		ret = bpf_fib_lookup(skb, &fib, sizeof(fib), 0);
		if (ret == BPF_FIB_LKUP_RET_NO_NEIGH) {
			/* ppp and tunnels have no neighbour table, so the first
			 * pass answers NO_NEIGH even though the route is right
			 * there. Ask for the route only; the emit path for such
			 * a device is bpf_redirect(ifindex), which needs no L2
			 * header. Measured 2026-10-18 on a PPPoE WAN before this
			 * retry: every packet of a working client flow ended in
			 * fib_fail, so acceleration never fired on ppp at all. */
			DPD_INC(st, ST_FIB_RETRY);
			no_neigh = 1;
			ret = bpf_fib_lookup(skb, &fib, sizeof(fib),
					     BPF_FIB_LOOKUP_SKIP_NEIGH);
		}
		if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
			DPD_INC(st, ST_FIB_FAIL);
			return TC_ACT_UNSPEC;
		}
		DPD_INC(st, ST_FIB_OK);

		/* never accelerate traffic that is local to this box */
		if (!fib.ifindex || fib.ifindex == skb->ifindex) {
			DPD_INC(st, ST_LOCAL);
			return TC_ACT_UNSPEC;
		}

		/* ---- Mode 0: observe only. never touch the packet. ---- */
		if (cfg->mode == DPD_MODE_OBSERVE)
			return TC_ACT_UNSPEC;

		/* ---- Mode A (and the #14 probe): take the packet over now ---- */
		if (cfg->mode != DPD_MODE_STATEFUL) {
			__u16 cls = dpd_emit_class(cfg, fib.ifindex, no_neigh,
						   !tagged);

			if (fkey.family == AF_INET)
				ret = dpd_dec_ttl_v4(skb, data, data_end, l3_off);
			else
				ret = dpd_dec_hop_v6(data, data_end, l3_off);
			if (ret > 0) {
				DPD_INC(st, ST_TTL_DROP);
				return TC_ACT_SHOT;
			}
			if (ret < 0)
				return TC_ACT_UNSPEC;

			return dpd_emit_cached(skb, fib.ifindex, cls, fib.dmac,
					       fib.smac, st);
		}

		/* ---- Mode B: learn the shortcut, this packet stays slow ---- */
		{
			struct dpd_flow_val nv = {};
			__u16 cls = dpd_emit_class(cfg, fib.ifindex, no_neigh,
						   !tagged);

			nv.egress_ifindex = fib.ifindex;
			nv.last_seen_ms = (__u32)(bpf_ktime_get_ns() / 1000000ULL);
			nv.flags = cls | (no_neigh ? DPD_FLOW_F_NO_NEIGH : 0);
			nv.wan = (__u16)((__u32)(cfg->epoch & 0xff) << 8);
			__builtin_memcpy(nv.dmac, fib.dmac, ETH_ALEN);
			__builtin_memcpy(nv.smac, fib.smac, ETH_ALEN);

			/*
			 * Multi-WAN: pick an uplink by weighted rendezvous and
			 * steer the slow path of this new flow with a fwmark
			 * (the daemon installs `ip rule fwmark <mark> lookup
			 * <table>` plus a default route per WAN). Only for
			 * packets that did not arrive on an uplink -- downlink
			 * traffic already has its egress (the LAN).
			 *
			 * The FIB lookup above still decides "is this
			 * forwardable at all" (local/unreachable packets return
			 * early), it just no longer decides *which* uplink.
			 */
			if (fkey.family == AF_INET && !dpd_is_uplink(skb->ifindex)) {
				int wi = dpd_pick_wan(&fkey);

				if (wi >= 0 && wi < DPD_WAN_MAX) {
					struct dpd_wan w;

					if (dpd_wan_get((__u32)wi, &w) == 0 &&
					    w.ifindex) {
						nv.egress_ifindex = w.ifindex;
						nv.wan = (__u16)((__u32)(wi + 1) |
							((__u32)(cfg->epoch & 0xff) << 8));
						/* ppp/tun uplinks have no L2
						 * header to write; everything else
						 * gets the usual decision. */
						nv.flags = (w.flags & DPD_WAN_F_L3)
							? (DPD_FLOW_F_DEV | DPD_FLOW_F_WAN)
							: (dpd_emit_class(cfg, w.ifindex, 0, 1) |
							   DPD_FLOW_F_WAN);
						__builtin_memcpy(nv.dmac, w.gw_mac, ETH_ALEN);
						__builtin_memcpy(nv.smac, w.dev_mac, ETH_ALEN);
						skb->mark = w.mark;
					}
				}
			}

			bpf_map_update_elem(&dpd_flows, &fkey, &nv, BPF_ANY);
			/* the map write may have invalidated the cached stats
			 * pointer; re-fetch before counting */
			st = dpd_stat();
			DPD_INC(st, ST_FLOW_WRITE);
			return TC_ACT_UNSPEC;
		}
	}

non_ip:
	DPD_INC(st, ST_NON_IP);
	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
