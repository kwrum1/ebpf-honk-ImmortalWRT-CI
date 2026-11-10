// SPDX-License-Identifier: GPL-2.0-only
/*
 * dpd_fastpath.bpf.c - ebpf TC fastpath.
 *
 * See src/dpd_common.h for the redlines and the hook layout. Short version:
 * no conntrack and no reads of einat maps; the classic ingress program always
 * yields with TC_ACT_UNSPEC unless it has genuinely taken over a packet.
 *
 * ABI 19/20 add two optional halves, both off by default:
 *   classifier/egress   forward SNAT + port allocation (`nat_forward=dpd`)
 *   ingress DNAT        return-path DNAT from dpd_nat_rev (`nat_ingress=dpd`)
 * With the defaults (einat owns NAT) neither program rewrites anything.
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
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "dpd_common.h"

/* Two program variants: L2 ingress (Ethernet, VLAN, bridge) and L3 ingress
 * (ppp/tun, where skb->data starts at the IP header). The attach script picks
 * the section from /sys/class/net/<dev>/flags instead of doing an iface map
 * lookup on every packet. Keep these strings in sync with DPD_SEC_L2/L3 in
 * dpd_common.h and files/dpd-fastpath.sh. */
#define DPD_SEC_L2 "classifier/l2"
#define DPD_SEC_L3 "classifier/l3"

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

/* ABI 12: config + counters in one per-CPU block (struct dpd_cpu). One lookup
 * on the hot path; see dpd_common.h. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dpd_cpu);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpd_cfg SEC(".maps");

/* Mode B: self-learned shortcut table. Populated by nothing but us. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct dpd_flow_key);
	__type(value, struct dpd_flow_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpd_flows SEC(".maps");

/* ABI 18: policy cache written by userspace (dpdctl class / a control-plane
 * plugin). The learn path copies action + skb_priority into the UFS entry, so
 * the hit path never pays for this lookup. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, DPD_CLASS_MAX);
	__type(key, struct dpd_flow_key);
	__type(value, struct dpd_class_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpd_class SEC(".maps");

/* per-ifindex L2 capabilities + IPv4 next hop, filled in from userspace
 * (`dpdctl ifaces` / `dpdctl gw`); see struct dpd_iface_val. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, struct dpd_iface_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpd_iface SEC(".maps");

/* Per-ifindex MTU, learned from userspace by `dpdctl ifaces`
 * (/sys/class/net/<dev>/mtu). The MSS clamp needs the *egress* MTU and
 * bpf_fib_lookup() does not return it, so it is one small map lookup on the
 * SYN/SYN-ACK path only. A missing entry means "unknown": the packet is left
 * alone and ST_MSS_SKIP is counted (an unclamped packet still moves, it just
 * does not get the PPPoE black-hole protection). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpd_mtu SEC(".maps");

/* ABI 20: addresses owned by the router, see struct dpd_local_key. Filled by
 * `dpdctl local sync` and refreshed by dpdfwd on RTM_NEWADDR/DELADDR. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, struct dpd_local_key);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpd_local SEC(".maps");

/* dpd_vlans: optional segment allow-list, u16 VLAN id -> u8 1.
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

/* P2.1: einat full-cone binding cache, mirrored into the DPD object by
 * `dpd-einat`. Key = the LAN source (pre-SNAT) 3-tuple; value = the external
 * address/port einat allocated. The hit path applies this SNAT before emit;
 * the return path is already reverse-NATed by einat's TCX program. Keeping it
 * in a separate map (instead of growing dpd_flow_val) keeps ABI 15 intact.
 * The key/value layout lives in dpd_common.h so dpdctl can dump it. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct dpd_nat_key);
	__type(value, struct dpd_nat_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpd_nat SEC(".maps");

/* ABI 19: return-path DNAT table, mirrored from einat's *reverse* bindings
 * (external tuple -> internal tuple) by dpd-einat-sync. Used only when
 * cfg.nat_ingress is set; with einat's ingress TCX attached the packet is
 * already DNATed and the key does not match, so the mode is safe by default.
 *
 * ABI 20: with nat_forward=dpd this map is also the port ownership table:
 * a candidate external port is free when its reverse entry is absent or its
 * timestamp is older than the TCP TTL. ts_ms is CLOCK_MONOTONIC truncated to
 * 32 bits (0 = foreign/unknown, e.g. an entry mirrored from einat). The
 * layout lives in dpd_common.h. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct dpd_nat_rev_key);
	__type(value, struct dpd_nat_rev_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dpd_nat_rev SEC(".maps");

/* ------------------------------------------------------------------ helpers */

/* ABI 19: return-path DNAT. Rewrites the destination address/port and updates
 * the IP and L4 checksums incrementally. Used only when cfg.nat_ingress is
 * set and einat's ingress TCX is not attached. */
static __always_inline int
dpd_dnat_apply(struct __sk_buff *skb, void *data, void *data_end,
	       __u32 l3_off, __u32 l4_off, const struct dpd_flow_key *k,
	       __be32 new_daddr, __be16 new_dport)
{
	struct iphdr *iph = data + l3_off;
	__be32 old_daddr;
	__be16 old_dport = k->dport;
	__u32 dport_off = 0, csum_off = 0;
	int csum_l4 = 1;

	if (k->family != AF_INET)
		return -1;
	if (k->proto != IPPROTO_TCP && k->proto != IPPROTO_UDP &&
	    k->proto != IPPROTO_ICMP)
		return -1;
	if ((void *)(iph + 1) > data_end)
		return -1;

	old_daddr = iph->daddr;
	if (old_daddr == new_daddr && old_dport == new_dport)
		return 0;

	if (k->proto == IPPROTO_TCP) {
		struct tcphdr *th = data + l4_off;

		if ((void *)(th + 1) > data_end)
			return -1;
		dport_off = l4_off + __builtin_offsetof(struct tcphdr, dest);
		csum_off = l4_off + __builtin_offsetof(struct tcphdr, check);
	} else if (k->proto == IPPROTO_UDP) {
		struct udphdr *uh = data + l4_off;

		if ((void *)(uh + 1) > data_end)
			return -1;
		dport_off = l4_off + __builtin_offsetof(struct udphdr, dest);
		csum_off = l4_off + __builtin_offsetof(struct udphdr, check);
		if (uh->check == 0)
			csum_l4 = 0;
	} else {
		/* ABI 20: ICMP echo. The 16-bit echo id takes the place of the
		 * port; the ICMP checksum does not cover the IP header, so only
		 * the id participates in the L4 fixup. */
		struct icmphdr *ic = data + l4_off;

		if ((void *)(ic + 1) > data_end)
			return -1;
		dport_off = l4_off +
			__builtin_offsetof(struct icmphdr, un.echo.id);
		csum_off = l4_off +
			__builtin_offsetof(struct icmphdr, checksum);
	}

	if (bpf_skb_store_bytes(skb,
				l3_off + __builtin_offsetof(struct iphdr, daddr),
				&new_daddr, sizeof(new_daddr), 0) < 0)
		return -1;
	if (bpf_l3_csum_replace(skb,
				l3_off + __builtin_offsetof(struct iphdr, check),
				(__u64)old_daddr, (__u64)new_daddr,
				sizeof(new_daddr)) < 0)
		return -1;
	/* The ICMPv4 checksum does not cover the IP header, so the address
	 * change must not touch it (unlike TCP/UDP, which have a pseudo
	 * header). */
	if (csum_l4 && k->proto != IPPROTO_ICMP &&
	    bpf_l4_csum_replace(skb, csum_off, (__u64)old_daddr,
				(__u64)new_daddr,
				sizeof(new_daddr) | BPF_F_PSEUDO_HDR) < 0)
		return -1;
	if (old_dport != new_dport) {
		if (bpf_skb_store_bytes(skb, dport_off, &new_dport,
					sizeof(new_dport), 0) < 0)
			return -1;
		if (csum_l4 &&
		    bpf_l4_csum_replace(skb, csum_off, (__u64)old_dport,
					(__u64)new_dport,
					sizeof(new_dport)) < 0)
			return -1;
	}
	return 0;
}

/* ABI 20: forward SNAT. Mirrors dpd_dnat_apply(): rewrites saddr/sport and
 * updates the IP and L4 checksums incrementally. The old tuple is passed in
 * because the caller parsed it already and looked it up. */
static __always_inline int
dpd_snat_apply(struct __sk_buff *skb, void *data, void *data_end,
	       __u32 l3_off, __u32 l4_off, __u8 proto,
	       __be32 old_saddr, __be16 old_sport,
	       __be32 new_saddr, __be16 new_sport)
{
	struct iphdr *iph = data + l3_off;
	__u32 sport_off = 0, csum_off = 0;
	int csum_l4 = 1;

	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP &&
	    proto != IPPROTO_ICMP)
		return -1;
	if ((void *)(iph + 1) > data_end)
		return -1;
	if (iph->saddr != old_saddr)
		return -1;

	if (proto == IPPROTO_TCP) {
		struct tcphdr *th = data + l4_off;

		if ((void *)(th + 1) > data_end)
			return -1;
		sport_off = l4_off + __builtin_offsetof(struct tcphdr, source);
		csum_off = l4_off + __builtin_offsetof(struct tcphdr, check);
	} else if (proto == IPPROTO_UDP) {
		struct udphdr *uh = data + l4_off;

		if ((void *)(uh + 1) > data_end)
			return -1;
		sport_off = l4_off + __builtin_offsetof(struct udphdr, source);
		csum_off = l4_off + __builtin_offsetof(struct udphdr, check);
		if (uh->check == 0)
			csum_l4 = 0;
	} else {
		struct icmphdr *ic = data + l4_off;

		if ((void *)(ic + 1) > data_end)
			return -1;
		sport_off = l4_off +
			__builtin_offsetof(struct icmphdr, un.echo.id);
		csum_off = l4_off +
			__builtin_offsetof(struct icmphdr, checksum);
	}

	if (old_saddr != new_saddr) {
		if (bpf_skb_store_bytes(skb,
			l3_off + __builtin_offsetof(struct iphdr, saddr),
			&new_saddr, sizeof(new_saddr), 0) < 0)
			return -1;
		if (bpf_l3_csum_replace(skb,
			l3_off + __builtin_offsetof(struct iphdr, check),
			(__u64)old_saddr, (__u64)new_saddr,
			sizeof(new_saddr)) < 0)
			return -1;
		if (csum_l4 && proto != IPPROTO_ICMP &&
		    bpf_l4_csum_replace(skb, csum_off, (__u64)old_saddr,
					(__u64)new_saddr,
					sizeof(new_saddr) | BPF_F_PSEUDO_HDR) < 0)
			return -1;
	}
	if (old_sport != new_sport) {
		if (bpf_skb_store_bytes(skb, sport_off, &new_sport,
					sizeof(new_sport), 0) < 0)
			return -1;
		if (csum_l4 &&
		    bpf_l4_csum_replace(skb, csum_off, (__u64)old_sport,
					(__u64)new_sport,
					sizeof(new_sport)) < 0)
			return -1;
	}
	return 0;
}

/* ABI 20: the external address for a new binding. The route's preferred source
 * is the only correct answer on a multi-homed uplink (the lab's eth1 carries
 * both 10.46.0.6 and 198.18.0.1), so ask the FIB once per allocation instead of
 * trusting the first address userspace happened to teach. `fallback` is
 * dpd_iface.addr4 for a box where the lookup fails. */
static __always_inline __be32
dpd_nat_ext_addr(struct __sk_buff *skb, __u32 ifindex, __be32 daddr,
		 __u8 proto, __be16 sport, __be16 dport, __be32 fallback)
{
	struct bpf_fib_lookup fib = {};
	int ret;

	fib.family = AF_INET;
	fib.l4_protocol = proto;
	fib.sport = sport;
	fib.dport = dport;
	fib.ipv4_dst = daddr;
	fib.ifindex = ifindex;
	fib.mark = skb->mark;
	/* tot_len stays 0: no MTU check, a too-big packet must not make the
	 * source lookup fail. SKIP_NEIGH: the neighbour may still be
	 * unresolved on the SYN that triggers the allocation. */
	ret = bpf_fib_lookup(skb, &fib, sizeof(fib),
			     BPF_FIB_LOOKUP_OUTPUT | BPF_FIB_LOOKUP_SRC |
			     BPF_FIB_LOOKUP_SKIP_NEIGH | BPF_FIB_LOOKUP_MARK);
	if (ret == 0 && fib.ipv4_src)
		return fib.ipv4_src;
	return fallback;
}

/* ABI 18: learn-time policy lookup. Port 0 and ifindex 0 are wildcards, so
 * the eight combinations cover "any source port", "any destination port" and
 * "any interface". This runs once per learned flow, never on a hit. */
static __always_inline struct dpd_class_val *
dpd_class_find(const struct dpd_flow_key *fk)
{
	struct dpd_flow_key ck;
	struct dpd_class_val *cv;

	cv = bpf_map_lookup_elem(&dpd_class, fk);
	if (cv)
		return cv;

	ck = *fk;
	ck.sport = 0;
	cv = bpf_map_lookup_elem(&dpd_class, &ck);
	if (cv)
		return cv;

	ck = *fk;
	ck.dport = 0;
	cv = bpf_map_lookup_elem(&dpd_class, &ck);
	if (cv)
		return cv;

	ck = *fk;
	ck.sport = 0;
	ck.dport = 0;
	cv = bpf_map_lookup_elem(&dpd_class, &ck);
	if (cv)
		return cv;

	ck = *fk;
	ck.ifindex = 0;
	cv = bpf_map_lookup_elem(&dpd_class, &ck);
	if (cv)
		return cv;

	ck = *fk;
	ck.ifindex = 0;
	ck.sport = 0;
	cv = bpf_map_lookup_elem(&dpd_class, &ck);
	if (cv)
		return cv;

	ck = *fk;
	ck.ifindex = 0;
	ck.dport = 0;
	cv = bpf_map_lookup_elem(&dpd_class, &ck);
	if (cv)
		return cv;

	ck = *fk;
	ck.ifindex = 0;
	ck.sport = 0;
	ck.dport = 0;
	return bpf_map_lookup_elem(&dpd_class, &ck);
}

/* One lookup gets this CPU's config *and* its counter block (ABI 12). The
 * caller enforces the killer switch on .cfg and bumps counters through .stats;
 * nothing between those bumps may modify a map (only bpf_fib_lookup() /
 * bpf_redirect*() run on that path, and they do not touch dpd_cfg). */
static __always_inline struct dpd_cpu *dpd_cpu(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&dpd_cfg, &zero);
}

#define DPD_INC(s, i)		do { if (s) (s)->v[i]++; } while (0)
#define DPD_ADD(s, i, n)	do { if (s) (s)->v[i] += (n); } while (0)

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

/* ------------------------------------------------------------------ MSS clamp
 *
 * Why this exists: accelerating a TCP flow means fw4 never sees it, and fw4
 * is what clamps MSS (`tcp option maxseg size set rt mtu` in its
 * mangle_prerouting chain, i.e. nft's mtu_fix). On a PPPoE WAN the uplink MTU
 * is 1492 while both end points are on 1500-MTU Ethernet, so they advertise
 * MSS 1460 and the server's first full segment is 1514 bytes on the wire --
 * larger than the path -- and the carrier drops it. PMTUD is supposed to
 * recover that by ICMP, and when the path filters ICMP the symptom is exactly
 * "pages open, downloads hang": the handshake succeeds, the first full-MTU
 * segment disappears.
 *
 * So the accelerated path does what the slow path would have done: rewrite the
 * MSS option of SYN/SYN-ACK to egress_mtu - 40 (IPv4) or - 60 (IPv6). Three
 * deliberate limits:
 *
 *   - only SYN / SYN-ACK. The MSS option exists nowhere else, and touching
 *     data packets would mean recomputing checksums for no reason.
 *   - only packets this program actually takes over. The slow path keeps
 *     receiving fw4's clamp; doing it twice would only hide a broken fw4.
 *   - fail-open. If dpd_mtu has no entry (userspace never taught the egress
 *     device) or the computed MSS is absurd, count ST_MSS_SKIP and leave the
 *     packet alone. A missing clamp is the old behaviour; a *wrong* clamp
 *     (e.g. 0) would break paths that work today.
 *
 * The rewrite is done with the skb helpers rather than direct packet access:
 * the option walk is over a variable offset, which the verifier cannot bound
 * as a raw pointer, and bpf_skb_load_bytes()/bpf_skb_store_bytes() take that
 * offset as a scalar. Checksum repair is the same incremental update the TTL
 * code uses (bpf_l4_csum_replace), so CHECKSUM_PARTIAL skbs stay consistent.
 */

/* MSS ceiling for an MTU, 0 when it cannot be trusted. 536 is the RFC 879
 * floor every stack must accept; below that the clamp would hurt more than
 * the PMTUD problem it solves. */
static __always_inline __u32 dpd_mss_limit(__u32 mtu, int v6)
{
	__u32 overhead = v6 ? 60 : 40;

	if (!mtu || mtu <= overhead)
		return 0;
	if (mtu - overhead < 536)
		return 536;
	return mtu - overhead;
}

/* Smallest known MTU of the two devices a forwarded packet touches, 0 when
 * neither is known.
 *
 * Why both, and why the *reverse* direction matters: the MSS option in a SYN
 * describes what the sender is willing to receive, i.e. it constrains the
 * segments travelling in the opposite direction. For a LAN->WAN SYN the
 * bottleneck of that reverse path is the WAN device (the packet's egress), and
 * for a WAN->LAN SYN-ACK it is also the WAN device (the packet's ingress). So a
 * one-sided rule (egress only) fixes downloads and silently leaves uploads
 * broken on a PPPoE line: the server's SYN-ACK advertises 1460, the client
 * sends 1514-byte frames, the 1492 uplink drops them and PMTUD is what is
 * supposed to recover -- which is exactly what an ICMP filter breaks. Taking the
 * minimum of ingress and egress is correct for both halves of a symmetric
 * forward path, and errs on the safe side (a smaller MSS) otherwise.
 */
static __always_inline __u32 dpd_mtu_min(__u32 a, __u32 b)
{
	__u32 *pa = bpf_map_lookup_elem(&dpd_mtu, &a);
	__u32 *pb = bpf_map_lookup_elem(&dpd_mtu, &b);
	__u32 va = pa ? *pa : 0;
	__u32 vb = pb ? *pb : 0;

	if (!va)
		return vb;
	if (!vb)
		return va;
	return va < vb ? va : vb;
}

static __always_inline void dpd_mss_clamp(struct __sk_buff *skb, __u32 l4_off,
					  __u32 in_ifindex, __u32 out_ifindex,
					  int v6, struct dpd_stat_val *st)
{
	__u32 limit, opt, end, mtu;
	__u8 hdr[2];

	/* Byte 12 of the TCP header is (data offset << 4) | reserved, byte 13
	 * is the flags. A helper read is used instead of direct packet access
	 * because l4_off is a variable offset: the verifier tracks it as a
	 * bounded scalar, not as a packet pointer, and `data + l4_off` would be
	 * rejected as an invalid memory access. It runs for TCP packets only
	 * and costs one helper call; the write path is already helper based. */
	if (bpf_skb_load_bytes(skb, l4_off + 12, hdr, 2) < 0)
		return;
	if (!(hdr[1] & 0x02))	/* not SYN / SYN-ACK: no MSS option */
		return;
	if ((hdr[0] >> 4) < 5)
		return;

	mtu = dpd_mtu_min(in_ifindex, out_ifindex);
	limit = dpd_mss_limit(mtu, v6);
	if (!limit) {
		DPD_INC(st, ST_MSS_SKIP);
		return;
	}
	opt = l4_off + sizeof(struct tcphdr);
	end = l4_off + (__u32)(hdr[0] >> 4) * 4;

	/* TCP options are at most 40 bytes and every option advances by >= 1,
	 * so 20 iterations is an upper bound the verifier can unroll. */
#pragma unroll
	for (int i = 0; i < 20; i++) {
		__u8 b[2];
		__be16 old_be, new_be;
		__u16 mss;
		__u8 kind, len;

		if (opt + 2 > end)
			break;
		if (bpf_skb_load_bytes(skb, opt, b, 2) < 0)
			break;
		kind = b[0];
		if (kind == 0)		/* End of option list */
			break;
		if (kind == 1) {	/* NOP */
			opt += 1;
			continue;
		}
		len = b[1];
		if (len < 2 || opt + len > end)
			break;
		if (kind == 2 && len == 4) {	/* MSS */
			__u8 m[2];

			if (bpf_skb_load_bytes(skb, opt + 2, m, 2) < 0)
				break;
			mss = (__u16)(((__u16)m[0] << 8) | m[1]);
			if (mss <= limit)
				return;
			old_be = bpf_htons(mss);
			new_be = bpf_htons((__u16)limit);
			if (bpf_skb_store_bytes(skb, opt + 2, &new_be,
						sizeof(new_be), 0) < 0)
				break;
			/* TCP checksum field sits at l4_off + 16 */
			bpf_l4_csum_replace(skb, l4_off + 16, old_be, new_be, 2);
			DPD_INC(st, ST_MSS_CLAMP);
			return;
		}
		opt += len;
	}
	DPD_INC(st, ST_MSS_SKIP);
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
	/* ABI 20: ICMP is NATed (echo id <-> external id) but never taken
	 * over. Its UFS key has no ports, so every id of one host->peer pair
	 * would collide in one entry; keeping it on the stack also lets
	 * conntrack see the reply, which after the DNAT matches the original
	 * tuple exactly. */
	if (k->proto == IPPROTO_ICMP)
		return 0;
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
	if (k->family == AF_INET6) {
		__u32 h = bpf_ntohl(k->daddr[0]);

		/* fe80::/10 (link-local) and :: (unspecified) are never routed;
		 * a fast path that tried would either loop or steal neighbour
		 * discovery traffic. */
		if (h == 0 || ((h >> 24) == 0xfe && ((h >> 16) & 0xc0) == 0x80)) {
			DPD_INC(st, ST_V6_SKIP);
			return 0;
		}
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

	/* bpf_redirect_map() would save the per-packet device lookup, but it
	 * is an XDP helper: a sched_cls program cannot call it (the verifier
	 * rejects the load with "program of this type cannot use helper
	 * bpf_redirect_map"). TC has bpf_redirect() and bpf_redirect_neigh()
	 * only, so this stays. */
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
 *   NOARP/PPP   -> DEV                    (no neighbour table, no L2 header)
 *   NO_NEIGH    -> 0                      (Ethernet with a cold ARP cache:
 *                                          let redirect_neigh resolve it)
 *   stacked dev -> 0                      (dev_hard_header does real work)
 *   plain eth   -> L2                     (only when a tagged frame is not in
 *                                          play and dmac/smac are usable)
 */
static __always_inline __u16 dpd_emit_class(struct dpd_config *cfg,
					    __u32 ifindex, int no_neigh,
					    __u8 l2_ok)
{
	struct dpd_iface_val *p;
	__u32 flags = 0;

	if (cfg->redirect == DPD_REDIR_FORCE_NEIGH)
		return 0;
	if (cfg->redirect == DPD_REDIR_FORCE_DEV)
		return DPD_FLOW_F_DEV;

	p = bpf_map_lookup_elem(&dpd_iface, &ifindex);
	if (p)
		flags = p->flags;

	/* ppp / tunnels / NOARP devices: there is no neighbour table and no L2
	 * header to write, but there is still an L2 header on the frame we
	 * hold. bpf_redirect() keeps it, so ppp_start_xmit() prepends the PPP
	 * protocol to an Ethernet header and the BRAS drops every accelerated
	 * packet (live PPPoE box, 2026-11-06: TLS reset after the client's
	 * Finished, downloads stalled at ~56 KB). bpf_redirect_neigh() is the
	 * right emit here: __bpf_redirect_neigh() does skb_pull(ETH_HLEN) and
	 * skb_reset_network_header() before the route/neighbour step, and a
	 * device without header_ops resolves to neigh_direct_output(). */
	if (flags & (DPD_IF_F_NOARP | DPD_IF_F_POINTOPOINT))
		return 0;

	/* NO_NEIGH on an Ethernet egress is NOT the ppp case: it means the
	 * neighbour entry is not resolved *yet* (cold cache, flushed ARP). The
	 * frame we hold still carries the ingress L2 header -- its destination
	 * is our own address on the ingress side -- so emitting it with
	 * bpf_redirect() sends a frame nobody will accept. Measured in the QEMU
	 * lab: a veth egress with a cold neighbour cache black-holed the first
	 * flow (pkt_total 16, redirect_ok 11, no reply) when NO_NEIGH was
	 * mapped to DEV. redirect_neigh() is the correct answer here: it runs
	 * the route lookup and resolves the neighbour before transmitting. */
	if (no_neigh)
		return 0;

	if (l2_ok && !(flags & DPD_IF_F_LOWER))
		return DPD_FLOW_F_L2;
	return 0;
}

/* Emit with a class that was already decided (hit path and stateless path). */
static __always_inline int dpd_emit_cached(struct __sk_buff *skb, __u32 ifindex,
					   __u16 fflags, const __u8 *dmac,
					   const __u8 *smac, __u32 nh4,
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

	/* ABI 15: explicit IPv4 nexthop. Required on ppp/tun egresses: the
	 * route-lookup variant below (params == NULL) calls
	 * ip_route_output_flow() with flowi4_iif == 0, which on a router whose
	 * LAN source only resolves with iif set returns -ENETUNREACH and frees
	 * the packet after this program already said "redirect" (silent, the
	 * only evidence is ST_NEIGH_OK growing with no traffic). With the
	 * nexthop the helper goes straight to ip_neigh_gw4() ->
	 * neigh_direct_output(), i.e. no route lookup at all. */
	if ((fflags & DPD_FLOW_F_NH4) && nh4) {
		struct bpf_redir_neigh nh = {};

		nh.nh_family = AF_INET;
		nh.ipv4_nh = nh4;
		if (bpf_redirect_neigh(ifindex, &nh, sizeof(nh), 0) ==
		    TC_ACT_REDIRECT) {
			DPD_INC(st, ST_NEIGH_OK);
			return TC_ACT_REDIRECT;
		}
		DPD_INC(st, ST_NEIGH_FAIL);
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


/*
 * ABI 22: should the hit path stand down because the hardware owns this flow?
 *
 * ppe_mode semantics (see dpd_common.h):
 *   OFF      never yield -- x86/RK, where no such hardware exists.
 *   YIELD    stand down only when conntrack explicitly reported OFFLOADED.
 *   FALLBACK additionally *take over* a flow the hardware failed or denied,
 *            which is the point of having both engines: DPD is the safety net.
 *
 * ppe_grace_ms keeps DPD off a freshly learned flow long enough for the kernel
 * to decide whether the flowtable/PPE will take it. Without the grace the two
 * engines race, and the loser's counters lie.
 *
 * Returns 1 = hand the packet back to the stack (do not accelerate).
 */
static __always_inline int dpd_ppe_yield(const struct dpd_config *cfg,
					 const struct dpd_flow_val *fval,
					 __u32 age, struct dpd_stat_val *st)
{
	if (cfg->ppe_mode == DPD_PPE_OFF)
		return 0;

	switch (fval->ct_cookie) {
	case DPD_PPE_OFFLOADED:
	case DPD_PPE_YIELDED:
		/* The kernel already handed this flow to a flowtable (or NSS).
		 * Redirecting it would either double-process the packet or
		 * count hits for traffic that no longer reaches us. */
		DPD_INC(st, ST_PPE_YIELD);
		return 1;
	case DPD_PPE_FAILED:
	case DPD_PPE_DENIED:
		/* Hardware tried and did not take it. FALLBACK means DPD
		 * deliberately becomes the data path here; YIELD means the
		 * operator wants the stack to handle the failure. */
		return cfg->ppe_mode == DPD_PPE_FALLBACK ? 0 : 1;
	default:
		break;
	}

	/* UNKNOWN / SW_ACTIVE: still inside the grace window? Give the kernel
	 * its chance before DPD claims the flow. */
	if (cfg->ppe_grace_ms && age < (__s32)cfg->ppe_grace_ms) {
		DPD_INC(st, ST_PPE_GRACE);
		return 1;
	}
	return 0;
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

static __always_inline int dpd_fastpath_common(struct __sk_buff *skb,
					       const __u8 force_l3)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	/* Read the interface index once, before any pointer spills. On 6.18.55
	 * a later `skb->ifindex` made clang spill the *ctx pointer* and the
	 * verifier rejected the reload with "dereference of modified ctx ptr";
	 * 6.18.60 happened to accept it. A plain scalar local avoids the
	 * difference entirely. */
	__u32 ifindex = skb->ifindex;
	struct dpd_config *cfg;
	struct dpd_cpu *cpu;
	struct dpd_flow_key fkey = {};
	struct dpd_stat_val *st;
	struct ethhdr *eth;
	__u32 l3_off = sizeof(*eth);
	__u32 l4_off = 0;	/* set once the L3 header length is known */
	__u16 h_proto;
	__u16 vlan_id = 0;	/* the 802.1Q/802.1AD VID, if tagged	*/
	__u8 tagged = 0;
	__u8 tag_meta = 0;	/* tag lives in skb->vlan_tci, not in the frame */
	__u8 l3in = force_l3;	/* set by the L2/L3 program variant	*/
	int ret;

	cpu = dpd_cpu();
	if (!cpu || !cpu->cfg.enable || cpu->cfg.mode == DPD_MODE_OFF)
		return TC_ACT_UNSPEC;
	cfg = &cpu->cfg;
	/* ABI 12: the same lookup that returned cfg also carries this CPU's
	 * counters; one map access for both. */
	st = &cpu->stats;
	DPD_INC(st, ST_PKT_TOTAL);
	DPD_ADD(st, ST_BYTES, skb->len);

	/* ABI 13: the NIC/veth may hand us the 802.1Q tag as metadata
	 * (skb->vlan_present + vlan_tci) with the frame itself untagged. Both
	 * forms have to be seen as "tagged", because the take-over path has to
	 * pop them; only the in-band form shifts the L3 offset when popped. */
	if (skb->vlan_present) {
		tagged = 1;
		tag_meta = 1;
		vlan_id = skb->vlan_tci & 0x0fff;
	}

	/* The L3 variant is attached to ppp/tun devices: skb->data starts at the
	 * IP header, so there is no Ethernet header to parse and no iface map
	 * lookup on the hot path. The attach script chooses this section from
	 * IFF_NOARP/IFF_POINTOPOINT. */
	if (l3in)
		l3_off = 0;

	eth = data;
	if ((void *)(eth + 1) > data_end) {
		DPD_INC(st, ST_NON_IP);
		return TC_ACT_UNSPEC;
	}

	if (l3in) {
		__u8 ver = *(__u8 *)data >> 4;

		if (ver == 4)
			h_proto = ETH_P_IP;
		else if (ver == 6)
			h_proto = ETH_P_IPV6;
		else
			goto non_ip;
	} else {
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
			tag_meta = 0;
			l3_off += sizeof(*vh);
		}
	}

	fkey.ifindex = ifindex;

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
		l4_off = l3_off + ihl;

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

	/* ABI 19: optional DPD-owned return-path DNAT. With einat's ingress
	 * TCX attached the packet already carries the internal destination and
	 * the reverse key does not match, so this is a no-op by default. It is
	 * only effective after the ingress TCX link is detached. */
	if (cfg->nat_ingress && fkey.family == AF_INET &&
	    (fkey.proto == IPPROTO_TCP || fkey.proto == IPPROTO_UDP ||
	     fkey.proto == IPPROTO_ICMP)) {
		struct dpd_nat_rev_key rk = {};
		struct dpd_nat_rev_val *rv;
		int nat_ok = 1;

		if (fkey.proto == IPPROTO_ICMP) {
			struct icmphdr *ic = data + l4_off;

			/* ABI 20: only an echo reply carries a mapping; a
			 * request from the LAN must never be "de-NATed". */
			if ((void *)(ic + 1) <= data_end &&
			    ic->type == ICMP_ECHOREPLY) {
				fkey.dport = ic->un.echo.id;
			} else {
				nat_ok = 0;
			}
		}

		rk.daddr = fkey.daddr[3];
		rk.dport = fkey.dport;
		rk.proto = fkey.proto;
		rv = nat_ok ? bpf_map_lookup_elem(&dpd_nat_rev, &rk) : NULL;
		if (rv && rv->saddr) {
			__be32 ndaddr = rv->saddr;
			__be16 ndport = rv->sport;

			if (dpd_dnat_apply(skb, data, data_end, l3_off, l4_off,
					   &fkey, ndaddr, ndport) < 0)
				return TC_ACT_UNSPEC;
			data = (void *)(long)skb->data;
			data_end = (void *)(long)skb->data_end;
			fkey.daddr[3] = ndaddr;
			fkey.dport = ndport;
			DPD_INC(st, ST_NAT_DNAT);
		}
	}

	/* ABI 14: IP bytes by family, the denominator of the homepage share.
	 * Non-IP frames never reach here (they take the non_ip path). */
	DPD_ADD(st, fkey.family == AF_INET ? ST_BYTES_V4 : ST_BYTES_V6, skb->len);

	/* ---- Mode B: try the self-learned shortcut first ---- */
	if (cfg->mode == DPD_MODE_STATEFUL) {
		/* One clock domain only: learn (line ~2021), the NAT stamp
		 * and this read all use bpf_ktime_get_ns(). A coarse clock
		 * here would be a different time base (MONOTONIC_COARSE can
		 * lag by a tick), making age negative -- and a negative age
		 * means "expired", so every flow would be dropped on its
		 * first hit. The ~10 cycles are not worth that class of bug;
		 * measure it properly before revisiting. */
		__u32 now = (__u32)(bpf_ktime_get_ns() / 1000000ULL);
		__u32 ttl = cfg->flow_ttl_ms;
		struct dpd_flow_val *fval;
		__s32 age;

		fval = bpf_map_lookup_elem(&dpd_flows, &fkey);

		/* ABI 17: per-protocol timeouts. A UDP flow that has not seen a
		 * reply yet uses the short one-way timeout (pf's 30 s), the
		 * longer one as soon as the reverse entry exists. 0 falls back
		 * to flow_ttl_ms. */
		if (fval) {
			if (fkey.proto == IPPROTO_TCP && cfg->tcp_ttl_ms) {
				ttl = cfg->tcp_ttl_ms;
			} else if (fkey.proto == IPPROTO_UDP) {
				__u32 u = (fval->flags & DPD_FLOW_F_REPLY) ?
					  cfg->udp_ttl_ms :
					  cfg->udp_unidir_ttl_ms;

				if (u)
					ttl = u;
			}
		}

		/* the freshness test is a *signed* difference: last_seen_ms is a
		 * 32-bit truncation, so an absolute compare would expire every
		 * flow once per 49.7 days. A negative age means the timestamp is
		 * "in the future" (that only happens across that wrap for an
		 * entry nobody refreshed) and is treated as expired. */
		if (ttl > 86400000u)	/* one day: keep the cast in range */
			ttl = 86400000u;

		age = fval ? (__s32)(now - fval->last_seen_ms) : 0;

		/* A dead entry is removed on the spot instead of waiting for LRU
		 * eviction: expired, epoch-stale (topology change), or never got
		 * an egress. Measured on the N5000 2026-11-09: the map was 96%
		 * older than the largest TTL after two hours online, because
		 * nothing but LRU ever removed an entry. Deleting here is one
		 * helper call on a lookup that was going to miss anyway. */
		if (fval && (!fval->egress_ifindex || age < 0 ||
			     age >= (__s32)ttl ||
			     (fval->wan & DPD_FLOW_EPOCH_MASK) !=
				((cfg->epoch & 0xff) << 8))) {
			bpf_map_delete_elem(&dpd_flows, &fkey);
			fval = NULL;
			age = 0;
		}

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
			__u32 prime = cfg->accel_after_pkts;

			/* ABI 18: the policy action cached at learn time. The
			 * class map is not consulted here, so this is two
			 * compares plus (optionally) the per-flow counters. */
			if (fval->action == DPD_ACT_BLOCK) {
				DPD_INC(st, ST_FLOW_BLOCK);
				return TC_ACT_SHOT;
			}
			if (fval->action == DPD_ACT_PROXY ||
			    fval->action == DPD_ACT_LOCAL) {
				DPD_INC(st, ST_FLOW_SKIP);
				return TC_ACT_UNSPEC;
			}
			/* ABI 20: 1 = update the per-flow counters on every hit,
			 * 2 = only when (packets & 0xf) == 0, i.e. one hit in
			 * 16. Mode 2 trades telemetry precision for the two
			 * 64-bit RMWs a hit would otherwise pay: packets/bytes
			 * read as a sampled rate (the bytes/packets ratio stays
			 * right), and a flow that ends before its first sample
			 * is not counted at all. 0 keeps both stores off the
			 * hit path; the added test is one compare and a mask. */
			if (cfg->flow_counters == 1 ||
			    (cfg->flow_counters == 2 &&
			     (fval->packets & 0xf) == 0)) {
				fval->packets++;
				fval->bytes += skb->len;
			}

			/* ABI 17: a FIN/RST releases the flow immediately. The
			 * packet itself goes to the stack (the TCP state machine
			 * there still has work to do), and the reverse entry is
			 * left to its TTL. Without this a closed connection kept
			 * its UFS entries until the (now much longer) TCP TTL. */
			if (fkey.proto == IPPROTO_TCP) {
				struct tcphdr *th = data + l4_off;

				if ((void *)(th + 1) <= data_end &&
				    (th->fin || th->rst)) {
					/* ABI 21: release the reverse entry too.
					 * It used to wait for its TTL, which is
					 * the longest-lived half of a closed
					 * connection. */
					struct dpd_flow_key rk = fkey;
					__u32 tp = rk.sport;
					int wi;

					fval->state = DPD_FLOW_STATE_FIN;
					bpf_map_delete_elem(&dpd_flows, &fkey);
					rk.ifindex = fval->egress_ifindex;
					rk.sport = rk.dport;
					rk.dport = tp;
#pragma unroll
					for (wi = 0; wi < 4; wi++) {
						__u32 w = rk.saddr[wi];

						rk.saddr[wi] = rk.daddr[wi];
						rk.daddr[wi] = w;
					}
					bpf_map_delete_elem(&dpd_flows, &rk);
					DPD_INC(st, ST_FLOW_FIN);
					return TC_ACT_UNSPEC;
				}
			}

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
			 *
			 * ABI 17: the count is cfg->accel_after_pkts (default
			 * 32), so short flows never enter the fast path at all.
			 * The counter is 7 bits; clamp so a bad config cannot
			 * overflow into DPD_FLOW_F_REPLY.
			 */
			if (prime > 127)
				prime = 127;
			if (primed < prime) {
				fval->flags = (fval->flags & ~DPD_FLOW_PRIME_MASK) |
					      ((primed + 1) << DPD_FLOW_PRIME_SHIFT);
				if (primed + 1 >= prime) {
					fval->state = DPD_FLOW_STATE_BIND;
					DPD_INC(st, ST_FLOW_BIND);
				}
				dpd_touch(fval, now, cfg->flow_refresh_ms);
				/* not counted as a hit: ST_FLOW_HIT keeps
				 * meaning "packets this program took over". */
				return TC_ACT_UNSPEC;
			}

			/* prime == 0: the first hit is already a takeover. */
			if (fval->state != DPD_FLOW_STATE_BIND) {
				fval->state = DPD_FLOW_STATE_BIND;
				DPD_INC(st, ST_FLOW_BIND);
			}

			/* ABI 22: the software/hardware handover. This has to
			 * run before the counters below, because a yielded
			 * packet was never taken over. */
			if (dpd_ppe_yield(cfg, fval, age, st))
				return TC_ACT_UNSPEC;

			DPD_INC(st, ST_FLOW_HIT);
			dpd_touch(fval, now, cfg->flow_refresh_ms);

			/* Only the VLAN policy is re-checked here: every other
			 * gate reads a field of the flow key, and the entry was
			 * only written after those passed. The policy can be
			 * changed by the operator while a flow is live. */
			if (!dpd_policy_ok(cfg, vlan_id, tagged, st))
				return TC_ACT_UNSPEC;

			/* P2.1: the forward half is SNATed by einat's TCX egress
			 * program, which still runs on an skb we redirect from
			 * ingress (measured on 2026-11-09: einat's egress hook
			 * allocated a second external port for an already
			 * rewritten packet, so rewriting here double-NATs and
			 * the server drops every ACK). dpd_nat is therefore a
			 * *gate*, not a rewrite: it proves einat has a binding
			 * for this flow, so the egress hook can SNAT it.
			 * Return traffic is reverse-NATed by einat's TCX ingress
			 * before this classic program sees it. */
			/* ABI 20: in nat_forward=dpd mode there is no einat
			 * binding to gate on -- the egress program below owns
			 * the rewrite and allocates on its own miss. */
			if (!cfg->nat_forward &&
			    (fval->flags & DPD_FLOW_F_NAT) &&
			    fkey.family == AF_INET &&
			    (fkey.proto == IPPROTO_TCP || fkey.proto == IPPROTO_UDP) &&
			    (__u32)(now - fval->nat_checked_ms) >=
					DPD_NAT_CHECK_MS) {
				struct dpd_nat_key nk = {};
				struct dpd_nat_val *nv;

				nk.saddr = fkey.saddr[3];
				nk.sport = fkey.sport;
				nk.proto = fkey.proto;
				nv = bpf_map_lookup_elem(&dpd_nat, &nk);
				if (!nv || !nv->to_addr) {
					DPD_INC(st, ST_NAT_GONE);
					return TC_ACT_UNSPEC;
				}
				fval->nat_checked_ms = now;
			}

			/* ABI 18: restore the QoS priority cached at learn time.
			 * The accelerated packet skips the stack's classifier, so
			 * without this the egress qdisc would see priority 0. */
			if (fval->skb_priority)
				skb->priority = fval->skb_priority;

			/* NOTE: the uplink acceleration is safe only with
			 * net.netfilter.nf_conntrack_tcp_be_liberal=1. The
			 * accelerated ACKs never reach conntrack, so its TCP window
			 * goes stale; the server's replies then arrive "out of
			 * window" and fw4 would mark them INVALID and REJECT them
			 * with a RST. The router-dataplane init and sysctl.d set it. */

			/* ABI 13: this flow arrives tagged, so every packet
			 * carries a tag that has to go before the L2 emit.
			 * Only an in-band tag shifts L3/L4; a metadata tag
			 * (skb->vlan_tci) leaves the frame layout alone. */
			if (tagged) {
				if (bpf_skb_vlan_pop(skb) < 0) {
					DPD_INC(st, ST_TAG_SKIP);
					return TC_ACT_UNSPEC;
				}
				DPD_INC(st, ST_TAG_POP);
				if (!tag_meta) {
					l3_off -= 4;
					l4_off -= 4;
				}
				data = (void *)(long)skb->data;
				data_end = (void *)(long)skb->data_end;
			}

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

			/* ABI 11: the fast path bypasses fw4's mtu_fix, so a SYN
			 * we take over here is the only chance to keep a PPPoE
			 * path from black-holing full-size segments. Only TCP
			 * SYN/SYN-ACK parses; for every other packet this is one
			 * proto compare. */
			if (cfg->mss_clamp && fkey.proto == IPPROTO_TCP)
				dpd_mss_clamp(skb, l4_off, ifindex,
					      fval->egress_ifindex,
					      fkey.family == AF_INET6, st);

			/* count v6 takeovers separately, so "is IPv6 actually
			 * accelerated here" is answerable from dpdctl */
			if (fkey.family == AF_INET6)
				DPD_INC(st, ST_V6_OK);

			/* Downlink from a ppp/tun device: the skb is L3 and the
			 * LAN is Ethernet, so push a zeroed Ethernet header
			 * (bpf_skb_change_head is exactly "L3 skb -> L2
			 * redirect": __skb_push + memset + reset mac header).
			 * dpd_emit_l2() fills in the two MACs, we set the
			 * ethertype, which the pushed header does not have. */
			if (l3in) {
				if (!(fval->flags & DPD_FLOW_F_L2) ||
				    bpf_skb_change_head(skb, ETH_HLEN, 0) < 0)
					return TC_ACT_UNSPEC;
				data = (void *)(long)skb->data;
				data_end = (void *)(long)skb->data_end;
				eth = data;
				if ((void *)(eth + 1) > data_end)
					return TC_ACT_UNSPEC;
				eth->h_proto = bpf_htons(fkey.family == AF_INET ?
							 ETH_P_IP : ETH_P_IPV6);
			}

			ret = dpd_emit_cached(skb, fval->egress_ifindex,
					      fval->flags, fval->dmac,
					      fval->smac, fval->nh4, st);
			if (ret == TC_ACT_REDIRECT) {
				if (fkey.family == AF_INET) {
					DPD_ADD(st, ST_BYTES_HIT_V4, skb->len);
					if (fval->flags & DPD_FLOW_F_L2)
						DPD_INC(st, ST_L2_V4);
				} else {
					DPD_ADD(st, ST_BYTES_HIT_V6, skb->len);
					if (fval->flags & DPD_FLOW_F_L2)
						DPD_INC(st, ST_L2_V6);
				}
			}
			return ret;
		}
		DPD_INC(st, ST_FLOW_MISS);
	}

	/* Every gate below needs no route: family, :53, DHCP, non-unicast and
	 * the VLAN policy all read the flow key or the config. Running them
	 * before bpf_fib_lookup() is what keeps DNS/broadcast/v6 traffic from
	 * paying for an acceleration it can never get. */
	if (!dpd_may_accelerate(cfg, vlan_id, tagged, &fkey, st))
		return TC_ACT_UNSPEC;

	/* Fast local-delivery judgement: a packet addressed to one of the
	 * router's own addresses is never forwarded, so bpf_fib_lookup() can
	 * only answer NOT_FWDED and bump fib_fail. The list is small (one
	 * entry per iface address) and refreshed by userspace on address
	 * changes. This runs on the miss path only, before the expensive FIB
	 * lookup; forwarded flows pay one small hash lookup. */
	{
		struct dpd_local_key lk = {};

		lk.family = fkey.family;
		if (fkey.family == AF_INET)
			__builtin_memcpy(lk.addr, &fkey.daddr[3], 4);
		else
			__builtin_memcpy(lk.addr, fkey.daddr, sizeof(lk.addr));
		if (bpf_map_lookup_elem(&dpd_local, &lk)) {
			DPD_INC(st, ST_LOCAL);
			return TC_ACT_UNSPEC;
		}
	}

	/* ---- FIB lookup, shared by every mode ---- */
	{
		struct bpf_fib_lookup fib = {};
		struct iphdr *iph = data + l3_off;
		__u32 ihl;
		int no_neigh = 0;	/* FIB needed SKIP_NEIGH: no neighbour */

		if ((void *)(iph + 1) > data_end)
			return TC_ACT_UNSPEC;
		ihl = (__u32)iph->ihl * 4;

		fib.ifindex = ifindex;
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
		if (skb->gso_size) {
			__u32 l4h = 0;
			__u32 seg;

			if (fkey.proto == IPPROTO_TCP) {
				struct tcphdr *th = data + l3_off +
					(fkey.family == AF_INET ? ihl :
					 sizeof(struct ipv6hdr));

				if ((void *)(th + 1) <= data_end)
					l4h = (__u32)th->doff * 4;
			} else if (fkey.proto == IPPROTO_UDP) {
				l4h = 8;
			}

			/* One segment = L3 header + L4 header + gso_size. v4's L3
			 * header is ihl, v6's is a fixed 40 bytes. */
			seg = (fkey.family == AF_INET ? ihl : sizeof(struct ipv6hdr)) +
			      l4h + skb->gso_size;
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
		if (!fib.ifindex || fib.ifindex == ifindex) {
			DPD_INC(st, ST_LOCAL);
			return TC_ACT_UNSPEC;
		}

		/* P2.1: a WAN egress (learned IPv4 nexthop) may need SNAT.
		 * With einat on the uplink (nat_offload) the packet may be taken
		 * over once einat has allocated a binding -- the daemon mirrors
		 * it into dpd_nat, and einat's TCX egress still does the actual
		 * rewrite. Without one, stay on the slow path so einat can
		 * create it. With no einat at all, never take the uplink half:
		 * a redirected packet skips fw4's masquerade. The return half is
		 * reverse-NATed before we see it and needs no entry here. */
		{
			struct dpd_iface_val *eg =
				bpf_map_lookup_elem(&dpd_iface, &fib.ifindex);

			if (eg && eg->gw4) {
				struct dpd_nat_key nk = {};
				struct dpd_nat_val *nv;

				if (!cfg->nat_offload)
					return TC_ACT_UNSPEC;
				if (fkey.family != AF_INET ||
				    (fkey.proto != IPPROTO_TCP &&
				     fkey.proto != IPPROTO_UDP))
					return TC_ACT_UNSPEC;
				/* ABI 20: DPD's egress program allocates on its
				 * own first packet, so there is nothing to wait
				 * for here. ICMP and other protocols still stay
				 * on the stack: DPD has no SNAT for them. */
				if (!cfg->nat_forward) {
					struct dpd_nat_rev_key rk = {};
					struct dpd_nat_rev_val *rv;

					nk.saddr = fkey.saddr[3];
					nk.sport = fkey.sport;
					nk.proto = fkey.proto;
					nv = bpf_map_lookup_elem(&dpd_nat, &nk);
					if (!nv || !nv->to_addr)
						return TC_ACT_UNSPEC;
					/* The reverse entry must point back at this
					 * internal tuple. A forward/reverse mismatch
					 * means the binding was recycled or
					 * overwritten (a long-lived flow outliving
					 * its NAT binding); accelerating would emit
					 * with the wrong external port. Keep such a
					 * flow on the stack. */
					rk.daddr = nv->to_addr;
					rk.dport = nv->to_port;
					rk.proto = fkey.proto;
					rv = bpf_map_lookup_elem(&dpd_nat_rev, &rk);
					if (!rv || rv->saddr != fkey.saddr[3] ||
					    rv->sport != fkey.sport) {
						DPD_INC(st, ST_NAT_GONE);
						return TC_ACT_UNSPEC;
					}
				}
			}
		}

		/* ---- Mode 0: observe only. never touch the packet. ---- */
		if (cfg->mode == DPD_MODE_OBSERVE)
			return TC_ACT_UNSPEC;

		/* ---- Mode A (and the #14 probe): take the packet over now ---- */
		if (cfg->mode != DPD_MODE_STATEFUL) {
			__u16 cls = dpd_emit_class(cfg, fib.ifindex, no_neigh, 1);

			/* ABI 13: a tagged frame can only be taken over when the
			 * egress is plain Ethernet (L2 class); then the tag has
			 * to be popped before the header is rewritten. A stacked
			 * egress keeps tag ownership with the stack. */
			if (tagged) {
				if (!(cls & DPD_FLOW_F_L2)) {
					DPD_INC(st, ST_TAG_SKIP);
					return TC_ACT_UNSPEC;
				}
				if (bpf_skb_vlan_pop(skb) < 0) {
					DPD_INC(st, ST_TAG_SKIP);
					return TC_ACT_UNSPEC;
				}
				DPD_INC(st, ST_TAG_POP);
				if (!tag_meta) {
					l3_off -= 4;
					l4_off -= 4;
				}
				data = (void *)(long)skb->data;
				data_end = (void *)(long)skb->data_end;
			}

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

			/* same clamp as the hit path, using the FIB egress */
			if (cfg->mss_clamp && fkey.proto == IPPROTO_TCP)
				dpd_mss_clamp(skb, l4_off, ifindex,
					      fib.ifindex,
					      fkey.family == AF_INET6, st);

			/* Downlink from a ppp/tun device: see the hit-path
			 * equivalent; only an Ethernet egress is possible. */
			if (l3in) {
				if (!(cls & DPD_FLOW_F_L2) ||
				    bpf_skb_change_head(skb, ETH_HLEN, 0) < 0)
					return TC_ACT_UNSPEC;
				data = (void *)(long)skb->data;
				data_end = (void *)(long)skb->data_end;
				eth = data;
				if ((void *)(eth + 1) > data_end)
					return TC_ACT_UNSPEC;
				eth->h_proto = bpf_htons(fkey.family == AF_INET ?
							 ETH_P_IP : ETH_P_IPV6);
			}

			{
				struct dpd_iface_val *ep;
				__u32 eif = fib.ifindex;
				__u32 nh4 = 0;

				ep = bpf_map_lookup_elem(&dpd_iface, &eif);
				if (ep && (ep->flags & (DPD_IF_F_NOARP |
							DPD_IF_F_POINTOPOINT)) &&
				    fkey.family == AF_INET)
					nh4 = ep->gw4;
				ret = dpd_emit_cached(skb, fib.ifindex, cls,
						      fib.dmac, fib.smac, nh4, st);
			}
			if (ret == TC_ACT_REDIRECT) {
				if (fkey.family == AF_INET) {
					DPD_ADD(st, ST_BYTES_HIT_V4, skb->len);
					if (cls & DPD_FLOW_F_L2)
						DPD_INC(st, ST_L2_V4);
				} else {
					DPD_ADD(st, ST_BYTES_HIT_V6, skb->len);
					if (cls & DPD_FLOW_F_L2)
						DPD_INC(st, ST_L2_V6);
				}
			}
			return ret;
		}

		/* ---- Mode B: learn the shortcut, this packet stays slow ---- */
		{
			struct dpd_flow_val nv = {};
			__u16 cls;

			/*
			 * IPv6: never learn from the uplink. Inbound-initiated v6
			 * connections stay on the stack (same as v4, where einat drops
			 * the unsolicited SYN before netfilter). Outbound flows seed
			 * their own reverse entry below.
			 */
			if (fkey.family == AF_INET6 && dpd_is_uplink(ifindex))
				return TC_ACT_UNSPEC;

			cls = dpd_emit_class(cfg, fib.ifindex, no_neigh, 1);

			/* An L3 ingress can only be emitted to an Ethernet
			 * egress, where the hit path pushes a new L2 header with
			 * bpf_skb_change_head(). An L3->L3 hairpin would need
			 * bpf_redirect() instead; leave it on the stack. */
			if (l3in && !(cls & DPD_FLOW_F_L2))
				return TC_ACT_UNSPEC;

			/* ABI 13: only learn tagged flows whose egress is plain
			 * Ethernet, where the hit path can pop the tag itself. */
			if (tagged && !(cls & DPD_FLOW_F_L2))
				return TC_ACT_UNSPEC;

			nv.egress_ifindex = fib.ifindex;
			nv.last_seen_ms = (__u32)(bpf_ktime_get_ns() / 1000000ULL);
			nv.flags = cls | ((cls & DPD_FLOW_F_DEV) ?
					  DPD_FLOW_F_NO_NEIGH : 0) |
				   (tagged ? DPD_FLOW_F_TAG : 0);
			nv.wan = (__u16)((__u32)(cfg->epoch & 0xff) << 8);
			__builtin_memcpy(nv.dmac, fib.dmac, ETH_ALEN);
			__builtin_memcpy(nv.smac, fib.smac, ETH_ALEN);

			/* ABI 15: remember that the egress is a ppp/tun device, and
			 * its nexthop if we know one. The hit path uses L3OUT to
			 * keep the *uplink* on the slow path until einat's egress
			 * SNAT is verified for TC-redirected packets (on the live
			 * PPPoE box of 2026-11-06 it was not applied: accelerated
			 * packets left unNATed and died upstream). The downlink
			 * needs no NAT here -- einat DNATed at its own TC ingress
			 * hook before ours -- so it stays accelerated. */
			{
				struct dpd_iface_val *ep;
				__u32 eif = fib.ifindex;

				ep = bpf_map_lookup_elem(&dpd_iface, &eif);
				/* ABI 16: with einat on the uplink, a flow whose
				 * egress has a learned nexthop is NATed. Mark it so
				 * the hit path keeps re-checking einat's binding;
				 * the return half has no such mark and never pays. */
				if (cfg->nat_offload && ep && ep->gw4)
					nv.flags |= DPD_FLOW_F_NAT;
				if (ep && (ep->flags & (DPD_IF_F_NOARP |
							DPD_IF_F_POINTOPOINT))) {
					nv.flags |= DPD_FLOW_F_L3OUT;
					/* nh4 is an IPv4 nexthop: a v6 packet
					 * must not carry it, bpf_out_neigh_v6()
					 * drops on a non-AF_INET6 nh. */
					if (ep->gw4 && fkey.family == AF_INET) {
						nv.nh4 = ep->gw4;
						nv.flags |= DPD_FLOW_F_NH4;
					}
				}
			}

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
			if (fkey.family == AF_INET && !dpd_is_uplink(ifindex)) {
				int wi = dpd_pick_wan(&fkey);

				if (wi >= 0 && wi < DPD_WAN_MAX) {
					struct dpd_wan w;

					if (dpd_wan_get((__u32)wi, &w) == 0 &&
					    w.ifindex) {
						nv.egress_ifindex = w.ifindex;
						nv.wan = (__u16)((__u32)(wi + 1) |
							((__u32)(cfg->epoch & 0xff) << 8));
						/* ABI 13: a tagged flow can only
						 * be learned when this uplink has an
						 * L2 header to rewrite; a ppp/tun
						 * uplink cannot pop the tag. */
						if (tagged && (w.flags & DPD_WAN_F_L3))
							return TC_ACT_UNSPEC;
						/* L3 uplinks (ppp/tun) have no
						 * neighbour table: the neigh
						 * class pulls the Ethernet header
						 * and emits through direct output. */
						nv.flags = dpd_emit_class(cfg, w.ifindex,
									  (w.flags & DPD_WAN_F_L3) ? 1 : 0,
									  1) | DPD_FLOW_F_WAN;
						/* ABI 16: same NAT gate as the FIB
						 * egress above; the WAN table carries
						 * the ifindex, not the nexthop. */
						{
							struct dpd_iface_val *ep;
							__u32 eif = w.ifindex;

							ep = bpf_map_lookup_elem(&dpd_iface,
										 &eif);
							if (cfg->nat_offload && ep &&
							    ep->gw4)
								nv.flags |= DPD_FLOW_F_NAT;
						}
						if (w.flags & DPD_WAN_F_L3) {
							struct dpd_iface_val *ep;
							__u32 eif = w.ifindex;

							nv.flags |= DPD_FLOW_F_L3OUT;
							ep = bpf_map_lookup_elem(&dpd_iface,
										 &eif);
							if (ep && ep->gw4) {
								nv.nh4 = ep->gw4;
								nv.flags |= DPD_FLOW_F_NH4;
							}
						}
						if (tagged)
							nv.flags |= DPD_FLOW_F_TAG;
						__builtin_memcpy(nv.dmac, w.gw_mac, ETH_ALEN);
						__builtin_memcpy(nv.smac, w.dev_mac, ETH_ALEN);
						/* Only the low 28 bits are ours: they
						 * select the routing table (the ip rule
						 * matches with /0x0fffffff). The high
						 * nibble belongs to the proxy/datapath
						 * layer (honk: CLASSIFIED_MARK
						 * 0x4000_0000, DIRECT_UNSPEC_MARK
						 * 0x2000_0000). Overwriting the whole
						 * field made a packet that had already
						 * been classified look unclassified to
						 * whatever ran after us. */
						skb->mark = (skb->mark & 0xf0000000u) |
							    (w.mark & 0x0fffffffu);
					}
				}
			}

			/* ABI 17: does the reverse direction already exist? A
			 * UDP flow that has exchanged at least one packet gets
			 * the long timeout, a one-way flow the short one. This
			 * is one extra lookup at learn time, never on a hit. */
			if (fkey.proto == IPPROTO_UDP) {
				struct dpd_flow_key rk = fkey;
				__be16 p;
				int i;

				for (i = 0; i < 4; i++) {
					__be32 t = rk.saddr[i];

					rk.saddr[i] = rk.daddr[i];
					rk.daddr[i] = t;
				}
				p = rk.sport;
				rk.sport = rk.dport;
				rk.dport = p;
				rk.ifindex = nv.egress_ifindex;
				if (bpf_map_lookup_elem(&dpd_flows, &rk))
					nv.flags |= DPD_FLOW_F_REPLY;
			}

			/* ABI 18: fill the UFS v2 fields, then consult the policy
			 * cache exactly once (never on a hit). */
			nv.state = DPD_FLOW_STATE_OBSERVE;
			nv.action = DPD_ACT_FORWARD;
			nv.skb_priority = skb->priority;
			nv.packets = 0;
			nv.bytes = 0;
			/* ABI 22: a new flow starts with no hardware claim. dpdfwd
			 * overwrites this from conntrack once the kernel knows. */
			nv.ct_cookie = DPD_PPE_UNKNOWN;
			if (fkey.family == AF_INET) {
				struct iphdr *ih = data + l3_off;

				if ((void *)(ih + 1) <= data_end)
					nv.dscp = ih->tos >> 2;
			} else {
				struct ipv6hdr *i6 = data + l3_off;

				if ((void *)(i6 + 1) <= data_end)
					nv.dscp = i6->priority;
			}
			if (cfg->class_enable) {
				struct dpd_class_val *cv =
					dpd_class_find(&fkey);

				if (cv) {
					nv.action = cv->action;
					if (cv->skb_priority)
						nv.skb_priority =
							cv->skb_priority;
				}
			}

			/* An L2 entry with an all-zero destination MAC is dead on
			 * arrival: dpd_emit_l2() would write a zero dmac and the
			 * frame is dropped by the first switch. It happens when the
			 * neighbour was not resolved at learn time. Leave the flow
			 * on the stack (redirect_neigh resolves it there). */
			if ((nv.flags & DPD_FLOW_F_L2) &&
			    !(nv.dmac[0] | nv.dmac[1] | nv.dmac[2] |
			      nv.dmac[3] | nv.dmac[4] | nv.dmac[5]))
				return TC_ACT_UNSPEC;

			bpf_map_update_elem(&dpd_flows, &fkey, &nv, BPF_ANY);

			/*
			 * IPv6: seed the reverse entry from the frame we are holding.
			 *
			 * v4 does not need this: einat rewrites the reply's L2/L3 on
			 * its own TCX hooks, so the reverse flow is learned from the
			 * (already translated) WAN packet. v6 has no NAT, so the reply
			 * is an ordinary routed packet and its L2 header is exactly the
			 * one that belongs on the LAN: the pair we already see in this
			 * frame -- dmac = destination we sent to (the router's LAN
			 * MAC), smac = the client's LAN MAC -- swapped.
			 *
			 * Doing it here instead of letting the WAN ingress learn its
			 * own entry is what makes both directions cheap and, more
			 * importantly, correct: the reverse entry never depends on a
			 * WAN-side FIB/neighbour lookup that can be in flight (the
			 * earlier attempt learned `ingress=wan egress=wan` entries and
			 * black-holed the session).
			 *
			 * Guards: untagged frame (a VLAN tag would have to be pushed
			 * again), forward emit is the L2 class (we have both MACs),
			 * the ingress is Ethernet (a ppp/tun L3 skb has no MAC pair
			 * to swap -- reading one from the IP header produced a
			 * reverse entry with garbage MACs, which is what broke
			 * IPv6 the moment the WAN hook started accelerating), and
			 * the egress really differs from the ingress. The reverse
			 * entry starts with prime=0, so its first packet still
			 * walks the stack -- conntrack sees the reply before we
			 * take over.
			 */
			if (fkey.family == AF_INET6 && !tagged && !l3in &&
			    (nv.flags & DPD_FLOW_F_L2) &&
			    nv.egress_ifindex != ifindex) {
				struct dpd_flow_key rk = fkey;
				struct dpd_flow_val rv = {};
				struct ethhdr *eh = data;

				if ((void *)(eh + 1) <= data_end) {
					__be32 t;
					__u16 p;
					int i;

					for (i = 0; i < 4; i++) {
						t = rk.saddr[i];
						rk.saddr[i] = rk.daddr[i];
						rk.daddr[i] = t;
					}
					p = rk.sport;
					rk.sport = rk.dport;
					rk.dport = p;
					rk.ifindex = nv.egress_ifindex;

					rv.egress_ifindex = ifindex;
					rv.last_seen_ms = nv.last_seen_ms;
					rv.flags = DPD_FLOW_F_L2;
					rv.wan = nv.wan & DPD_FLOW_EPOCH_MASK;
					__builtin_memcpy(rv.dmac, eh->h_source, ETH_ALEN);
					__builtin_memcpy(rv.smac, eh->h_dest, ETH_ALEN);

					/* both must be real unicast MACs */
					if (dpd_mac_ok(rv.dmac) && dpd_mac_ok(rv.smac) &&
					    !(rv.dmac[0] & 1) && !(rv.smac[0] & 1))
						bpf_map_update_elem(&dpd_flows, &rk, &rv,
								    BPF_ANY);
				}
			}

			/* the map write may have invalidated the cached pointers;
			 * re-fetch before counting */
			cpu = dpd_cpu();
			st = cpu ? &cpu->stats : NULL;
			DPD_INC(st, ST_FLOW_WRITE);
			/* ABI 18: the first packet already obeys a cached
			 * policy, so a block takes effect immediately and a
			 * proxy/local flow is handed to the stack. */
			if (nv.action == DPD_ACT_BLOCK) {
				DPD_INC(st, ST_FLOW_BLOCK);
				return TC_ACT_SHOT;
			}
			if (nv.action == DPD_ACT_PROXY ||
			    nv.action == DPD_ACT_LOCAL) {
				DPD_INC(st, ST_FLOW_SKIP);
				return TC_ACT_UNSPEC;
			}
			return TC_ACT_UNSPEC;
		}
	}

non_ip:
	DPD_INC(st, ST_NON_IP);
	return TC_ACT_UNSPEC;
}

/* The attach script selects the section by device type. Both wrappers inline
 * the same body with a constant `force_l3`, so the verifier sees the fast path
 * without the per-packet dpd_iface lookup. */
SEC(DPD_SEC_L2)
int dpd_fastpath_l2(struct __sk_buff *skb)
{
	return dpd_fastpath_common(skb, 0);
}

SEC(DPD_SEC_L3)
int dpd_fastpath_l3(struct __sk_buff *skb)
{
	return dpd_fastpath_common(skb, 1);
}

/* ------------------------------------------------------------------- nat
 *
 * ABI 20: return-path DNAT stage (nat_ingress=dpd).
 *
 * Why it is a separate program at pref 50 instead of the block inside the main
 * program at pref 100: router-acl sits at pref 90 and, before the tuple is
 * restored, an inbound reply looks like "WAN -> the router itself". Measured
 * 2026-11-09 on the lab: ICMP echo replies were dropped at pref 90 and the
 * ping failed 0/3 with our DNAT at 100; the same program at 50 made the reply
 * DNAT *before* the ACL and the ping passed 3/3. einat avoids this by using
 * TCX, which runs before every classic filter.
 *
 * This program is DNAT-only and always returns TC_ACT_UNSPEC: it never
 * accelerates, never drops, and the main program still makes every forwarding
 * decision after the policy layer.
 */
/* ABI 20: ICMP error translation (type 3/11/12). The quirks:
 *
 *  - the error is addressed to the external address; the inner IPv4 header
 *    (after the 8-byte ICMP header) carries the SNATed tuple we sent;
 *  - look the inner (saddr, sport, proto) up in dpd_nat_rev, then restore the
 *    outer destination AND the inner source address/port, so the client can
 *    match the error to its socket (PMTUD, traceroute);
 *  - the outer ICMP checksum covers the inner header, so every inner change
 *    is applied to it as well; the inner IP checksum is updated in place;
 *  - the inner TCP checksum field is not among the 8 captured transport
 *    bytes (UDP's is, but Linux does not validate it when demuxing an ICMP
 *    error), so it is left alone.
 *
 * Always returns 0 (the caller yields); a packet that cannot be translated
 * is simply left alone. */
static __always_inline int
dpd_dnat_icmp_err(struct __sk_buff *skb, void *data, void *data_end,
		  __u32 l3_off, __u32 l4_off, struct dpd_stat_val *st)
{
	struct iphdr *oip = data + l3_off;
	struct icmphdr *oic = data + l4_off;
	__u32 inner = l4_off + sizeof(*oic);
	struct iphdr *iip = data + inner;
	struct dpd_nat_rev_key rk = {};
	struct dpd_nat_rev_val *rv;
	__u32 il4, sport_off = 0;
	__be32 old_saddr, new_saddr;
	__be16 old_sport, new_sport;
	__u8 proto;

	if ((void *)(oic + 1) > data_end)
		return 0;
	if ((void *)(iip + 1) > data_end)
		return 0;
	if (iip->version != 4 || iip->ihl < 5)
		return 0;
	if (iip->frag_off & bpf_htons(DPD_IP_MF | DPD_IP_OFFMASK))
		return 0;
	il4 = inner + (__u32)iip->ihl * 4;
	proto = iip->protocol;

	if (proto == IPPROTO_TCP) {
		struct tcphdr *th = data + il4;

		if ((void *)(th + 1) > data_end)
			return 0;
		old_sport = th->source;
		sport_off = il4 + __builtin_offsetof(struct tcphdr, source);
	} else if (proto == IPPROTO_UDP) {
		struct udphdr *uh = data + il4;

		if ((void *)(uh + 1) > data_end)
			return 0;
		old_sport = uh->source;
		sport_off = il4 + __builtin_offsetof(struct udphdr, source);
	} else if (proto == IPPROTO_ICMP) {
		struct icmphdr *iic = data + il4;

		if ((void *)(iic + 1) > data_end)
			return 0;
		if (iic->type != ICMP_ECHO)
			return 0;
		old_sport = iic->un.echo.id;
		sport_off = il4 +
			__builtin_offsetof(struct icmphdr, un.echo.id);
	} else {
		return 0;
	}

	old_saddr = iip->saddr;
	if (oip->daddr != old_saddr)
		return 0;

	rk.daddr = old_saddr;
	rk.dport = old_sport;
	rk.proto = proto;
	rv = bpf_map_lookup_elem(&dpd_nat_rev, &rk);
	if (!rv || !rv->saddr)
		return 0;
	new_saddr = rv->saddr;
	new_sport = rv->sport;

	/* outer destination: ext -> client */
	if (bpf_skb_store_bytes(skb,
			l3_off + __builtin_offsetof(struct iphdr, daddr),
			&new_saddr, sizeof(new_saddr), 0) < 0)
		return 0;
	if (bpf_l3_csum_replace(skb,
			l3_off + __builtin_offsetof(struct iphdr, check),
			(__u64)old_saddr, (__u64)new_saddr,
			sizeof(new_saddr)) < 0)
		return 0;

	/* inner source: ext -> client */
	if (bpf_skb_store_bytes(skb,
			inner + __builtin_offsetof(struct iphdr, saddr),
			&new_saddr, sizeof(new_saddr), 0) < 0)
		return 0;
	if (bpf_l3_csum_replace(skb,
			inner + __builtin_offsetof(struct iphdr, check),
			(__u64)old_saddr, (__u64)new_saddr,
			sizeof(new_saddr)) < 0)
		return 0;

	/* inner source port / echo id: ext port -> client port */
	if (old_sport != new_sport) {
		if (bpf_skb_store_bytes(skb, sport_off, &new_sport,
					sizeof(new_sport), 0) < 0)
			return 0;
	}

	/* the outer ICMP checksum covers the inner header */
	if (bpf_l4_csum_replace(skb,
			l4_off + __builtin_offsetof(struct icmphdr, checksum),
			(__u64)old_saddr, (__u64)new_saddr,
			sizeof(new_saddr)) < 0)
		return 0;
	if (old_sport != new_sport) {
		if (bpf_l4_csum_replace(skb,
				l4_off + __builtin_offsetof(struct icmphdr, checksum),
				(__u64)old_sport, (__u64)new_sport,
				sizeof(new_sport)) < 0)
			return 0;
	}

	DPD_INC(st, ST_NAT_DNAT);
	return 1;
}

SEC(DPD_SEC_NAT)
int dpd_fastpath_nat(struct __sk_buff *skb)
{
	struct dpd_cpu *cpu = dpd_cpu();
	struct dpd_config *cfg = cpu ? &cpu->cfg : NULL;
	struct dpd_stat_val *st = cpu ? &cpu->stats : NULL;
	struct dpd_iface_val *iv;
	struct dpd_nat_rev_key rk = {};
	struct dpd_nat_rev_val *rv;
	struct dpd_flow_key k = {};
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph;
	__u32 ifindex = skb->ifindex;
	__u32 l3_off, l4_off;
	__be32 ndaddr;
	__be16 ndport;

	if (!cfg || !cfg->nat_ingress)
		return TC_ACT_UNSPEC;

	iv = bpf_map_lookup_elem(&dpd_iface, &ifindex);
	if (iv && (iv->flags & (DPD_IF_F_NOARP | DPD_IF_F_POINTOPOINT))) {
		l3_off = 0;
	} else {
		struct ethhdr *eth = data;
		__be16 et;

		if ((void *)(eth + 1) > data_end)
			return TC_ACT_UNSPEC;
		l3_off = sizeof(*eth);
		et = eth->h_proto;
		if (et == bpf_htons(ETH_P_8021Q) ||
		    et == bpf_htons(ETH_P_8021AD)) {
			struct dpd_vlan_hdr *vh = data + l3_off;

			if ((void *)(vh + 1) > data_end)
				return TC_ACT_UNSPEC;
			et = vh->h_vlan_encapsulated_proto;
			l3_off += 4;
			if (et == bpf_htons(ETH_P_8021Q)) {
				struct dpd_vlan_hdr *v2 = data + l3_off;

				if ((void *)(v2 + 1) > data_end)
					return TC_ACT_UNSPEC;
				et = v2->h_vlan_encapsulated_proto;
				l3_off += 4;
			}
		}
		if (et != bpf_htons(ETH_P_IP))
			return TC_ACT_UNSPEC;
	}

	iph = data + l3_off;
	if ((void *)(iph + 1) > data_end)
		return TC_ACT_UNSPEC;
	if (iph->version != 4 || iph->ihl < 5)
		return TC_ACT_UNSPEC;
	if (iph->frag_off & bpf_htons(DPD_IP_MF | DPD_IP_OFFMASK))
		return TC_ACT_UNSPEC;
	k.proto = iph->protocol;
	if (k.proto != IPPROTO_TCP && k.proto != IPPROTO_UDP &&
	    k.proto != IPPROTO_ICMP)
		return TC_ACT_UNSPEC;
	l4_off = l3_off + (__u32)iph->ihl * 4;
	k.family = AF_INET;
	k.daddr[3] = iph->daddr;

	if (k.proto == IPPROTO_TCP) {
		struct tcphdr *th = data + l4_off;

		if ((void *)(th + 1) > data_end)
			return TC_ACT_UNSPEC;
		k.dport = th->dest;
	} else if (k.proto == IPPROTO_UDP) {
		struct udphdr *uh = data + l4_off;

		if ((void *)(uh + 1) > data_end)
			return TC_ACT_UNSPEC;
		k.dport = uh->dest;
	} else {
		struct icmphdr *ic = data + l4_off;

		if ((void *)(ic + 1) > data_end)
			return TC_ACT_UNSPEC;
		if (ic->type == ICMP_ECHOREPLY) {
			k.dport = ic->un.echo.id;
		} else if (ic->type == ICMP_DEST_UNREACH ||
			   ic->type == ICMP_TIME_EXCEEDED ||
			   ic->type == ICMP_PARAMETERPROB) {
			/* ABI 20: PMTUD / traceroute errors. The inner packet
			 * carries the SNATed tuple; translate it back. */
			dpd_dnat_icmp_err(skb, data, data_end, l3_off, l4_off,
					  st);
			return TC_ACT_UNSPEC;
		} else {
			return TC_ACT_UNSPEC;
		}
	}

	rk.daddr = k.daddr[3];
	rk.dport = k.dport;
	rk.proto = k.proto;
	rv = bpf_map_lookup_elem(&dpd_nat_rev, &rk);
	if (!rv || !rv->saddr)
		return TC_ACT_UNSPEC;

	ndaddr = rv->saddr;
	ndport = rv->sport;
	if (dpd_dnat_apply(skb, data, data_end, l3_off, l4_off, &k, ndaddr,
			   ndport) < 0)
		return TC_ACT_UNSPEC;
	DPD_INC(st, ST_NAT_DNAT);
	return TC_ACT_UNSPEC;
}

/* ------------------------------------------------------------------ egress
 *
 * ABI 20: DPD-owned forward SNAT. Attached to the *uplink's* egress hook only
 * (files/dpd-fastpath.sh), i.e. after routing and netfilter, which is exactly
 * where einat's TCX egress hook runs. Replacing einat here therefore does not
 * change which packets netfilter sees; the redirected fast path (which skips
 * netfilter) is the reason the rewrite has to happen at egress and not at
 * ingress -- rewriting at ingress double-NATs once einat is back (measured
 * 2026-11-09).
 *
 * A device opts in by having an addr4 taught (`dpdctl nat_addr`), so the same
 * object can sit on a LAN device without ever touching its packets.
 *
 * The binding is created on the first packet: the port is claimed by inserting
 * the reverse entry with BPF_NOEXIST, so two CPUs racing for the same port
 * cannot both win. A reverse entry older than the TCP TTL is recycled, which is
 * also how the port pool is bounded.
 */

/* How many ports to probe before giving up. 8 consecutive taken ports in a
 * 10000-port range is rare, and bounding it keeps the verifier happy. */
#define DPD_NAT_PROBES	8

SEC(DPD_SEC_EGRESS)
int dpd_fastpath_egress(struct __sk_buff *skb)
{
	struct dpd_cpu *cpu = dpd_cpu();
	struct dpd_config *cfg = cpu ? &cpu->cfg : NULL;
	struct dpd_stat_val *st = cpu ? &cpu->stats : NULL;
	struct dpd_iface_val *iv;
	struct dpd_nat_key nk = {};
	struct dpd_nat_val *nv;
	struct dpd_nat_rev_key rk = {};
	struct dpd_flow_key fk = {};
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph;
	__u32 ifindex = skb->ifindex;
	__be32 saddr, daddr, ext;
	__be16 sport, dport;
	__u32 l3_off, l4_off, now, port_min, port_max, span, h, stale;
	__u32 ext2;
	__u16 chosen = 0;
	__u8 proto;

	if (!cfg || !cfg->enable || !cfg->nat_forward)
		return TC_ACT_UNSPEC;

	iv = bpf_map_lookup_elem(&dpd_iface, &ifindex);
	if (!iv || !iv->addr4)
		return TC_ACT_UNSPEC;
	ext = iv->addr4;

	if (iv->flags & (DPD_IF_F_NOARP | DPD_IF_F_POINTOPOINT)) {
		l3_off = 0;	/* ppp/tun: data starts at the IP header */
	} else {
		struct ethhdr *eth = data;
		__be16 et;

		if ((void *)(eth + 1) > data_end)
			return TC_ACT_UNSPEC;
		l3_off = sizeof(*eth);
		et = eth->h_proto;
		if (et == bpf_htons(ETH_P_8021Q) ||
		    et == bpf_htons(ETH_P_8021AD)) {
			struct dpd_vlan_hdr *vh = data + l3_off;

			if ((void *)(vh + 1) > data_end)
				return TC_ACT_UNSPEC;
			et = vh->h_vlan_encapsulated_proto;
			l3_off += 4;
			if (et == bpf_htons(ETH_P_8021Q)) {
				struct dpd_vlan_hdr *v2 = data + l3_off;

				if ((void *)(v2 + 1) > data_end)
					return TC_ACT_UNSPEC;
				et = v2->h_vlan_encapsulated_proto;
				l3_off += 4;
			}
		}
		if (et != bpf_htons(ETH_P_IP))
			return TC_ACT_UNSPEC;
	}

	iph = data + l3_off;
	if ((void *)(iph + 1) > data_end)
		return TC_ACT_UNSPEC;
	if (iph->version != 4 || iph->ihl < 5)
		return TC_ACT_UNSPEC;
	proto = iph->protocol;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP &&
	    proto != IPPROTO_ICMP)
		return TC_ACT_UNSPEC;
	if (iph->frag_off & bpf_htons(DPD_IP_MF | DPD_IP_OFFMASK))
		return TC_ACT_UNSPEC;
	l4_off = l3_off + (__u32)iph->ihl * 4;
	saddr = iph->saddr;
	daddr = iph->daddr;
	if (proto == IPPROTO_TCP) {
		struct tcphdr *th = data + l4_off;

		if ((void *)(th + 1) > data_end)
			return TC_ACT_UNSPEC;
		sport = th->source;
		dport = th->dest;
	} else if (proto == IPPROTO_UDP) {
		struct udphdr *uh = data + l4_off;

		if ((void *)(uh + 1) > data_end)
			return TC_ACT_UNSPEC;
		sport = uh->source;
		dport = uh->dest;
	} else {
		/* ABI 20: ICMP echo. Only a request from the LAN is SNATed;
		 * the echo id plays the role of the source port. */
		struct icmphdr *ic = data + l4_off;

		if ((void *)(ic + 1) > data_end)
			return TC_ACT_UNSPEC;
		if (ic->type != ICMP_ECHO || ic->code != 0)
			return TC_ACT_UNSPEC;
		sport = ic->un.echo.id;
		dport = 0;
	}

	/* the router's own traffic already carries the external address */
	if (saddr == ext)
		return TC_ACT_UNSPEC;
	/* multicast / limited broadcast is never NATed */
	if (daddr == 0xffffffffu ||
	    (bpf_ntohl(daddr) & 0xf0000000u) == 0xe0000000u)
		return TC_ACT_UNSPEC;

	nk.saddr = saddr;
	nk.sport = sport;
	nk.proto = proto;
	now = (__u32)(bpf_ktime_get_ns() / 1000000ULL);

	nv = bpf_map_lookup_elem(&dpd_nat, &nk);
	if (nv && nv->to_addr && nv->to_port) {
		/* Keep the port owned while the flow is alive: refresh the
		 * ownership stamp at most once a minute, which is the only
		 * per-packet cost of the pool besides the lookup. */
		struct dpd_nat_rev_val *rv;

		rk.daddr = nv->to_addr;
		rk.dport = nv->to_port;
		rk.proto = proto;
		rv = bpf_map_lookup_elem(&dpd_nat_rev, &rk);
		if (rv && now - rv->ts_ms > 60000)
			rv->ts_ms = now;
		if (dpd_snat_apply(skb, data, data_end, l3_off, l4_off, proto,
				   saddr, sport, nv->to_addr,
				   nv->to_port) < 0) {
			DPD_INC(st, ST_NAT_GONE);
			return TC_ACT_UNSPEC;
		}
		DPD_INC(st, ST_NAT_SNAT);
		return TC_ACT_OK;
	}

	/* Miss: allocate. The candidate is a pure function of the internal
	 * 5-tuple, so retransmissions that race the allocation land on the
	 * same first candidate; the probe only moves on a real collision. */
	ext2 = dpd_nat_ext_addr(skb, ifindex, daddr, proto, sport, dport, ext);
	/* the router's own traffic leaves with the selected source already:
	 * never allocate a binding for it (it would rewrite the source port) */
	if (ext2 == saddr)
		return TC_ACT_UNSPEC;
	port_min = cfg->nat_port_min ? cfg->nat_port_min : 20000;
	port_max = cfg->nat_port_max ? cfg->nat_port_max : 29999;
	if (port_min < 1024 || port_max <= port_min || port_max > 65535)
		return TC_ACT_UNSPEC;
	span = port_max - port_min + 1;
	stale = cfg->tcp_ttl_ms ? cfg->tcp_ttl_ms : 300000;

	fk.family = AF_INET;
	fk.proto = proto;
	fk.saddr[3] = saddr;
	fk.daddr[3] = daddr;
	fk.sport = sport;
	fk.dport = dport;
	h = dpd_flow_hash(&fk, 0x85ebca6bu);

#define DPD_ALLOC_TRY(i) do {						\
	if (!chosen) {							\
		__u32 p = port_min +					\
			((h + (i) * 0x9e3779b9u) % span);		\
		struct dpd_nat_rev_key ck = {};				\
		struct dpd_nat_rev_val *old;				\
									\
		ck.daddr = ext2;					\
		ck.dport = bpf_htons((__u16)p);				\
		ck.proto = proto;					\
		old = bpf_map_lookup_elem(&dpd_nat_rev, &ck);		\
		if (!old || now - old->ts_ms > stale) {			\
			struct dpd_nat_rev_val nrv = {};		\
									\
			if (old)					\
				bpf_map_delete_elem(&dpd_nat_rev, &ck);	\
			nrv.saddr = saddr;				\
			nrv.sport = sport;				\
			nrv.ts_ms = now;				\
			if (bpf_map_update_elem(&dpd_nat_rev, &ck, &nrv,	\
						BPF_NOEXIST) == 0)	\
				chosen = (__u16)p;			\
		}							\
	}								\
} while (0)
	DPD_ALLOC_TRY(0); DPD_ALLOC_TRY(1); DPD_ALLOC_TRY(2); DPD_ALLOC_TRY(3);
	DPD_ALLOC_TRY(4); DPD_ALLOC_TRY(5); DPD_ALLOC_TRY(6); DPD_ALLOC_TRY(7);
#undef DPD_ALLOC_TRY

	if (!chosen) {
		DPD_INC(st, ST_NAT_EXHAUST);
		return TC_ACT_UNSPEC;
	}

	{
		struct dpd_nat_val nvn = {};

		nvn.to_addr = ext2;
		nvn.to_port = bpf_htons(chosen);
		if (bpf_map_update_elem(&dpd_nat, &nk, &nvn, BPF_ANY) < 0) {
			/* give the port back; the packet stays un-NATed */
			rk.daddr = ext2;
			rk.dport = bpf_htons(chosen);
			rk.proto = proto;
			bpf_map_delete_elem(&dpd_nat_rev, &rk);
			DPD_INC(st, ST_NAT_GONE);
			return TC_ACT_UNSPEC;
		}
		DPD_INC(st, ST_NAT_ALLOC);
		if (dpd_snat_apply(skb, data, data_end, l3_off, l4_off, proto,
				   saddr, sport, ext2, nvn.to_port) < 0)
			return TC_ACT_UNSPEC;
	}
	DPD_INC(st, ST_NAT_SNAT);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
