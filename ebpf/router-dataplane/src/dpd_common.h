/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * dpd_common.h - shared ABI between the dpd_fastpath BPF program and dpdctl.
 *
 * ebpf / router-dataplane
 *
 * REDLINES (see docs / 工作计划.md §3-§4). The BPF program:
 *   - does NOT do NAT            (NAT has exactly one owner: einat-ebpf)
 *   - does NOT read einat maps   (no coupling, no shared ABI to rot)
 *   - does NOT depend on conntrack (self-learning only)
 *   - is a TC *ingress* hook only
 *   - returns TC_ACT_UNSPEC on every path that must not take over a packet,
 *     so it always yields to the rest of the filter chain
 *   - has an `enable` killer switch in dpd_cfg
 *
 * Hook layout. Every line below was MEASURED (`bpftool net show` + `tc filter
 * show`) in QEMU x86_64 on 2026-10-17 with the real image, honk running against
 * a real VLESS/REALITY node, einat attached, router-acl at pref 90:
 *
 *   br-lan ingress : honk TCX lan_ingress_l2        -> dpd_fastpath (pref 100)
 *   br-lan egress  : honk TCX lan_egress_l2         <- we are NOT here
 *   eth0  ingress  : honk TCX lan_ingress_l2 (slave) -> dpd (pref 100)
 *   eth1  ingress  : honk TCX wan_ingress_l2
 *                    einat TCX ingress_rev_snat
 *                    router-acl (pref 90)           -> dpd_fastpath (pref 100)
 *   eth1  egress   : honk TCX wan_egress_l2
 *                    einat TCX egress_snat
 *                    router-acl (pref 90)
 *   dae0  ingress  : honk TCX dae0_ingress
 *
 * Two ordering facts make the cascade safe, and neither is a convention we
 * hope upstream keeps:
 *
 *  1. sch_handle_ingress()/sch_handle_egress() run tcx_run() BEFORE tc_run().
 *     Every TCX program (honk's, einat's) therefore sees a packet before every
 *     classic cls_bpf filter (router-acl's, ours). dpd is structurally BEHIND
 *     the interception layer: whatever honk declines falls through to us, and
 *     whatever honk proxies is redirected to dae0 and never reaches us. This is
 *     *why* the acceleration layer and the transparent proxy can coexist.
 *
 *  2. Among classic filters, ordering is by pref: router-acl 90 < dpd 100, so
 *     the policy layer decides before we do.
 *
 * dpd must stay a *classic* filter. Moving it to TCX would jump it in front of
 * honk and it would start stealing proxied flows. files/dpd-fastpath.sh checks
 * at attach time that nothing else sits after us and downgrades to observe if
 * something does.
 *
 * Acceleration is IPv4-only and gated on einat: taking a packet over skips
 * NETFILTER, not just the routing lookup, so the return path of an accelerated
 * flow needs einat's conntrack-free NAT plus the blanket WAN->LAN accept that
 * einat injects into fw4. IPv6 has no NAT in this baseline (no NAT66, by
 * design), so a v6 flow's untracked reply would be rejected by fw4 -- v6 is
 * therefore never accelerated (see dpd_policy / dpd_may_accelerate()).
 */

#ifndef __DPD_COMMON_H
#define __DPD_COMMON_H

#include <linux/types.h>

/* 3: added ST_FRAG_SKIP and ST_DNS_SKIP (see dpd_may_accelerate())
 * 4: added ST_FIB_RETRY -- bpf_fib_lookup() without a neighbour succeeded on a
 *    second pass with BPF_FIB_LOOKUP_SKIP_NEIGH. This is the PPPoE case: a ppp
 *    device has no neighbour table, so the first lookup answers
 *    BPF_FIB_LKUP_RET_NO_NEIGH and, before this, EVERY packet on a PPPoE WAN
 *    failed the lookup (measured 2026-10-18: fib_ok 0 / fib_fail 29) and
 *    nothing was ever accelerated. */
/* 5: added ST_DHCP_SKIP and ST_BCAST_SKIP -- DHCP and every non-unicast
 *    destination must reach the local stack. A DISCOVER (0.0.0.0 ->
 *    255.255.255.255, UDP 68->67) matched the default route and was
 *    redirect_neigh()'d out the WAN, so odhcpd never saw it and LAN clients
 *    got no lease (measured 2026-10-27: fib_ok +2, neigh_ok +2, no lease;
 *    with dpd stopped the same client leased 192.168.10.204 immediately).
 * 6: dpd_flow_val now carries the L2 header (smac next to dmac) and a 32-bit
 *    millisecond timestamp, so the redirect can be a plain bpf_redirect()
 *    instead of bpf_redirect_neigh() -- the latter re-runs the route lookup and
 *    the neighbour lookup for every packet. The value stays 24 bytes, so an
 *    object upgrade can reuse the pinned map (see dpd_flow_val).
 * 7: stateful mode *primes* each direction before it starts redirecting: the
 *    first DPD_FLOW_PRIME+1 packets of a learned flow still traverse netfilter.
 *    Without it a TCP flow's handshake never completes as far as conntrack is
 *    concerned, because the client's final ACK is already taken over: the entry
 *    sticks in SYN_RECV (measured 2026-10-27: packets=1 bytes=60 for a 12.4 GB
 *    download) and dies on the 120 s syn_recv timer while the flow is still
 *    running. Priming costs two packets per flow, makes the entry reach
 *    ESTABLISHED, and keeps nf_conntrack_count / `ct state` rules / the
 *    transition back to the slow path meaningful. No value-layout change: the
 *    counter lives in the spare high byte of dpd_flow_val.flags.
 *
 * 9: the 2026-10-28 review pass (correctness + per-packet cost):
 *      - dpd_stats is ONE per-CPU block (struct dpd_stat_val) instead of
 *        ST__MAX array keys: the packet path used to do 5 map lookups, now 1.
 *      - dpd_cfg gains `epoch` and `flow_refresh_ms`. The epoch is a flow-cache
 *        generation; the control plane bumps it on any topology change (link
 *        up/down, address/route/neighbour change, WAN re-pick). A cached entry
 *        from another epoch is ignored and re-learned. That is what lets the
 *        hit path drop its per-packet dpd_iface / dpd_wans re-validation.
 *      - dpd_flow_val records the *emit class* (L2 / dev / neigh) at learn
 *        time, so a hit no longer looks up dpd_iface or re-decides.
 *      - timestamps refresh at most once per flow_refresh_ms (0 = every
 *        packet). Entries then live up to flow_refresh_ms *longer* than
 *        flow_ttl_ms -- the error is always "cached too long", never "live
 *        flow dropped".
 *      - IPv4 GSO length comes from the real per-segment headers
 *        (iph->ihl*4 + L4 header + gso_size), not from gso_size alone.
 *      - IPv6, :53, DHCP and non-unicast packets are rejected *before* the
 *        FIB lookup: they can never be accelerated, so they no longer pay for
 *        a route lookup.
 *
 * 10: optional IPv6 acceleration (`option ipv6`, default 0).
 *      IPv6 has no NAT here, so an accelerated flow's return path must be
 *      carried by conntrack, not by einat: the stateful priming (ABI 7) makes
 *      conntrack see the handshake first, after which fw4's
 *      `ct state established,related accept` covers the primed packets and the
 *      rest is redirected on the WAN ingress hook.
 *      Only TCP/UDP without extension headers, non-fragment, unicast, non-53,
 *      non-DHCPv6(546/547) v6 packets are eligible, and only in the LAN->WAN
 *      direction: v6 replies stay on the stack (conntrack is authoritative for
 *      the return half, there is no NAT66 to reconstruct it). `ST_V6_OK` counts
 *      the packets that took the fast path; ST_V6_SKIP keeps counting refusals.
 *
 * 11: TCP MSS clamp on the accelerated path, plus the machine-readable status
 *      that goes with it.
 *      - Taking a flow over skips fw4's `mtu_fix` (the nft `tcp option maxseg
 *        size set rt mtu` rule), so on a PPPoE WAN (1492) the end points keep
 *        their 1460 MSS and the first full segment is dropped by the uplink.
 *        PMTUD would normally recover it, but an ICMP-filtered path then looks
 *        exactly like "web pages open, downloads hang". The fast path now
 *        rewrites the MSS option of SYN/SYN-ACK to the path MTU (the smaller of
 *        the ingress and egress device MTUs) - 40 (v4) / - 60 (v6) before
 *        redirecting, the same arithmetic fw4 uses. Both directions matter: the
 *        MSS in a SYN-ACK is what the *client* may send into the 1492 uplink,
 *        so an egress-only rule would fix downloads and leave uploads black-
 *        holed. Only packets this program actually takes over are touched; the
 *        slow path keeps getting fw4's clamp. `option mss_clamp '0'` disables it.
 *      - dpd_config gains `mss_clamp`; new map `dpd_mtu` (ifindex -> MTU, fed
 *        by `dpdctl ifaces` from /sys/class/net/<dev>/mtu) so the BPF side can
 *        learn the egress MTU without a per-packet syscall.
 *      - new counters ST_MSS_CLAMP / ST_MSS_SKIP; `dpdctl status [-j]` and
 *        /var/run/ebpf/gate.json make the gate decision readable by scripts,
 *        LuCI and humans (see dpd-fastpath.sh:dpd_gate_publish()).
 *
 * 12: one per-CPU block for config + counters (struct dpd_cpu).
 *      The hit path used to look up dpd_cfg and dpd_stats separately, i.e. two
 *      map lookups for what is one hot cache line each. They are now the same
 *      per-CPU value, so the packet path does a single lookup and the cfg
 *      fields sit in the same cache line as the counters it bumps. Userspace
 *      keeps the invariant: a write reads every CPU's block, changes only the
 *      cfg part and writes them back, so counters survive a `dpdctl set`.
 *      No change to the config layout or the counter order; the ABI bump is
 *      about the map *value* size (pinned maps must be dropped on upgrade).
 *
 * 13: 802.1Q-aware take-over. Tagged frames used to be refused (l2_ok = !tagged)
 *      and fell back to bpf_redirect_neigh(), which keeps the tag in the skb:
 *      on an untagged WAN that ships a tagged frame to the ISP, and on a VLAN
 *      egress it can double-tag. The fast path now:
 *        - pops the tag before emitting on a plain Ethernet egress
 *          (bpf_skb_vlan_pop, then the normal L2 emit), and
 *        - refuses the take-over when the egress is stacked (VLAN sub-interface,
 *          veth, tunnel), leaving tag ownership to the stack.
 *      The flow entry remembers that the flow is tagged (DPD_FLOW_F_TAG) so the
 *      hit path pops on every packet, and l3_off/l4_off are adjusted by the
 *      4 bytes the pop removes.
 *      New counters ST_TAG_POP / ST_TAG_SKIP.
 *
 * 14: ST_BYTES_HIT - bytes of the packets the fast path actually took over.
 *      The homepage shows an acceleration share (bytes_hit / bytes), and a
 *      packet ratio would misrepresent bulk flows (a few large segments per
 *      flow vs many small ones). Incremented on the stateless emit and on the
 *      stateful hit, never on primed/slow packets. The counters are split by
 *      address family (ST_*_V4 / ST_*_V6) and the L2 shortcut has its own pair,
 *      so the status card can show "v4 / v6" for each number.
 *
 * 16: ST_NAT_GONE + dpd_nat gate. The forward half of a NATed flow is taken
 *      over only when einat has an origin binding for it (mirrored into
 *      dpd_nat by dpd-einat-sync); the rewrite itself stays in einat's TCX
 *      egress, because rewriting at ingress and then letting einat's egress
 *      hook run double-NATs the packet (measured 2026-11-09). The forward
 *      entry is re-checked on every hit: a binding that is gone drops the
 *      packet back to the stack instead of sending it un-NATed.
 *
 * 17: Flow Manager knobs in dpd_config + FIN/RST release:
 *      - accel_after_pkts (0..127, default 32) replaces the fixed 1-packet
 *        prime, so short flows stay on the stack (ECM/SFE behaviour);
 *      - per-protocol TTLs (tcp 300 s, UDP 120 s, unidirectional UDP 30 s)
 *        instead of the single 5 s flow_ttl_ms. UDP "has a reply" is learned
 *        once, at learn time, by looking up the reverse key and setting
 *        DPD_FLOW_F_REPLY (bit 15; the prime counter narrowed to 7 bits);
 *      - a TCP FIN/RST that hits an accelerated flow deletes the entry and
 *        returns the packet to the stack (ST_FLOW_FIN), instead of holding a
 *        dead flow until the TTL. The reverse entry is left to its TTL.
 *
 * 18: UFS v2 + policy cache:
 *      - dpd_flow_val grows the design's missing fields: state, action,
 *        skb_priority, ct_cookie, nat_flags, dscp, packets, bytes;
 *      - the explicit state machine OBSERVE -> BIND (priming count) is
 *        recorded instead of being implicit in the counter;
 *      - dpd_class is a userspace-written 5-tuple policy cache
 *        (FORWARD/PROXY/BLOCK/LOCAL + skb_priority); the learn path copies
 *        it into the UFS entry and the hit path obeys it. This is the
 *        "plugins are control-plane, one lookup in the hot path" contract.
 *
 * 19: optional DPD-owned return-path DNAT (`nat_ingress=dpd`). A new
 *      dpd-nat-rev map is mirrored from einat's reverse bindings; when
 *      einat's ingress TCX is detached, the WAN ingress packet is DNATed by
 *      DPD before the UFS lookup. With einat's ingress attached (default) it
 *      already DNATed the packet, the reverse key does not match and DPD
 *      does nothing, so the mode is safe by default.
 *
 * 20: DPD-owned forward SNAT + port allocation (`nat_forward=dpd`). A TC
 *      *egress* program (`classifier/egress`) on every uplink owns the
 *      forward rewrite: it looks up `dpd_nat` for the internal tuple and,
 *      on a miss, allocates a port from [nat_port_min, nat_port_max] by
 *      probing `dpd_nat_rev` (which now carries a monotonic timestamp),
 *      writes both directions and rewrites saddr/sport with incremental
 *      checksums. The ingress program skips the einat binding gate in
 *      this mode; the return half is the ABI 19 `dpd_nat_rev` DNAT. The
 *      external address is the uplink's `dpd_iface_val.addr4`, taught by
 *      `dpdctl nat_addr`. einat must not be attached on the uplink
 *      (double NAT) and fw4 needs a WAN->LAN accept for the untracked
 *      return path; the default (`nat_forward=einat`) is unchanged.
 *      ICMP echo shares the allocator (the 16-bit echo id is the port)
 *      but is never accelerated. The return DNAT lives in its own
 *      `classifier/nat` stage at pref 50, ahead of router-acl (90): at the
 *      main program's 100 an untranslated reply looks like WAN->router and
 *      the policy layer drops it (measured: ICMP 0/3 vs 3/3).
 *      - cfg.flow_counters gains value 2 (sampled, 1/16 of hits). The field
 *      stays a __u32 at the same offset, so no layout or ABI change.
 */
#define DPD_ABI_VERSION		20

/* TC section names in the BPF object; files/dpd-fastpath.sh passes the right
 * one to tc(8) based on the ingress device type. L2 is the classic Ethernet
 * parser; L3 starts at the IP header (ppp/tun). */
#define DPD_BPF_SECTION		"classifier/l2"
#define DPD_SEC_L2		"classifier/l2"
#define DPD_SEC_L3		"classifier/l3"
/* ABI 20: egress SNAT program, attached to the uplinks only. */
#define DPD_SEC_EGRESS		"classifier/egress"
/* ABI 20: return-path DNAT stage, attached to the uplinks at a pref *below*
 * the policy layer (router-acl owns 90). DNAT-only, always UNSPEC. */
#define DPD_SEC_NAT		"classifier/nat"

/* TC priority. The interception layer owns TCX (no pref at all), so this pref
 * only orders us among *classic* filters: router-acl owns 90 on the WAN, we own
 * 100 everywhere. Nothing may collide. */
#define DPD_TC_PREF		100
#define DPD_TC_HANDLE		100
/* The DNAT stage must run before router-acl (90), so it lives at 50. It is
 * not an accelerator: it only restores the internal tuple and yields. */
#define DPD_TC_PREF_NAT		50

/* default object path inside the image */
#define DPD_BPF_OBJECT		"/lib/bpf/dpd_fastpath.bpf.o"
#define DPD_PIN_DIR		"/sys/fs/bpf"

/* Where the gate decision is published (dpd-fastpath.sh:dpd_gate_publish()).
 * Rewritten by every gate evaluation, so scripts/CI/LuCI never have to parse
 * logread to answer "why is this not accelerating?". Shape:
 *
 *   { "requested": "stateful", "effective": "observe",
 *     "code": "no-einat", "reason": "einat is not attached ...",
 *     "at": "2026-11-02T09:03:11Z", "uptime_s": 412,
 *     "checks": { "uci_enabled": 1, "uplink": true, "einat": false,
 *                 "einat_on_uplink": false, "honk": false, "honk_p1": true } }
 *
 * `code` is a stable token, `reason` the human sentence; both come from
 * dpd_gate_mode() in files/dpd-fastpath.sh. dpdctl status embeds the object
 * verbatim (`"gate": {...}`) when it parses, and LuCI renders the same file,
 * so there is exactly one producer. */
#define DPD_GATE_FILE		"/var/run/ebpf/gate.json"

/* Same decision in a form a shell can read without a JSON parser: four lines,
 * in this order, no escaping (the reason is one ASCII line by construction).
 *   requested
 *   effective
 *   code
 *   reason
 * Written by dpd_gate_publish() together with the JSON. */
#define DPD_GATE_TEXT		"/var/run/ebpf/gate"

/* Per-CPU counters of the whole program are published here by the watchdog so
 * a status page can show numbers without exec rights (dpdctl status -j writes
 * the same shape). Refreshed every watchdog tick and by dpd-gate-refresh. */
#define DPD_STATUS_FILE		"/var/run/ebpf/status.json"

/* dpd_vlans: optional segment allow-list, u16 VLAN id -> u8 1 */
#define DPD_VLAN_MAP_MAX	64

enum dpd_mode {
	DPD_MODE_OFF		= 0,	/* passthrough, still counted	*/
	DPD_MODE_OBSERVE	= 1,	/* fib lookup + counters, never touch   */
	DPD_MODE_STATELESS	= 2,	/* every packet: fib -> redirect_neigh  */
	DPD_MODE_STATEFUL	= 3,	/* learn on miss, redirect on hit       */
	DPD_MODE_NEIGH_PROBE	= 9,	/* #14: answer "does bpf_redirect_neigh
					 *      actually work here?" at runtime */
};

/* Which packets may be taken over (dpd_cfg.policy). */
enum dpd_policy {
	DPD_POLICY_ALLOW_ALL	= 0,	/* every IPv4 forwarding packet	*/
	DPD_POLICY_VLANS_ONLY	= 1,	/* only VLAN ids in dpd_vlans; an
					 * untagged packet is never eligible  */
};

/* how to place the packet on the wire once the FIB says "forward me" */
enum dpd_redirect {
	DPD_REDIR_AUTO		= 0,	/* bpf_redirect() with the header the
					 * FIB lookup already gave us, when the
					 * egress is a plain Ethernet device;
					 * bpf_redirect_neigh() otherwise (ppp,
					 * tunnels, VLAN/lower devices)	*/
	DPD_REDIR_FORCE_NEIGH	= 1,	/* always bpf_redirect_neigh(), i.e. a
					 * route + neighbour lookup per packet.
					 * The pre-ABI-6 behaviour; keep it as
					 * the escape hatch			*/
	DPD_REDIR_FORCE_DEV	= 2,	/* bpf_redirect(ifindex, 0) - ppp / veth */
};

struct dpd_config {
	__u32	abi_version;
	__u32	mode;		/* enum dpd_mode			*/
	__u32	enable;		/* killer switch, 0 = always UNSPEC	*/
	__u32	redirect;	/* enum dpd_redirect			*/
	__u32	flow_ttl_ms;	/* Mode B entry freshness		*/
	__u32	policy;		/* enum dpd_policy			*/
	/* Flow-cache generation. Userspace bumps it whenever a cached egress
	 * may have become wrong (link up/down, address or route change, WAN
	 * re-pick, neighbour flush). Entries store the epoch they were learned
	 * in; a hit from another epoch is treated as a miss. 8 bits are kept in
	 * dpd_flow_val.wan, so the comparison is one byte. */
	__u32	epoch;
	/* Refresh dpd_flow_val.last_seen_ms at most once per this many ms.
	 * 0 = every packet (exact idle-timeout semantics). A non-zero value
	 * keeps an idle entry alive for up to this much longer than
	 * flow_ttl_ms, which is the safe direction. */
	__u32	flow_refresh_ms;
	/* 1 = accelerate IPv6 as well (TCP/UDP, no extension headers, unicast,
	 * not :53, not DHCPv6). 0 = IPv4 only, which is the shipped default:
	 * the v6 path is newer and needs `ct state established` to carry the
	 * return direction (there is no NAT66 to do it). */
	__u32	ipv6;
	/* 1 = clamp the TCP MSS option of the SYN/SYN-ACK packets the fast path
	 * takes over to the egress MTU (mtu-40 for v4, mtu-60 for v6), i.e. what
	 * fw4's mtu_fix would have done. The slow path is untouched: it already
	 * goes through netfilter's clamp. 0 = no rewrite (diagnostics only; on a
	 * PPPoE WAN that brings back the PMTUD black hole). */
	__u32	mss_clamp;
	/* ABI 16: 1 = einat owns NAT on the uplinks, so the forward half may be
	 * taken over once einat has a binding (the TCX egress hook does the
	 * SNAT). 0 = no einat: never take the uplink half over, because the
	 * redirected packet would skip fw4's masquerade. */
	__u32	nat_offload;
	/* ABI 17: the Flow Manager knobs that used to be compile-time constants
	 * or absent. accel_after_pkts is how many packets of a newly learned
	 * direction still walk the stack (0..127; 0 = take over immediately).
	 * The TTLs are per protocol; 0 falls back to flow_ttl_ms. A UDP flow
	 * that has no reply learned yet uses udp_unidir_ttl_ms (pf's short
	 * one-way timeout); once the reverse entry exists it uses udp_ttl_ms. */
	__u32	accel_after_pkts;
	__u32	tcp_ttl_ms;
	__u32	udp_ttl_ms;
	__u32	udp_unidir_ttl_ms;
	/* ABI 18/20: per-flow packets/bytes accounting on the UFS hit path.
	 *   0 = off (datapath-wide counters only),
	 *   1 = exact: update both counters on every hit (two 64-bit RMWs on
	 *       an entry that is already hot),
	 *   2 = sampled: update only when (packets & 0xf) == 0, i.e. one hit
	 *       in 16. Cheaper on the hit path; the recorded rate is 1/16 of
	 *       the real one, so read it as a rate, not a packet count.
	 * The value fits in the ABI 18 __u32, so the layout is unchanged.
	 * class_enable: 1 = consult dpd_class when a flow is learned. */
	__u32	flow_counters;
	__u32	class_enable;
	/* ABI 19: 1 = DPD performs the return-path DNAT itself from
	 * dpd_nat_rev (requires einat's ingress TCX to be detached; with it
	 * attached this is a no-op because the packet is already DNATed). */
	__u32	nat_ingress;
	/* ABI 20: 1 = the egress SNAT program owns the forward rewrite and
	 * allocates ports itself (einat must be detached from the uplink).
	 * 0 = einat's TCX egress owns SNAT, as before. */
	__u32	nat_forward;
	/* ABI 20: external port range for nat_forward=dpd, host byte order,
	 * inclusive. 0 means "use the default" (20000..29999). */
	__u32	nat_port_min;
	__u32	nat_port_max;
};

enum dpd_stat_idx {
	ST_PKT_TOTAL = 0,	/* every packet entering the program	*/
	ST_BYTES,		/* bytes entering the program		*/
	ST_NON_IP,		/* not IPv4/IPv6 (arp, pppoe ctrl, ...)	*/
	ST_FIB_OK,		/* bpf_fib_lookup -> RET_SUCCESS	*/
	ST_FIB_FAIL,		/* any other fib return code		*/
	ST_REDIRECT_OK,		/* bpf_redirect() accepted the packet	*/
	ST_NEIGH_OK,		/* bpf_redirect_neigh() accepted it	*/
	ST_NEIGH_FAIL,		/* bpf_redirect_neigh() -> SHOT		*/
	ST_FLOW_HIT,		/* Mode B flow map hit			*/
	ST_FLOW_MISS,		/* Mode B flow map miss			*/
	ST_FLOW_WRITE,		/* Mode B entry written			*/
	ST_TTL_DROP,		/* ttl/hop_limit <= 1			*/
	ST_LOCAL,		/* dest is local / not forwarded	*/
	ST_V6_SKIP,		/* eligible-looking IPv6: never accelerated
				 * (no NAT66 -> the reply would have no
				 * conntrack state and fw4 would reject it) */
	ST_VLAN_SKIP,		/* policy=vlans_only and this packet is not in
				 * dpd_vlans (incl. untagged)		*/
	ST_FRAG_SKIP,		/* IPv4 fragment: the L4 header only exists in
				 * the first one, so there is no honest flow key
				 * and nothing to gate the DNS check on. The
				 * whole stream goes to the stack, which is also
				 * what einat needs to build its binding.	*/
	ST_DNS_SKIP,		/* LAN->WAN port 53: netfilter (dns_redirect=1)
				 * would have DNATed it to the router itself. */
	ST_FIB_RETRY,		/* first bpf_fib_lookup said NO_NEIGH (ppp/tunnel:
				 * no neighbour table); a second pass with
				 * BPF_FIB_LOOKUP_SKIP_NEIGH found the route and
				 * the dev emit path delivered (measured on a
				 * PPPoE WAN: redirect_ok +9, peer's access log
				 * recorded the request).			*/
	ST_DHCP_SKIP,		/* UDP 67/68: the DHCP server is local, a
				 * DISCOVER to 255.255.255.255 must never be
				 * redirected. See dpd_is_dhcp().		*/
	ST_BCAST_SKIP,		/* non-unicast destination (limited broadcast,
				 * 224/4, ff00::/8): has to be delivered
				 * locally / flooded, not routed.		*/
	ST_V6_OK,		/* IPv6 packet the fast path took over	*/
	ST_MSS_CLAMP,		/* SYN/SYN-ACK whose MSS option was rewritten
				 * to the egress MTU on the fast path (ABI 11) */
	ST_MSS_SKIP,		/* SYN/SYN-ACK the fast path wanted to clamp but
				 * could not: no dpd_mtu entry for the egress, or
				 * the resulting MSS would be below the RFC 879
				 * floor. Counted so "clamp is on but nothing
				 * happens" is visible instead of silent. */
	ST_TAG_POP,		/* 802.1Q tag removed before an L2 emit	*/
	ST_TAG_SKIP,		/* tagged packet the fast path refused to take
				 * over (egress is stacked, or the pop failed) */
	/* ABI 14: IPv4/IPv6 split for the homepage line. The totals are per
	 * family so a share is a share of that family's traffic, not of the
	 * mixed stream (a v6-heavy or v4-heavy box would look wrong). */
	ST_BYTES_V4,		/* IPv4 bytes entering the program	*/
	ST_BYTES_V6,		/* IPv6 bytes entering the program	*/
	ST_BYTES_HIT_V4,	/* IPv4 bytes taken over		*/
	ST_BYTES_HIT_V6,	/* IPv6 bytes taken over		*/
	ST_L2_V4,		/* IPv4 packets emitted by the L2 shortcut */
	ST_L2_V6,		/* IPv6 packets emitted by the L2 shortcut */
	ST_NAT_GONE,		/* P2.1: forward flow whose einat binding
	 *			 * disappeared; fall back to the stack so
	 *			 * einat can re-create/route it. */
	ST_FLOW_FIN,		/* ABI 17: TCP FIN/RST released an
	 *			 * accelerated flow (entry deleted). */
	ST_FLOW_BIND,		/* ABI 18: OBSERVE -> BIND transition	*/
	ST_FLOW_BLOCK,		/* ABI 18: cached BLOCK action, packet
	 *			 * dropped by the fast path		*/
	ST_FLOW_SKIP,		/* ABI 18: cached PROXY/LOCAL action,
	 *			 * packet handed back to the stack	*/
	ST_NAT_DNAT,		/* ABI 19: return-path DNAT applied by DPD
	 *			 * (einat ingress detached)		*/
	ST_NAT_SNAT,		/* ABI 20: forward SNAT rewritten on the
	 *			 * egress hook (hit or fresh allocation)	*/
	ST_NAT_ALLOC,		/* ABI 20: a new external port binding was
	 *			 * allocated by the egress program		*/
	ST_NAT_EXHAUST,		/* ABI 20: every probe in the port range was
	 *			 * taken; packet left un-NATed		*/
	ST__MAX,
};

/* stored per entry in dpd_iface: flags userspace learned from the kernel */
#define DPD_IF_F_NOARP		0x0001	/* IFF_NOARP		*/
#define DPD_IF_F_POINTOPOINT	0x0002	/* IFF_POINTOPOINT	*/
#define DPD_IF_F_UP		0x0004	/* IFF_UP		*/
/* The device is stacked on a lower one (/sys/class/net/X/iflink != X's own
 * index): a VLAN sub-interface, a veth peer, a macvlan, a tunnel. Such a device
 * builds its L2 header in dev_hard_header() -- a VLAN device pushes the 802.1Q
 * tag there -- so writing the header ourselves and calling bpf_redirect() would
 * emit a frame that is wrong (untagged where a tag was owed, or tagged twice).
 * The cheap Ethernet emit path (dpd_emit_l2()) is therefore skipped for them and
 * they keep using bpf_redirect_neigh(). Taught by `dpdctl ifaces`. */
#define DPD_IF_F_LOWER		0x0008

/* Per-ifindex value of dpd_iface (ABI 15). flags are the IFF_* capabilities
 * taught by `dpdctl ifaces`; gw4 is the IPv4 next hop taught by `dpdctl gw`
 * (network byte order, 0 = none).
 *
 * Why the nexthop is kept here: bpf_redirect_neigh() with params==NULL re-runs
 * ip_route_output_flow() per packet with flowi4_iif left at 0. On a box whose
 * LAN source only resolves with iif set (policy rules, as on the PPPoE home
 * router this was found on) that lookup returns -ENETUNREACH and the packet is
 * silently freed after the helper said "redirect". Passing the nexthop skips
 * the route lookup entirely (ip_neigh_gw4 -> neigh_direct_output), which is
 * both correct and cheaper. */
struct dpd_iface_val {
	__u32	flags;
	__u32	gw4;
	/* ABI 20: the interface's primary IPv4 address (network order, 0 =
	 * none), taught by `dpdctl nat_addr`. The egress SNAT program uses it
	 * as the external address and refuses to touch a device whose addr4 is
	 * unset, so teaching it is also the NAT-uplink selector. */
	__be32	addr4;
	__u32	_pad;
};

/* dpd_flow_val.flags: the emit class (see dpd_emit_class()). L2 = write the
 * header and bpf_redirect(); DEV = bpf_redirect(ifindex, 0) for a device with no
 * neighbour table (ppp/tunnel/NOARP); neither = bpf_redirect_neigh(). Stored in
 * what used to be padding, so the structure layout is unchanged. */
#define DPD_FLOW_F_NO_NEIGH	0x0001

/* How to emit this flow, decided once at learn time (ABI 9). The hit path used
 * to look up dpd_iface and re-run the whole AUTO decision for every packet;
 * now it reads two bits.
 *   L2   - plain Ethernet egress with usable dmac/smac: write the header and
 *          bpf_redirect()
 *   DEV  - bpf_redirect(ifindex, 0), header untouched (ppp/tunnel/stacked dev)
 *   none - bpf_redirect_neigh() (the escape hatch and the unknown case)      */
#define DPD_FLOW_F_L2		0x0002
#define DPD_FLOW_F_DEV		0x0004
/* egress came from the multi-WAN table (informational for dpdctl) */
#define DPD_FLOW_F_WAN		0x0008
/* The flow arrives 802.1Q/802.1AD-tagged: every packet has to have its tag
 * popped before the L2 emit (ABI 13). Learned only for flows whose egress is a
 * plain Ethernet device; a stacked egress is never learned. */
#define DPD_FLOW_F_TAG		0x0010
#define DPD_FLOW_F_NH4		0x0020	/* emit with this nh4 (ABI 15)	*/
#define DPD_FLOW_F_L3OUT	0x0040	/* egress is ppp/tun (ABI 15)	*/
/* ABI 16: the egress is a NAT uplink (learned IPv4 nexthop), so the hit path
 * must re-check dpd_nat on every packet. Only such flows are gated: the return
 * half needs no binding and must never pay for the lookup. */
#define DPD_FLOW_F_NAT		0x0080
/* ABI 17: the reverse direction was already in the table when this entry was
 * learned (the flow has exchanged at least one packet). Used only to pick the
 * longer UDP timeout. Bit 15 is free because the prime counter was narrowed to
 * 7 bits (accel_after_pkts <= 127). */
#define DPD_FLOW_F_REPLY	0x8000

/* dpd_flow_val.flags bits 8..14: how many packets of this direction have been
 * let through netfilter since the entry was learned (saturating). A hit is only
 * redirected once the counter reaches cfg.accel_after_pkts, so the first
 * accel_after_pkts+1 packets of each direction walk the stack -- which is what
 * lets conntrack see a whole TCP handshake (SYN, SYN-ACK, ACK) instead of
 * stopping at SYN_RECV, and keeps short flows off the fast path entirely.
 * 7 bits because bit 15 is DPD_FLOW_F_REPLY since ABI 17. */
#define DPD_FLOW_PRIME_SHIFT	8
#define DPD_FLOW_PRIME_MASK	0x7f00
#define DPD_FLOW_PRIME		32	/* default; cfg.accel_after_pkts
					 * overrides it at runtime	*/

/*
 * Mode B flow key. Kept at a fixed 48 bytes to keep the LRU hash cheap.
 * IPv4 addresses are stored right-aligned into the 16-byte v6 slots.
 */
struct dpd_flow_key {
	__u32	ifindex;	/* ingress device			*/
	__u8	family;		/* AF_INET / AF_INET6			*/
	__u8	proto;		/* IPPROTO_TCP / UDP / ...		*/
	__u16	_pad;
	__be32	saddr[4];
	__be32	daddr[4];
	__be16	sport;
	__be16	dport;
};

/*
 * Mode B flow value -- 28 bytes since ABI 15 (24 before nh4), and that size is
 * part of the pinned-map ABI: a bpf_map_update_elem() value that changed size
 * makes libbpf refuse to reuse /sys/fs/bpf/dpd_flows, i.e. `tc filter add`
 * fails after an in-place upgrade until the pin is removed. dpd_pins_compat()
 * in files/dpd-fastpath.sh drops the pins when /usr/lib/dpd/abi changed.
 *
 * dmac/smac are the pair bpf_fib_lookup() filled in for this flow. Caching them
 * is what lets the hit path emit with bpf_redirect() instead of
 * bpf_redirect_neigh(); see dpd_emit_l2() in the BPF program.
 *
 * last_seen_ms is CLOCK_MONOTONIC in milliseconds (the same clock as
 * bpf_ktime_get_ns()), truncated to 32 bits: it wraps every ~49.7 days, so the
 * freshness test is done on the *signed difference* (age >= 0 && age < ttl),
 * never on an absolute comparison. That buys us 4 bytes for smac without growing
 * the entry.
 *
 * flags carries DPD_FLOW_F_NO_NEIGH in bit 0 and the per-direction prime
 * counter in bits 8..15 (DPD_FLOW_PRIME_*). The counter is the reason a
 * redirect does not start on the first hit; see the ABI 7 note above. */
/* ABI 18: explicit flow lifecycle, mirroring the design's NEW->OBSERVE->
 * BIND->FIN. It is recorded for observability and for the policy cache; the
 * actual takeover decision is still the prime counter + action. */
enum dpd_flow_state {
	DPD_FLOW_STATE_NEW = 0,
	DPD_FLOW_STATE_OBSERVE,
	DPD_FLOW_STATE_BIND,
	DPD_FLOW_STATE_FIN,
};

/* ABI 18: what the fast path is allowed to do with this flow. FORWARD is the
 * normal accelerate path; PROXY/LOCAL hand the packet back to the stack (honk
 * TCX or a local socket); BLOCK drops it explicitly. */
enum dpd_flow_action {
	DPD_ACT_FORWARD = 0,
	DPD_ACT_PROXY,
	DPD_ACT_BLOCK,
	DPD_ACT_LOCAL,
};

struct dpd_flow_val {
	__u32	egress_ifindex;
	__u32	last_seen_ms;	/* bpf_ktime_get_ns()/1e6, wraps	*/
	__u8	dmac[6];	/* next hop MAC from the FIB lookup	*/
	__u8	smac[6];	/* egress dev_addr from the FIB lookup	*/
	__u16	flags;		/* DPD_FLOW_F_* | prime counter		*/
	__u16	wan;		/* low byte: 1-based dpd_wans index, 0 =
				 * none; high byte: the cfg epoch this entry
				 * was learned in (ABI 9)			*/
	__u32	nh4;		/* ABI 15: IPv4 next hop for an L3 emit	*/
	/* ABI 18: UFS v2 */
	__u32	state;		/* enum dpd_flow_state			*/
	__u32	action;		/* enum dpd_flow_action			*/
	__u32	skb_priority;	/* cached skb->priority (QoS)		*/
	__u32	ct_cookie;	/* 0 unless the optional bpf_ct path	*/
	__u32	nat_flags;	/* DPD_NAT_* (sniffed, for observability) */
	__u16	dscp;		/* cached DSCP (iph->tos >> 2)		*/
	__u16	_pad2;
	__u64	packets;	/* per-flow counters (cfg->flow_counters) */
	__u64	bytes;
};

/* ABI 18: userspace-written policy cache, keyed by the same 5-tuple as
 * dpd_flows (including ingress ifindex). The learn path copies action and
 * skb_priority into the UFS entry once; the hit path never looks it up. */
struct dpd_class_val {
	__u32	action;		/* enum dpd_flow_action			*/
	__u32	skb_priority;	/* 0 = leave the skb field alone	*/
	__u32	flags;		/* reserved				*/
	__u32	_pad;
};

#define DPD_CLASS_MAX		16384

/* NAT binding tables (ABI 15/19/20). Kept here instead of only in the BPF
 * source so dpdctl can dump them; dpd-einat-sync keeps its own packed mirror
 * because it reads the map by id from a different object.
 *
 * dpd_nat:      pre-SNAT internal 3-tuple -> external address/port.
 * dpd_nat_rev:  external 3-tuple -> internal address/port, and (ABI 20) the
 *               egress port allocator's ownership table.
 *
 * ts_ms is CLOCK_MONOTONIC in milliseconds, truncated to 32 bits; 0 means
 * "foreign" (mirrored from einat) and the allocator treats it as stale. The
 * external port is stored in network byte order on both sides. */
struct dpd_nat_key {
	__be32	saddr;
	__be16	sport;
	__u8	proto;
	__u8	_pad;
};

struct dpd_nat_val {
	__be32	to_addr;
	__be16	to_port;
	__u16	_pad;
};

struct dpd_nat_rev_key {
	__be32	daddr;
	__be16	dport;
	__u8	proto;
	__u8	_pad;
};

struct dpd_nat_rev_val {
	__be32	saddr;
	__be16	sport;
	__u16	_pad;
	__u32	ts_ms;		/* ABI 20: port ownership stamp	*/
};

/* The epoch occupies the high byte of dpd_flow_val.wan; the index itself can
 * never exceed DPD_WAN_MAX (8). */
#define DPD_FLOW_EPOCH_MASK	0xff00

/* Statistics are one per-CPU block, not one array key per counter: the fast
 * path can then bump several counters after a single map lookup. Read with
 * `dpdctl stats` (sums every CPU). Keep ST_* in sync with dpd_stat_val.v[]. */
struct dpd_stat_val {
	__u64	v[ST__MAX];
};

/* One per-CPU value holding both the configuration and the counters (ABI 12).
 * The program looks it up once per packet: cfg sits at offset 0 and the
 * counters follow in the same cache line group, so the hot path pays one map
 * lookup instead of two. Userspace must treat this as read-modify-write: a
 * config change rewrites only .cfg of every CPU's block (see dpdctl cfg_write),
 * otherwise a `dpdctl set` would zero the counters. */
struct dpd_cpu {
	struct dpd_config cfg;
	struct dpd_stat_val stats;
};

/* ------------------------------------------------------------------ multi-WAN
 *
 * One entry per uplink. The userspace daemon owns the table: it fills in the
 * device index, the fwmark that routes the *first* packet of a flow into that
 * uplink's table, the weight, the health flag and the two MAC addresses the
 * egress needs (gateway and device).
 *
 * The fast path never does a second FIB lookup: it hashes the 5-tuple, picks a
 * WAN with weighted rendezvous hashing, hands the first packet to the stack
 * with skb->mark set, and caches the egress + MACs for the rest of the flow.
 * Empty table (max_entries all zero) = the pre-multi-WAN behaviour.
 */
#define DPD_WAN_MAX	8
#define DPD_WAN_F_UP	0x1
#define DPD_WAN_F_L3	0x2	/* no L2 header: ppp/tun, use bpf_redirect */

struct dpd_wan {
	__u32	ifindex;
	__u32	mark;		/* fwmark for the slow path of new flows */
	__u32	weight;		/* 0 disables the entry			*/
	__u32	flags;		/* DPD_WAN_F_*				*/
	__u8	gw_mac[6];	/* next hop on this uplink		*/
	__u8	dev_mac[6];	/* the uplink device's own address	*/
};

/* One map entry holds the whole table: a single lookup per packet beats eight,
 * and constant indices keep the verifier happy (no loop it cannot bound). */
struct dpd_wan_tbl {
	__u32	count;
	__u32	_pad;
	struct dpd_wan wan[DPD_WAN_MAX];
};

#endif /* __DPD_COMMON_H */
