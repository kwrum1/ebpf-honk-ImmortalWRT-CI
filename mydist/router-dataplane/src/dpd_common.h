/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * dpd_common.h - shared ABI between the dpd_fastpath BPF program and dpdctl.
 *
 * mydist / router-dataplane
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
#define DPD_ABI_VERSION		4

/* name of the TC section in the BPF object; dpdctl/init pass this to tc(8) */
#define DPD_BPF_SECTION		"classifier"

/* TC priority. The interception layer owns TCX (no pref at all), so this pref
 * only orders us among *classic* filters: router-acl owns 90 on the WAN, we own
 * 100 everywhere. Nothing may collide. */
#define DPD_TC_PREF		100
#define DPD_TC_HANDLE		100

/* default object path inside the image */
#define DPD_BPF_OBJECT		"/lib/bpf/dpd_fastpath.bpf.o"
#define DPD_PIN_DIR		"/sys/fs/bpf"

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
	DPD_REDIR_AUTO		= 0,	/* _neigh unless iface flags say NOARP */
	DPD_REDIR_FORCE_NEIGH	= 1,
	DPD_REDIR_FORCE_DEV	= 2,	/* bpf_redirect(ifindex,0) - ppp / veth */
};

struct dpd_config {
	__u32	abi_version;
	__u32	mode;		/* enum dpd_mode			*/
	__u32	enable;		/* killer switch, 0 = always UNSPEC	*/
	__u32	redirect;	/* enum dpd_redirect			*/
	__u32	flow_ttl_ms;	/* Mode B entry freshness		*/
	__u32	policy;		/* enum dpd_policy			*/
	__u32	flags;		/* reserved				*/
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
	ST__MAX,
};

/* stored per entry in dpd_iface: flags userspace learned from the kernel */
#define DPD_IF_F_NOARP		0x0001	/* IFF_NOARP		*/
#define DPD_IF_F_POINTOPOINT	0x0002	/* IFF_POINTOPOINT	*/
#define DPD_IF_F_UP		0x0004	/* IFF_UP		*/

/* dpd_flow_val.flags: Mode B remembered that this egress has no neighbour
 * (a FIB lookup needed BPF_FIB_LOOKUP_SKIP_NEIGH), so the shortcut hit path must
 * use bpf_redirect() rather than bpf_redirect_neigh(). Stored in what used to be
 * padding, so the structure layout is unchanged. */
#define DPD_FLOW_F_NO_NEIGH	0x0001

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

struct dpd_flow_val {
	__u32	egress_ifindex;
	__u64	last_seen_ns;
	__u8	dmac[6];	/* for the force-dev (bpf_redirect) path */
	__u16	flags;		/* DPD_FLOW_F_* (was padding)		*/
};

#endif /* __DPD_COMMON_H */
