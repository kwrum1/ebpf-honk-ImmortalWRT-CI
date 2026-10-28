/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * acl_common.h - shared ABI between the router-acl BPF program and aclctl.
 *
 * ebpf / router-acl
 *
 * What this program is
 * --------------------
 * A *filtering* program for the WAN device only. It is the piece that lets the
 * distribution stop leaning on nf_conntrack for the question "does this inbound
 * packet belong to something we started?".
 *
 * REDLINES, same spirit as dpd_common.h:
 *   - does NOT do NAT            (NAT has exactly one owner: einat-ebpf)
 *   - does NOT read einat maps   (no shared ABI to rot; it learns by itself)
 *   - never redirects, never rewrites payload; it only accepts or drops
 *   - returns TC_ACT_UNSPEC on every path that must not take over a packet
 *   - has a killer switch: acl_cfg.mode == ACL_MODE_OFF
 *
 * Hook layout. TCX links run before the classic chain (sch_handle_ingress() runs
 * tcx_run() before tc_run()), so on the WAN:
 *
 *   ingress : einat (TCX) -> router-acl (pref 90) -> dpd_fastpath (pref 100)
 *   egress  : einat (TCX) -> router-acl (pref 90)
 *
 * pref 90 puts the ACL in front of the fastpath: a packet we drop must never
 * reach it. einat owns the TCX links and pref 1/100 belong to einat/dpd; 90 is
 * ours alone.
 *
 * Why the IPv4 table is keyed by the remote endpoint
 * ------------------------------------------------
 * einat does BOTH halves of the translation in eBPF: SNAT on egress (TCX) and
 * the reverse on ingress (TCX). Both of its links run before this program,
 * because the kernel calls tcx_run() before tc_run() in both
 * sch_handle_ingress() and sch_handle_egress() (read out of 6.18 sources, see
 * 工作计划.md). So the two hooks do not see the same packet:
 *
 *   egress   the packet AFTER SNAT:     src = wan_ip : wan_port
 *   ingress  the packet AFTER un-SNAT:  dst = lan_host : lan_port
 *
 * The port is therefore a *different number* on the two sides, and a table
 * keyed by port can never match: every reply would be dropped and every flow
 * would die. This was measured the hard way -- ICMP worked (einat does not
 * rewrite the echo id) while TCP and UDP died, which is exactly the signature
 * of a port-keyed table that happens to be right for ICMP by accident.
 *
 * The only field that survives both translations is the *remote endpoint*: what
 * we sent to is precisely what the reply comes from. So the key is
 * (proto, remote ip, remote port):
 *
 *   egress   learn  (proto, iph->daddr, dport)
 *   ingress  match  (proto, iph->saddr, sport)
 *
 * That is exact for every flow the box starts, forwarded or local, and it is
 * also safe: a third party cannot get a packet accepted without spoofing the
 * exact remote endpoint we are already talking to, and then it is blind.
 *
 * The cost is that a *third-party initiated* inbound packet -- a real full cone
 * peer that learned the mapping from somewhere else -- does not match. The
 * `fullcone` option restores it by additionally accepting inbound TCP/UDP whose
 * destination is inside a LAN prefix. That is the same posture einat's own
 * procd data takes (it emits a blanket WAN->LAN accept), and it is off by
 * default because with it on, anything able to forge a LAN destination can
 * inject into the LAN. Doing better requires seeing the packet before einat's
 * un-SNAT, i.e. an XDP hook; XDP is out of scope for this baseline.
 *
 * IPv6 has no NAT here (no NAT66), so nothing is rewritten and the exact
 * reverse 5-tuple works: learned on egress, matched on ingress.
 *
 * Modes
 * -----
 *   OFF     no-op: acl_cfg.mode == 0 makes both programs return UNSPEC.
 *   GUARD   drop unsolicited inbound. Purely additive: fw4 and conntrack keep
 *           working exactly as before, because the flows stay tracked. All it
 *           removes is junk -- a port scan no longer creates conntrack entries
 *           and no longer walks the nft ruleset.
 *   BYPASS  GUARD plus marking, which is what actually takes nf_conntrack out
 *           of the data path for NATed flows:
 *             - init writes chain-post/raw_prerouting  `... notrack`
 *             - init writes chain-pre/forward          `... accept`
 *           so conntrack never sees the flow and fw4 never asks it anything.
 *           Requires einat to be enabled: fw4's own `masquerade` is a conntrack
 *           operation and cannot work on a notracked packet.
 *
 * The `forwarded` flag
 * --------------------
 * At the egress hook skb->sk is NULL for forwarded traffic and non-NULL for
 * traffic a local socket generated. Only forwarded flows are marked on the
 * return path, so the router's own connections keep full fw4 input filtering
 * instead of silently bypassing it.
 */

#ifndef ACL_COMMON_H
#define ACL_COMMON_H

#include <linux/types.h>

#define ACL_ABI_VERSION		2

/* name of the TC section in acl.bpf.c; aclctl/init pass this to tc(8) */
#define ACL_BPF_SECTION		"classifier"

/* TC priorities. einat owns the TCX links, dpd owns 100. */
#define ACL_TC_PREF		90
#define ACL_TC_HANDLE		90

/* How many IPv4 LAN prefixes the fullcone option can cover. */
#define ACL_MAX_LAN_V4		4

/* default object paths inside the image */
#define ACL_BPF_INGRESS_OBJECT	"/lib/bpf/acl_ingress.bpf.o"
#define ACL_BPF_EGRESS_OBJECT	"/lib/bpf/acl_egress.bpf.o"
#define ACL_PIN_DIR		"/sys/fs/bpf"

/*
 * The bit this program uses in skb->mark, and the mask fw4's generated rules
 * match it with. fw4 does not use marks unless told to and honk steers with
 * marks of its own, so take a high bit and always match it masked.
 */
#define ACL_MARK_BIT		0x01000000u
#define ACL_MARK_MASK		0xff000000u

enum acl_mode {
	ACL_MODE_OFF	= 0,
	ACL_MODE_GUARD	= 1,
	ACL_MODE_BYPASS	= 2,
};

enum acl_scope {
	ACL_SCOPE_FORWARD = 1,	/* inbound towards a LAN host (port forward) */
	ACL_SCOPE_INPUT	  = 2,	/* inbound towards the router itself	    */
};

/* address family values as used in the port table; frozen ABI values */
#define ACL_AF_INET	2
#define ACL_AF_INET6	10

enum acl_stat {
	AS_INGRESS_PKT = 0,	/* every IPv4 packet entering the program  */
	AS_INGRESS_MAPPED,	/* allowed: learned full-cone mapping	    */
	AS_INGRESS_FORWARD,	/* allowed: explicit port forward	    */
	AS_INGRESS_INPUT,	/* allowed: router's own service	    */
	AS_INGRESS_ICMP_ERR,	/* allowed: ICMP error for a known flow    */
	AS_INGRESS_ECHO,	/* allowed: echo request, opt-in	    */
	AS_INGRESS_FULLCONE,	/* allowed: fullcone, inbound to a LAN	    */
	AS_INGRESS_DROP,	/* dropped				    */
	AS_INGRESS_NONIP,	/* not IPv4/IPv6 (arp, pppoe ctrl, ...)    */
	AS_EGRESS_PKT,
	AS_EGRESS_LEARN,	/* mapping written			    */
	AS_EGRESS_NONIP,
	AS_V6_INGRESS_PKT,
	AS_V6_INGRESS_STATE,	/* allowed: learned v6 flow		    */
	AS_V6_INGRESS_ICMP6,	/* allowed: essential/related ICMPv6	    */
	AS_V6_INGRESS_FORWARD,	/* allowed: explicit v6 allow list	    */
	AS_V6_INGRESS_DROP,
	AS_V6_EGRESS_PKT,
	AS_V6_EGRESS_LEARN,
	AS_MARKED,		/* packets we set ACL_MARK_BIT on	    */
	AS_MAX
};

struct acl_lan_v4 {
	__be32	net;
	__be32	mask;
};

struct acl_config {
	__u32	abi_version;
	__u32	mode;			/* enum acl_mode		    */
	__u32	allow_v4_echo;		/* ICMP echo request from the WAN   */
	__u32	allow_v6_echo;
	__u32	udp_timeout_ms;
	__u32	tcp_timeout_ms;
	__u32	icmp_timeout_ms;
	__u32	mark;			/* value written in BYPASS	    */
	__u32	fullcone;		/* also accept inbound to a LAN	    */
	__u32	lan_count;		/* entries used in lan_v4	    */
	struct acl_lan_v4 lan_v4[ACL_MAX_LAN_V4];
};

/* IPv4: state for flows the box started. Keyed by the *remote endpoint*, which
 * is the only field that survives einat's SNAT on the way out and its un-SNAT
 * on the way back (see the long comment at the top). Field order is chosen so
 * the struct has no padding and can be zero-initialised wholesale. */
struct acl_v4_key {
	__be32	ip;			/* remote address		    */
	__be16	port;			/* remote port			    */
	__u16	proto;
};

struct acl_v4_val {
	__u64	last_seen_ns;
	__u32	packets;
	__u32	forwarded;	/* 1 = LAN-initiated, safe to notrack */
};

/* The explicit allow list: port forwards (FORWARD) and the router's own
 * services (INPUT). port == 0 means "any port of this protocol". */
struct acl_port_key {
	__u16	family;		/* ACL_AF_INET / ACL_AF_INET6	    */
	__u16	proto;
	__u16	scope;		/* enum acl_scope		    */
	__be16	port;
};

struct acl_port_val {
	__u64	last_seen_ns;
	__u32	packets;
	__u32	pad;
};

/* IPv6: real per-flow state, stored in the LAN->WAN direction. */
struct acl_v6_key {
	__u8	src[16];
	__u8	dst[16];
	__u16	sport;
	__u16	dport;
	__u8	proto;
	__u8	pad[3];
};

struct acl_v6_val {
	__u64	last_seen_ns;
	__u32	packets;
	__u32	forwarded;
};

#endif /* ACL_COMMON_H */
