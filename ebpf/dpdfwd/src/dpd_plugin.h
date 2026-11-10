/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * dpd_plugin.h - the dpdfwd plugin ABI (v1).
 *
 * A plugin is a shared object that exports exactly one symbol:
 *
 *     struct dpd_plugin_ops dpd_plugin_ops;
 *
 * dpdfwd scans /usr/lib/dpd/plugins for .so files at start, dlopen()s each,
 * checks .version against DPD_PLUGIN_ABI and calls .init(). A plugin that
 * fails to load or init is skipped; the datapath never depends on it.
 *
 * Plugins are control-plane only. They see conntrack and topology events,
 * can classify a new flow (which dpdfwd turns into a dpd_class entry), and
 * can keep their own state. They must never touch the packet path directly;
 * the hot path stays "one UFS lookup, one rewrite, one redirect".
 */
#ifndef DPD_PLUGIN_H
#define DPD_PLUGIN_H

#include <stdint.h>
#include <stddef.h>

#define DPD_PLUGIN_ABI		1
#define DPD_PLUGIN_SYMBOL	"dpd_plugin_ops"

enum dpd_plugin_action {
	DPD_PLUGIN_FORWARD = 0,
	DPD_PLUGIN_PROXY = 1,
	DPD_PLUGIN_BLOCK = 2,
	DPD_PLUGIN_LOCAL = 3,
};

/*
 * Software/hardware coexistence state (ABI 22).
 *
 * These values are the *wire format* of `dpdctl flows ppe <state>` and the
 * contents of dpd_flow_val.ct_cookie, so they must stay in sync with
 * enum dpd_ppe_state in bpf/core/src/dpd_common.h. They are repeated here
 * because dpdfwd deliberately does not include the kernel-side header: the
 * daemon only speaks to the datapath through dpdctl and the maps, and pulling
 * in linux/bpf.h to share five constants would couple the control plane to a
 * specific kernel UAPI. Tests/abi-check keeps the two lists identical.
 */
enum dpd_ppe_state {
	DPD_PPE_UNKNOWN = 0,
	DPD_PPE_SW_ACTIVE = 1,
	DPD_PPE_YIELDED = 2,
	DPD_PPE_OFFLOADED = 3,
	DPD_PPE_FAILED = 4,
	DPD_PPE_DENIED = 5,
};

enum dpd_plugin_event {
	DPD_EV_LINK = 1,
	DPD_EV_ADDR,
	DPD_EV_ROUTE,
	DPD_EV_NEIGH,
	DPD_EV_CT_NEW,
	DPD_EV_CT_UPDATE,
	DPD_EV_CT_DESTROY,
};

/* One flow, as conntrack reported it. Addresses are network order in the
 * 16-byte slots (an IPv4 address occupies the first 4 bytes); ports are host
 * order. ifindex is 0 because conntrack does not carry it. */
struct dpd_flow_desc {
	uint8_t		family;		/* AF_INET / AF_INET6		*/
	uint8_t		proto;
	uint16_t	_pad;
	uint32_t	ifindex;	/* 0 = any			*/
	uint8_t		saddr[16];
	uint8_t		daddr[16];
	uint16_t	sport;
	uint16_t	dport;
	/* Output of flow_classify, consumed by dpdfwd. */
	uint32_t	action;		/* enum dpd_plugin_action	*/
	uint32_t	skb_priority;
	/* Informational, filled on expire when known. */
	uint64_t	packets;
	uint64_t	bytes;
};

struct dpd_plugin_ops {
	const char	*name;
	int		version;	/* DPD_PLUGIN_ABI */
	int		(*init)(void);
	/* Called once per new flow before it is cached. May set action and
	 * skb_priority; dpdfwd writes them into dpd_class via dpdctl. */
	int		(*flow_classify)(struct dpd_flow_desc *d);
	int		(*flow_create)(const struct dpd_flow_desc *d);
	void		(*flow_expire)(const struct dpd_flow_desc *d);
	void		(*topology_event)(int event, const char *ifname);
	/* Optional human-readable state for `dpdctl`/logs. */
	int		(*dump)(char *buf, size_t len);
};

#endif /* DPD_PLUGIN_H */
