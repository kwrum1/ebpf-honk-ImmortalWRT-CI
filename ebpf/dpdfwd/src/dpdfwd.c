// dpdfwd: DPD Flow Manager (MVP).
//
// Scope of this first version:
//   - subscribe to link / IPv4 address / IPv4 route / neighbour events and
//     turn a burst of them into ONE flow-cache epoch bump (`dpdctl bump`),
//     which is the targeted-invalidation primitive the datapath already has;
//   - subscribe to conntrack new/update/destroy and publish per-type counters;
//   - on conntrack destroy, batch the tuples (orig + reply) and call
//     `dpdctl delete -f` once per second, so a UFS entry whose conntrack
//     state is gone is invalidated without waiting for the TTL;
//   - apply a declarative class policy file to dpd_class via dpdctl;
//   - publish /var/run/dpd/flowd.json for the UI and for tests.
//
// The direct flow lifecycle (learn/hit/expire, accel_after_pkts, FIN/RST) lives
// in the BPF program; this daemon is the control-plane half and never touches
// the packet path.
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>

#include "dpd_plugin.h"

#define RTNL_GROUPS (RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | \
		     RTMGRP_NEIGH)

#define NFNL_SUBSYS_CTNETLINK 1
#define IPCTNL_MSG_CT_NEW 0
#define IPCTNL_MSG_CT_DELETE 2
#define CTNLGRP_NEW 1
#define CTNLGRP_UPDATE 2
#define CTNLGRP_DESTROY 3
#define CT_GROUPS ((1 << (CTNLGRP_NEW - 1)) | (1 << (CTNLGRP_UPDATE - 1)) | \
		   (1 << (CTNLGRP_DESTROY - 1)))

#define OUT_DIR "/var/run/dpd"
#define OUT_FILE OUT_DIR "/flowd.json"
/* The dashboard reads this one; writing it here means the snapshot exists
 * wherever dpdfwd runs, not only when the init script is present. */
#define UI_DIR "/var/run/ebpf"
#define UI_FILE UI_DIR "/status.json"
#define DPD_CTL_STATUS_S 2
#define DPD_CTL "/usr/sbin/dpdctl"
#define CT_DELETE_FILE "/tmp/dpd-ct-delete"
#define CT_PPE_FILE "/tmp/dpd-ct-ppe"
#define CT_PPE_MAX 128
/* Sweep interval for /proc/net/nf_conntrack, see ppe_sweep(). */
#define PPE_SWEEP_S 1
#define DEBOUNCE_MS 300
/* Neighbour churn: how long a *suspicious* one may wait before the epoch is
 * bumped, and the hard ceiling on how stale a cached MAC may get.
 *
 * Measured on the N5000 (2026-11-10, 8036 s uptime): 6503 neighbour events,
 * i.e. ~0.8/s, and 258 epoch bumps = one every 31 s -- the old 30 s rate
 * limit was permanently saturated, so the whole flow cache was invalidated
 * twice a minute and every live flow paid the 8-packet priming again. The
 * idle box still logged ~37 flow_miss/s, almost all of it re-learning.
 *
 * A neighbour event by itself is NOT a reason to distrust a cached egress:
 * NUD_REACHABLE refreshes, REACHABLE->STALE transitions and the periodic
 * garbage collection all arrive through the same RTM_NEWNEIGH/DELNEIGH path.
 * Only two things actually invalidate an L2-cached flow:
 *   - the neighbour became unusable (NUD_FAILED / NUD_INCOMPLETE, or the
 *     entry was deleted), or
 *   - the same address now resolves to a different lladdr.
 * Both are tracked per address below; anything else is ignored.
 * NEIGH_SWEEP_MS is the backstop for the case we cannot see (a switch or AP
 * silently changing what a MAC reaches): a cached dmac is trusted for this
 * long, then one bump re-learns everything. 5 min of a black hole in that
 * one scenario is far cheaper than re-learning the table every 31 s.
 *
 * NEIGH_BUMP_MS is therefore no longer a rate limit on "how often may we
 * invalidate": it is only the burst coalescer for events that already passed
 * neigh_event(). It is short (5 s) precisely because a real lladdr change must
 * propagate fast; the old 30 s value was what turned 0.8 events/s into a
 * permanent "invalidate everything" mode. */
#define NEIGH_BUMP_MS 5000
#define NEIGH_SWEEP_MS 300000L
#define NEIGH_TRACK_MAX 512
#define PUBLISH_MS 2000
/* The datapath deletes an entry only when a packet looks it up again, so an
 * idle flow that never returns stays in the map until LRU evicts it. Sweep the
 * ones older than every TTL (TCP max 600 s) once a minute. */
#define PRUNE_S 60
#define PRUNE_AGE_MS 900000
#define PRUNE_AGE_STR "900000"

#define CLASS_FILE_DEFAULT "/etc/dpd/class.conf"
/* libbpf's tc loader pins into /sys/fs/bpf/tc/globals; older releases used
 * /sys/fs/bpf directly, so both are checked. */
#define CLASS_PIN "/sys/fs/bpf/tc/globals/dpd_class"
#define CLASS_PIN_LEGACY "/sys/fs/bpf/dpd_class"
#define CLASS_MAX_RULES 4096
#define CLASS_CHECK_S 5
#define CLASS_FAIL_MAX 20
#define CLASS_LINE_MAX 1024

/* ctnetlink attribute numbers (linux/netfilter/nfnetlink_conntrack.h). */
#define CTA_TUPLE_ORIG 1
#define CTA_TUPLE_REPLY 2
#define CTA_STATUS 3
#define CTA_TUPLE_IP 1
#define CTA_TUPLE_PROTO 2
#define CTA_IP_V4_SRC 1
#define CTA_IP_V4_DST 2
#define CTA_IP_V6_SRC 3
#define CTA_IP_V6_DST 4
#define CTA_PROTO_NUM 1
#define CTA_PROTO_SRC_PORT 2
#define CTA_PROTO_DST_PORT 3

/* CTA_STATUS bits (linux/netfilter/nf_conntrack_common.h). */
#define IPS_OFFLOAD (1U << 14)
#define IPS_HW_OFFLOAD (1U << 15)

struct nfgenmsg {
	uint8_t nfgen_family;
	uint8_t version;
	uint16_t res_id;
};

struct ct_tuple {
	uint8_t family;
	uint8_t proto;
	uint16_t sport;		/* host order */
	uint16_t dport;
	uint8_t saddr[16];
	uint8_t daddr[16];
};

#define CT_PENDING_MAX 128

struct stats {
	unsigned long link;
	unsigned long link_port;	/* bridge-port link events, no bump */
	unsigned long addr;
	unsigned long route;
	unsigned long neigh;
	unsigned long neigh_ignored;	/* refreshes: no epoch bump */
	unsigned long neigh_forced;	/* the NEIGH_SWEEP_MS backstop */
	unsigned long ct_new;
	unsigned long ct_update;
	unsigned long ct_destroy;
	unsigned long ct_offload;
	unsigned long ct_hw_offload;
	unsigned long bumps;
	unsigned long unknown;
	unsigned long errors;
	unsigned long class_rules;
	unsigned long class_bad;
	unsigned long class_error;
	time_t class_applied_at;
	time_t started;
	time_t last_event;
};

/* ABI 22: conntrack-offload state, batched like the delete list so the daemon
 * forks dpdctl at most once a second instead of once per ctnetlink event. */
struct ppe_pend {
	struct ct_tuple t;
	uint32_t state;
};
static struct ppe_pend ppe_pending[CT_PPE_MAX];
static int ppe_pending_n;
static int ppe_enabled = 1;	/* set from uci at startup */
static unsigned long ppe_writes;
static unsigned long ppe_swept;

static struct ct_tuple ct_pending[CT_PENDING_MAX];
static int ct_pending_n;
static unsigned long ct_delete_batches;

/* defined below; the neighbour tracker needs them first */
static struct nlattr *nla_find(struct nlattr *head, int len, int type);
static void *nla_payload(struct nlattr *nla);

/*
 * Neighbour tracker: which addresses are currently believed to have a usable
 * lladdr, and what it is. Fixed-size and open-addressed; it is a heuristic
 * cache in front of the epoch bump, so a hash collision only means "that
 * address is not tracked", never a wrong decision about another one (the
 * address is compared in full after the probe).
 */
#define NEIGH_KEY_LEN 16

struct neigh_ent {
	uint8_t addr[NEIGH_KEY_LEN];
	uint8_t lladdr[6];
	uint8_t family;
	uint8_t used;
};

static struct neigh_ent neigh_tab[NEIGH_TRACK_MAX];
static long long neigh_sweep_at;

static unsigned int neigh_slot(const uint8_t *addr, uint8_t family)
{
	unsigned int h = 2166136261u ^ family;
	int i;

	for (i = 0; i < (family == AF_INET ? 4 : 16); i++)
		h = (h ^ addr[i]) * 16777619u;
	return h % NEIGH_TRACK_MAX;
}

static struct neigh_ent *neigh_find(const uint8_t *addr, uint8_t family)
{
	unsigned int s = neigh_slot(addr, family), i;

	for (i = 0; i < 8; i++) {
		struct neigh_ent *e = &neigh_tab[(s + i) % NEIGH_TRACK_MAX];

		if (!e->used)
			return NULL;
		if (e->family == family &&
		    !memcmp(e->addr, addr, family == AF_INET ? 4 : 16))
			return e;
	}
	return NULL;
}

/* Returns 1 when the address is new or its lladdr changed, i.e. a cached
 * egress that used it is now suspect. Returns 0 for a refresh of the same
 * mapping, which is the common case and must not cost an epoch. */
static int neigh_update(const uint8_t *addr, uint8_t family,
			const uint8_t *lladdr, int lladdr_len)
{
	unsigned int s = neigh_slot(addr, family), i;
	struct neigh_ent *e, *victim = NULL;

	e = neigh_find(addr, family);
	if (e) {
		if (lladdr_len == 6 && memcmp(e->lladdr, lladdr, 6)) {
			memcpy(e->lladdr, lladdr, 6);
			return 1;
		}
		return 0;
	}
	for (i = 0; i < 8; i++) {
		struct neigh_ent *c = &neigh_tab[(s + i) % NEIGH_TRACK_MAX];

		if (!c->used) {
			victim = c;
			break;
		}
	}
	if (!victim)
		return 0;	/* table full: do not guess */
	memset(victim, 0, sizeof(*victim));
	memcpy(victim->addr, addr, family == AF_INET ? 4 : 16);
	if (lladdr_len == 6)
		memcpy(victim->lladdr, lladdr, 6);
	victim->family = family;
	victim->used = 1;
	return 1;
}

static void neigh_forget(const uint8_t *addr, uint8_t family)
{
	struct neigh_ent *e = neigh_find(addr, family);

	if (e)
		memset(e, 0, sizeof(*e));
}

/*
 * Decide whether one RTM_*NEIGH message makes cached egresses wrong.
 *
 * Returns 1 = bump, 0 = ignore, -1 = not a neighbour we can track (missing
 * attributes), which the caller ignores as well. `why` is only for the log.
 */
static int neigh_event(struct nlmsghdr *h, const char **why)
{
	struct ndmsg *nd = NLMSG_DATA(h);
	struct nlattr *tb[NDA_MAX + 1] = {};
	uint8_t addr[NEIGH_KEY_LEN] = {};
	const uint8_t *lladdr = NULL;
	int alen, llen = 0;
	struct rtattr *rta;
	int rtl;

	if (h->nlmsg_len < NLMSG_HDRLEN + sizeof(*nd)) {
		*why = "short";
		return -1;
	}
	rtl = (int)(h->nlmsg_len - NLMSG_HDRLEN - sizeof(*nd));
	rta = (struct rtattr *)((char *)nd + NLMSG_ALIGN(sizeof(*nd)));
	for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
		int t = rta->rta_type & NLA_TYPE_MASK;

		if (t <= NDA_MAX)
			tb[t] = (struct nlattr *)rta;
	}
	if (!tb[NDA_DST]) {
		*why = "no-dst";
		return -1;
	}
	alen = tb[NDA_DST]->nla_len - NLA_ALIGN(sizeof(struct nlattr));
	if (nd->ndm_family == AF_INET && alen >= 4)
		memcpy(addr, nla_payload(tb[NDA_DST]), 4);
	else if (nd->ndm_family == AF_INET6 && alen >= 16)
		memcpy(addr, nla_payload(tb[NDA_DST]), 16);
	else {
		*why = "family";
		return -1;
	}
	if (tb[NDA_LLADDR]) {
		llen = tb[NDA_LLADDR]->nla_len -
		       NLA_ALIGN(sizeof(struct nlattr));
		if (llen > 6)
			llen = 6;
		if (llen > 0)
			lladdr = nla_payload(tb[NDA_LLADDR]);
	}

	/* A neighbour that just became unusable poisons every flow that
	 * cached its MAC; a delete does too. */
	if (h->nlmsg_type == RTM_DELNEIGH) {
		neigh_forget(addr, nd->ndm_family);
		*why = "neigh-deleted";
		return 1;
	}
	if (nd->ndm_state & (NUD_FAILED | NUD_INCOMPLETE)) {
		neigh_forget(addr, nd->ndm_family);
		*why = "neigh-failed";
		return 1;
	}
	/* Reachable/Stale/Delay/Probe with a lladdr: only a *changed* MAC
	 * matters. This is the 0.8 events/s stream that used to bump the
	 * whole table twice a minute. */
	if (lladdr && neigh_update(addr, nd->ndm_family, lladdr, llen)) {
		*why = "lladdr-changed";
		return 1;
	}
	*why = "refresh";
	return 0;
}

static struct nlattr *nla_find(struct nlattr *head, int len, int type)
{
	while (len >= (int)sizeof(struct nlattr)) {
		struct nlattr *nla = head;

		if (nla->nla_len < sizeof(struct nlattr) ||
		    nla->nla_len > len)
			break;
		if ((nla->nla_type & NLA_TYPE_MASK) == type)
			return nla;
		len -= NLA_ALIGN(nla->nla_len);
		head = (struct nlattr *)((char *)head +
					 NLA_ALIGN(nla->nla_len));
	}
	return NULL;
}

static void *nla_payload(struct nlattr *nla)
{
	return (char *)nla + NLA_ALIGN(sizeof(struct nlattr));
}

static int parse_tuple(struct nlattr *tuple, struct ct_tuple *t)
{
	int len = tuple->nla_len - NLA_ALIGN(sizeof(struct nlattr));
	struct nlattr *attrs = nla_payload(tuple);
	struct nlattr *ip, *pr, *a;

	memset(t, 0, sizeof(*t));
	ip = nla_find(attrs, len, CTA_TUPLE_IP);
	pr = nla_find(attrs, len, CTA_TUPLE_PROTO);
	if (!ip)
		return -1;
	a = nla_find(nla_payload(ip), ip->nla_len -
		     NLA_ALIGN(sizeof(struct nlattr)), CTA_IP_V4_SRC);
	if (a && a->nla_len >= NLA_ALIGN(sizeof(struct nlattr)) + 4) {
		t->family = AF_INET;
		memcpy(t->saddr, nla_payload(a), 4);
		a = nla_find(nla_payload(ip), ip->nla_len -
			     NLA_ALIGN(sizeof(struct nlattr)),
			     CTA_IP_V4_DST);
		if (!a || a->nla_len < NLA_ALIGN(sizeof(struct nlattr)) + 4)
			return -1;
		memcpy(t->daddr, nla_payload(a), 4);
	} else {
		t->family = AF_INET6;
		a = nla_find(nla_payload(ip), ip->nla_len -
			     NLA_ALIGN(sizeof(struct nlattr)), CTA_IP_V6_SRC);
		if (!a || a->nla_len < NLA_ALIGN(sizeof(struct nlattr)) + 16)
			return -1;
		memcpy(t->saddr, nla_payload(a), 16);
		a = nla_find(nla_payload(ip), ip->nla_len -
			     NLA_ALIGN(sizeof(struct nlattr)), CTA_IP_V6_DST);
		if (!a || a->nla_len < NLA_ALIGN(sizeof(struct nlattr)) + 16)
			return -1;
		memcpy(t->daddr, nla_payload(a), 16);
	}
	if (!pr)
		return -1;
	{
		int plen = pr->nla_len - NLA_ALIGN(sizeof(struct nlattr));
		struct nlattr *pn = nla_find(nla_payload(pr), plen,
					     CTA_PROTO_NUM);
		struct nlattr *ps = nla_find(nla_payload(pr), plen,
					     CTA_PROTO_SRC_PORT);
		struct nlattr *pd = nla_find(nla_payload(pr), plen,
					     CTA_PROTO_DST_PORT);

		if (!pn || !ps || !pd)
			return -1;
		t->proto = *(uint8_t *)nla_payload(pn);
		t->sport = ntohs(*(uint16_t *)nla_payload(ps));
		t->dport = ntohs(*(uint16_t *)nla_payload(pd));
	}
	return 0;
}

static void ct_queue(struct nlmsghdr *h)
{
	int len;
	struct nlattr *attrs, *a;
	struct ct_tuple t;
	struct nfgenmsg *nfg = NLMSG_DATA(h);

	if (h->nlmsg_len < NLMSG_HDRLEN + sizeof(*nfg))
		return;
	attrs = (struct nlattr *)((char *)nfg + sizeof(*nfg));
	len = h->nlmsg_len - NLMSG_HDRLEN - sizeof(*nfg);

	a = nla_find(attrs, len, CTA_TUPLE_ORIG);
	if (a && !parse_tuple(a, &t) && ct_pending_n < CT_PENDING_MAX)
		ct_pending[ct_pending_n++] = t;
	a = nla_find(attrs, len, CTA_TUPLE_REPLY);
	if (a && !parse_tuple(a, &t) && ct_pending_n < CT_PENDING_MAX)
		ct_pending[ct_pending_n++] = t;
}

/* One fork per second at most, not one per destroyed connection. dpdctl
 * scans the flow map once and deletes every key matching any of the tuples. */
/*
 * Map one CTA_STATUS to a dpd_ppe_state and queue it.
 *
 * Order matters: HW_OFFLOAD implies OFFLOAD, so test the hardware bit first.
 * A flow with neither bit is one the kernel is *not* offloading, i.e. squarely
 * DPD's business again -- recording SW_ACTIVE lets a flow come back to the
 * datapath when the flowtable drops it (the kernel does that on route/link
 * changes, exactly where DPD's epoch also moves).
 */
/* Stronger evidence of a hardware/flowtable claim must win. */
static int ppe_rank(uint32_t s)
{
	switch (s) {
	case DPD_PPE_OFFLOADED:	return 3;
	case DPD_PPE_YIELDED:	return 2;
	case DPD_PPE_SW_ACTIVE:	return 1;
	default:		return 0;
	}
}

static void ppe_update(const struct ct_tuple *t, uint32_t status)
{
	uint32_t want;
	int i;

	if (status & IPS_HW_OFFLOAD)
		want = DPD_PPE_OFFLOADED;
	else if (status & IPS_OFFLOAD)
		want = DPD_PPE_YIELDED;
	else
		want = DPD_PPE_SW_ACTIVE;

	/* One pending entry per tuple. Two sources feed this: the ctnetlink
	 * event path (which almost never carries an offload bit, because the
	 * kernel stops reporting once the flow leaves netfilter) and the
	 * /proc sweep (which does). If both queue the same flow, the weaker
	 * state must not overwrite the stronger one, or the datapath would be
	 * told "nobody owns it" right after being told "a flowtable does". */
	for (i = 0; i < ppe_pending_n; i++)
		if (ppe_pending[i].t.family == t->family &&
		    ppe_pending[i].t.proto == t->proto &&
		    ppe_pending[i].t.sport == t->sport &&
		    ppe_pending[i].t.dport == t->dport &&
		    !memcmp(ppe_pending[i].t.saddr, t->saddr, 16) &&
		    !memcmp(ppe_pending[i].t.daddr, t->daddr, 16)) {
			/* Rank: OFFLOADED(3) > YIELDED(2) > SW_ACTIVE(1). */
			if (ppe_rank(want) > ppe_rank(ppe_pending[i].state))
				ppe_pending[i].state = want;
			return;
		}

	if (ppe_pending_n >= CT_PPE_MAX)
		return;		/* next tick catches up */
	ppe_pending[ppe_pending_n].t = *t;
	ppe_pending[ppe_pending_n].state = want;
	ppe_pending_n++;
}

/*
 * Read the kernel's own offload flags out of /proc/net/nf_conntrack.
 *
 * Needed because ctnetlink does NOT deliver the transition: once a flow is
 * handed to a flowtable its packets stop traversing netfilter, so no further
 * CT UPDATE is emitted and CTA_STATUS with IPS_OFFLOAD is never seen. Measured
 * on the IPQ60xx (2026-11-11): the proc table showed [OFFLOAD] for two flows
 * while ct_offload stayed 0 for the whole connection.
 *
 * Line format (one entry per line, both directions on the same line):
 *   ipv4 2 tcp 6 431999 ESTABLISHED
 *       src=A dst=B sport=X dport=Y packets=.. [OFFLOAD]
 *       src=B dst=A sport=Y dport=X packets=.. mark=0 ...
 * Only the FIRST (original) direction is used, matching the event path.
 */
static void ppe_sweep(int dry)
{
	FILE *f;
	char line[1024];

	f = fopen("/proc/net/nf_conntrack", "r");
	if (!f)
		return;

	while (fgets(line, sizeof(line), f)) {
		struct ct_tuple t;
		uint32_t st = 0;
		char *p, *end;
		int field = 0, addrs = 0;

		if (strstr(line, "[HW_OFFLOAD]"))
			st = IPS_HW_OFFLOAD;
		else if (strstr(line, "[OFFLOAD]"))
			st = IPS_OFFLOAD;
		else
			continue;

		memset(&t, 0, sizeof(t));
		/* Skip family / l3num / proto / timeout, then the rest is
		 * key=value. Advance p past every skipped token, otherwise the
		 * key loop starts on the numeric timeout and misreads it. */
		p = line;
		for (field = 0; field < 4; field++) {
			size_t len;

			end = p + strcspn(p, " \t\r\n");
			len = (size_t)(end - p);
			if (field == 0)
				t.family = (len == 4 && !strncmp(p, "ipv6", 4))
					   ? AF_INET6 : AF_INET;
			else if (field == 2) {
				if (len == 3 && !strncmp(p, "tcp", 3))
					t.proto = IPPROTO_TCP;
				else if (len == 3 && !strncmp(p, "udp", 3))
					t.proto = IPPROTO_UDP;
			}
			if (!*end)
				break;
			p = end;
			while (*p == ' ' || *p == '\t')
				p++;
		}
		if (!t.proto)
			continue;

		while (*p) {
			char key[16], val[64];
			size_t vlen;
			char *eq;

			end = p + strcspn(p, " \t\r\n");
			vlen = (size_t)(end - p);
			eq = memchr(p, '=', vlen);
			if (eq) {
				size_t klen = (size_t)(eq - p);

				vlen = (size_t)(end - eq - 1);
				if (klen < sizeof(key) && vlen < sizeof(val)) {
					memcpy(key, p, klen);
					key[klen] = 0;
					memcpy(val, eq + 1, vlen);
					val[vlen] = 0;

					if (!strcmp(key, "src")) {
						if (inet_pton(t.family, val,
							      t.saddr) == 1)
							addrs |= 1;
					} else if (!strcmp(key, "dst")) {
						if (inet_pton(t.family, val,
							      t.daddr) == 1)
							addrs |= 2;
					} else if (!strcmp(key, "sport")) {
						t.sport = htons((uint16_t)
								strtoul(val, NULL, 10));
					} else if (!strcmp(key, "dport")) {
						t.dport = htons((uint16_t)
								strtoul(val, NULL, 10));
					}
				}
			}
			if (addrs == 3 && t.sport && t.dport)
				break;
			if (!*end)
				break;
			p = end;
			while (*p == ' ' || *p == '\t')
				p++;
		}

		if (addrs == 3 && t.sport && t.dport && !dry) {
			ppe_swept++;
			ppe_update(&t, st);
		}
	}
	fclose(f);
}

/* One fork per tick, regardless of how many flows changed: the whole batch
 * goes to a file and dpdctl applies it in one pass. Same shape as ct_flush()
 * for the same reason -- a daemon must not fork per conntrack event. */
static void ppe_flush(int dry)
{
	FILE *f;
	int i;

	if (!ppe_pending_n)
		return;

	f = fopen(CT_PPE_FILE, "w");
	if (!f) {
		ppe_pending_n = 0;
		return;
	}
	for (i = 0; i < ppe_pending_n; i++) {
		char sa[INET6_ADDRSTRLEN], da[INET6_ADDRSTRLEN];
		const struct ct_tuple *t = &ppe_pending[i].t;

		inet_ntop(t->family, t->saddr, sa, sizeof(sa));
		inet_ntop(t->family, t->daddr, da, sizeof(da));
		fprintf(f, "%u %s %u %s %u %s\n", ppe_pending[i].state,
			t->proto == IPPROTO_UDP ? "udp" : "tcp",
			(unsigned)ntohs(t->sport), sa,
			(unsigned)ntohs(t->dport), da);
	}
	fclose(f);

	if (!dry &&
	    system(DPD_CTL " flows ppe -f " CT_PPE_FILE " >/dev/null 2>&1") == 0)
		ppe_writes += (unsigned long)ppe_pending_n;
	ppe_pending_n = 0;
}

static void ct_flush(int dry)
{
	char sa[INET6_ADDRSTRLEN], da[INET6_ADDRSTRLEN];
	FILE *f;
	int i;

	if (!ct_pending_n)
		return;
	f = fopen(CT_DELETE_FILE, "w");
	if (!f) {
		ct_pending_n = 0;
		return;
	}
	for (i = 0; i < ct_pending_n; i++) {
		inet_ntop(ct_pending[i].family, ct_pending[i].saddr, sa,
			  sizeof(sa));
		inet_ntop(ct_pending[i].family, ct_pending[i].daddr, da,
			  sizeof(da));
		fprintf(f, "%u %s %u %s %u\n", ct_pending[i].proto, sa,
			ct_pending[i].sport, da, ct_pending[i].dport);
	}
	fclose(f);
	ct_delete_batches++;
	if (!dry)
		system(DPD_CTL " delete -f " CT_DELETE_FILE
		       " >/dev/null 2>&1");
	ct_pending_n = 0;
}

/*
 * Declarative class policy. Each line is a dpd_class key plus an action:
 *   <iface|any> <proto|tcp|udp|number> <saddr> <sport> <daddr> <dport>
 *   <forward|proxy|block|local> [priority]
 * dpdfwd flushes the map and repopulates it through dpdctl, so the only
 * dependency is the CLI (and the pinned map the core package creates).
 */
static const char *class_file = CLASS_FILE_DEFAULT;
static int class_enabled = 1;
static time_t class_next_check;
static struct stat class_prev;
static int class_have_prev;
static int class_ready_seen;
static unsigned long class_fail_streak;

static int class_port_ok(const char *s)
{
	char *e;
	unsigned long v;

	if (!strcmp(s, "any"))
		return 1;
	v = strtoul(s, &e, 0);
	return e != s && !*e && v <= 65535;
}

static int class_proto_ok(const char *s)
{
	char *e;
	unsigned long v;

	if (!strcmp(s, "tcp") || !strcmp(s, "udp"))
		return 1;
	v = strtoul(s, &e, 0);
	return e != s && !*e && v <= 255;
}

static int class_addr_family(const char *s)
{
	struct in_addr a4;
	struct in6_addr a6;

	if (inet_pton(AF_INET, s, &a4) == 1)
		return AF_INET;
	if (inet_pton(AF_INET6, s, &a6) == 1)
		return AF_INET6;
	return 0;
}

static int class_action_ok(const char *s)
{
	return !strcmp(s, "forward") || !strcmp(s, "proxy") ||
	       !strcmp(s, "block") || !strcmp(s, "local");
}

/* 0 = rule, 1 = blank/comment, -1 = invalid. tok[] points into line; an
 * "any" port is rewritten to "0" because dpdctl only parses a number. */
static int class_parse(char *line, char *tok[8], int *ntok)
{
	char *p = line, *t, *e;
	int n = 0, fam;
	unsigned long prio;

	t = strchr(line, '#');
	if (t)
		*t = '\0';
	for (;;) {
		while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
			p++;
		if (!*p)
			break;
		if (n >= 8)
			return -1;
		tok[n++] = p;
		while (*p && *p != ' ' && *p != '\t' && *p != '\r' &&
		       *p != '\n')
			p++;
		if (*p)
			*p++ = '\0';
	}
	if (!n)
		return 1;
	if (n < 7)		/* six tuple fields + action */
		return -1;
	fam = class_addr_family(tok[2]);
	if (!fam || class_addr_family(tok[4]) != fam)
		return -1;
	if (!class_proto_ok(tok[1]) || !class_action_ok(tok[6]))
		return -1;
	if (!class_port_ok(tok[3]) || !class_port_ok(tok[5]))
		return -1;
	if (n > 7) {
		prio = strtoul(tok[7], &e, 0);
		if (e == tok[7] || *e || prio > UINT32_MAX)
			return -1;
	}
	if (!strcmp(tok[3], "any"))
		tok[3] = "0";
	if (!strcmp(tok[5], "any"))
		tok[5] = "0";
	*ntok = n;
	return 0;
}

/* Run one dpdctl command. 0 = ok, 1 = failed, -1 = binary not installed. */
static int class_exec(char *const argv[])
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return 1;
	if (pid == 0) {
		int fd = open("/dev/null", O_WRONLY);

		if (fd >= 0) {
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			if (fd > STDERR_FILENO)
				close(fd);
		}
		execvp(DPD_CTL, argv);
		_exit(errno == ENOENT ? 127 : 126);
	}
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR)
			return 1;
	}
	if (!WIFEXITED(status))
		return 1;
	if (WEXITSTATUS(status) == 127)
		return -1;
	return WEXITSTATUS(status) ? 1 : 0;
}

static void class_add_argv(char *tok[], int ntok, char *argv[])
{
	int n = 0;

	argv[n++] = DPD_CTL;
	argv[n++] = "class";
	argv[n++] = "add";
	argv[n++] = tok[0];
	argv[n++] = tok[1];
	argv[n++] = tok[2];
	argv[n++] = tok[3];
	argv[n++] = tok[4];
	argv[n++] = tok[5];
	argv[n++] = tok[6];
	if (ntok > 7)
		argv[n++] = tok[7];
	argv[n] = NULL;
}

static void class_apply(struct stats *st, int dry)
{
	char line[CLASS_LINE_MAX];
	char *tok[8], *argv[12];
	char *flush_argv[] = { DPD_CTL, "class", "flush", NULL };
	FILE *f;
	int ntok, lineno = 0, first_bad = 0, bad = 0, ok = 1, rc;
	unsigned long valid = 0, tried = 0, added = 0;

	if (!dry && access(DPD_CTL, X_OK) != 0)
		return;		/* no dpdctl installed: silent no-op */
	f = fopen(class_file, "r");
	if (!f)
		return;		/* no policy file: silent no-op */
	while (fgets(line, sizeof(line), f)) {
		lineno++;
		rc = class_parse(line, tok, &ntok);
		if (rc < 0) {
			bad++;
			if (!first_bad)
				first_bad = lineno;
		} else if (rc == 0) {
			valid++;
		}
	}
	fclose(f);
	st->class_bad = (unsigned long)bad;
	if (bad)
		fprintf(stderr,
			"dpdfwd: %s: %d invalid line(s), first at %d\n",
			class_file, bad, first_bad);
	if (dry) {
		st->class_rules = valid > CLASS_MAX_RULES ?
				  CLASS_MAX_RULES : valid;
		return;
	}
	if (valid > CLASS_MAX_RULES)
		fprintf(stderr, "dpdfwd: %s: %lu rules, applying first %d\n",
			class_file, valid, CLASS_MAX_RULES);

	rc = class_exec(flush_argv);
	if (rc < 0)
		return;
	if (rc) {
		st->class_error++;
		class_fail_streak++;
		if (class_fail_streak >= CLASS_FAIL_MAX)
			fprintf(stderr, "dpdfwd: class: dpdctl failed %lu "
				"times, stopping apply\n", class_fail_streak);
		return;
	}
	class_fail_streak = 0;
	st->class_rules = 0;

	/* Second pass: the file can change under us, but a stale apply is
	 * caught by the next stat tick. */
	f = fopen(class_file, "r");
	if (!f)
		return;
	lineno = 0;
	while (fgets(line, sizeof(line), f)) {
		lineno++;
		if (class_parse(line, tok, &ntok) != 0)
			continue;
		if (tried >= CLASS_MAX_RULES)
			break;
		tried++;
		class_add_argv(tok, ntok, argv);
		rc = class_exec(argv);
		if (!rc) {
			class_fail_streak = 0;
			st->class_rules = ++added;
			continue;
		}
		if (rc < 0) {	/* binary vanished: silent no-op */
			fclose(f);
			return;
		}
		st->class_error++;
		ok = 0;
		if (++class_fail_streak >= CLASS_FAIL_MAX) {
			fprintf(stderr, "dpdfwd: class: %lu consecutive "
				"dpdctl failures, stopping apply\n",
				class_fail_streak);
			break;
		}
	}
	fclose(f);
	if (ok)
		st->class_applied_at = time(NULL);
}

static void class_tick(struct stats *st, int dry)
{
	struct stat sb;
	time_t now = time(NULL);
	int ready, changed;

	if (!class_enabled || now < class_next_check)
		return;
	class_next_check = now + CLASS_CHECK_S;

	if (stat(class_file, &sb) != 0) {
		class_have_prev = 0;
		return;
	}
	ready = dry || access(CLASS_PIN, F_OK) == 0 ||
		access(CLASS_PIN_LEGACY, F_OK) == 0;
	changed = !class_have_prev ||
		  sb.st_mtime != class_prev.st_mtime ||
		  sb.st_size != class_prev.st_size;
	class_prev = sb;
	class_have_prev = 1;
	if (!ready) {
		class_ready_seen = 0;
		return;		/* dpd_class not loaded (core not running) */
	}
	if (changed || !class_ready_seen)
		class_apply(st, dry);
	class_ready_seen = 1;
}

/* ---------------------------------------------------------------- plugins
 *
 * Control-plane plugins (see src/dpd_plugin.h). They are optional: a missing
 * directory, a broken .so or a failed init only logs and skips that plugin.
 * The packet path is never involved; a plugin classifies new flows and
 * dpdfwd turns the verdict into a dpd_class entry through dpdctl.
 */
#define PLUGIN_DIR_DEFAULT "/usr/lib/dpd/plugins"
#define PLUGIN_MAX 8

static struct dpd_plugin_ops *plugins[PLUGIN_MAX];
static void *plugin_handles[PLUGIN_MAX];
static int plugin_count;
static int plugins_enabled = 1;
static int plugin_dry = 1;
static const char *plugin_dir = PLUGIN_DIR_DEFAULT;

static void plugin_load_dir(const char *dir)
{
	DIR *d;
	struct dirent *de;

	d = opendir(dir);
	if (!d)
		return;
	while ((de = readdir(d)) != NULL) {
		char path[512];
		void *h;
		struct dpd_plugin_ops *ops;
		size_t n;

		n = strlen(de->d_name);
		if (n < 4 || strcmp(de->d_name + n - 3, ".so"))
			continue;
		if (plugin_count >= PLUGIN_MAX) {
			fprintf(stderr, "dpdfwd: plugin limit (%d) reached\n",
				PLUGIN_MAX);
			break;
		}
		snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
		h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
		if (!h) {
			fprintf(stderr, "dpdfwd: plugin %s: %s\n", path,
				dlerror());
			continue;
		}
		ops = (struct dpd_plugin_ops *)dlsym(h, DPD_PLUGIN_SYMBOL);
		if (!ops || !ops->name || ops->version != DPD_PLUGIN_ABI) {
			fprintf(stderr, "dpdfwd: plugin %s: bad ABI\n", path);
			dlclose(h);
			continue;
		}
		if (ops->init && ops->init() != 0) {
			fprintf(stderr, "dpdfwd: plugin %s: init failed\n",
				ops->name);
			dlclose(h);
			continue;
		}
		plugin_handles[plugin_count] = h;
		plugins[plugin_count++] = ops;
		fprintf(stderr, "dpdfwd: plugin %s loaded (ABI %d)\n",
			ops->name, ops->version);
	}
	closedir(d);
}

static void plugin_unload(void)
{
	int i;

	for (i = 0; i < plugin_count; i++) {
		if (plugin_handles[i])
			dlclose(plugin_handles[i]);
		plugin_handles[i] = NULL;
		plugins[i] = NULL;
	}
	plugin_count = 0;
}

static const char *plugin_action_name(uint32_t a)
{
	switch (a) {
	case DPD_PLUGIN_PROXY:	return "proxy";
	case DPD_PLUGIN_BLOCK:	return "block";
	case DPD_PLUGIN_LOCAL:	return "local";
	default:		return "forward";
	}
}

static void plugin_apply_class(const struct dpd_flow_desc *d)
{
	char sa[INET6_ADDRSTRLEN], da[INET6_ADDRSTRLEN];
	char sport[8], dport[8], prio[16], proto[8];
	char *argv[12];
	int n = 0;

	if (plugin_dry || access(DPD_CTL, X_OK) != 0)
		return;
	if (!inet_ntop(d->family, d->saddr, sa, sizeof(sa)) ||
	    !inet_ntop(d->family, d->daddr, da, sizeof(da)))
		return;
	snprintf(sport, sizeof(sport), "%u", d->sport);
	snprintf(dport, sizeof(dport), "%u", d->dport);
	snprintf(prio, sizeof(prio), "%u", d->skb_priority);
	snprintf(proto, sizeof(proto), "%u", d->proto);

	argv[n++] = DPD_CTL;
	argv[n++] = "class";
	argv[n++] = "add";
	argv[n++] = "any";
	argv[n++] = proto;
	argv[n++] = sa;
	argv[n++] = sport;
	argv[n++] = da;
	argv[n++] = dport;
	argv[n++] = (char *)plugin_action_name(d->action);
	argv[n++] = prio;
	argv[n] = NULL;
	class_exec(argv);
}

static void plugin_flow(int ev, const struct ct_tuple *t)
{
	struct dpd_flow_desc d;
	int i;

	if (!plugin_count)
		return;
	memset(&d, 0, sizeof(d));
	d.family = t->family;
	d.proto = t->proto;
	d.sport = t->sport;
	d.dport = t->dport;
	memcpy(d.saddr, t->saddr, sizeof(d.saddr));
	memcpy(d.daddr, t->daddr, sizeof(d.daddr));
	d.action = DPD_PLUGIN_FORWARD;

	for (i = 0; i < plugin_count; i++) {
		struct dpd_plugin_ops *p = plugins[i];
		struct dpd_flow_desc c = d;

		if (ev == DPD_EV_CT_DESTROY) {
			if (p->flow_expire)
				p->flow_expire(&c);
			continue;
		}
		if (p->flow_classify)
			p->flow_classify(&c);
		if (c.action != DPD_PLUGIN_FORWARD || c.skb_priority)
			plugin_apply_class(&c);
		if (p->flow_create)
			p->flow_create(&c);
	}
}

static void plugin_topology(int ev, const char *ifname)
{
	int i;

	for (i = 0; i < plugin_count; i++)
		if (plugins[i]->topology_event)
			plugins[i]->topology_event(ev, ifname);
}

static void plugin_ct(struct nlmsghdr *h, int ev)
{
	struct nfgenmsg *nfg = NLMSG_DATA(h);
	struct nlattr *attrs, *a;
	struct ct_tuple t;
	int len;

	if (!plugin_count)
		return;
	if (h->nlmsg_len < NLMSG_HDRLEN + sizeof(*nfg))
		return;
	attrs = (struct nlattr *)((char *)nfg + sizeof(*nfg));
	len = h->nlmsg_len - NLMSG_HDRLEN - sizeof(*nfg);
	a = nla_find(attrs, len, CTA_TUPLE_ORIG);
	if (a && !parse_tuple(a, &t))
		plugin_flow(ev, &t);
}

/* -------------------------------------------------------------- auto-tune
 *
 * The Flow Manager closes the loop on the four datapath knobs instead of
 * freezing them in UCI:
 *
 *   - accel_after_pkts: short flows (destroyed before 3 s) should stay on
 *     the stack; a high short-flow ratio raises the prime window, a
 *     long-flow mix lowers it;
 *   - tcp_ttl / udp_ttl: 4x the EWMA of the observed conntrack lifetime,
 *     clamped to [2 min, 10 min] and [1 min, 5 min];
 *   - udp_unidir_ttl: a quarter of the UDP TTL, clamped [15 s, 60 s].
 *
 * Samples come from CT new/destroy: a small open-addressed table maps a
 * 64-bit tuple hash to the start time. Collisions only skew one sample.
 * Values are written through dpdctl at most every 10 s and only when they
 * change; the static UCI values remain the initial state and the fallback
 * when auto_tune is off. Bounds are conservative on purpose.
 */
#define TUNE_SLOTS	4096
#define TUNE_INTERVAL	10

struct tune_ent {
	uint64_t	hash;
	uint64_t	started_ms;
};

static struct tune_ent tune_tab[TUNE_SLOTS];
static int auto_tune;
static int tune_dry = 1;
static unsigned int tune_accel = 8;
static unsigned int tune_tcp_ttl = 300000;
static unsigned int tune_udp_ttl = 120000;
static unsigned int tune_udp_unidir = 30000;
static unsigned int tune_accel_min = 8, tune_accel_max = 64;
static unsigned int tune_tcp_min = 120000, tune_tcp_max = 600000;
static unsigned int tune_udp_min = 60000, tune_udp_max = 300000;
static unsigned int tune_unidir_min = 15000, tune_unidir_max = 60000;
static unsigned long tune_samples, tune_short;
static unsigned long tune_tcp_samples, tune_udp_samples;
static uint64_t tune_tcp_avg, tune_udp_avg;
static time_t tune_last;

static uint64_t tune_hash(const struct ct_tuple *t)
{
	uint64_t h = 1469598103934665603ULL;
	int i, n = (t->family == AF_INET) ? 4 : 16;

#define TUNE_MIX(v) do {						\
	h = (h ^ (uint8_t)(v)) * 1099511628211ULL;			\
} while (0)
	TUNE_MIX(t->family);
	TUNE_MIX(t->proto);
	for (i = 0; i < n; i++)
		TUNE_MIX(t->saddr[i]);
	for (i = 0; i < n; i++)
		TUNE_MIX(t->daddr[i]);
	TUNE_MIX(t->sport);
	TUNE_MIX(t->sport >> 8);
	TUNE_MIX(t->dport);
	TUNE_MIX(t->dport >> 8);
#undef TUNE_MIX
	return h ? h : 1;
}

static void tune_ct(int ev, const struct ct_tuple *t)
{
	uint64_t h, now, life;
	uint32_t i;

	if (!auto_tune)
		return;
	h = tune_hash(t);
	i = (uint32_t)(h % TUNE_SLOTS);
	now = (uint64_t)time(NULL) * 1000;
	if (ev == DPD_EV_CT_NEW) {
		tune_tab[i].hash = h;
		tune_tab[i].started_ms = now;
		return;
	}
	if (ev != DPD_EV_CT_DESTROY)
		return;
	if (tune_tab[i].hash != h || !tune_tab[i].started_ms)
		return;
	life = now - tune_tab[i].started_ms;
	tune_tab[i].hash = 0;
	tune_tab[i].started_ms = 0;

	tune_samples++;
	if (life < 3000)
		tune_short++;
	if (t->proto == IPPROTO_TCP) {
		tune_tcp_avg = tune_tcp_avg ?
			(tune_tcp_avg * 7 + life) / 8 : life;
		tune_tcp_samples++;
	} else if (t->proto == IPPROTO_UDP) {
		tune_udp_avg = tune_udp_avg ?
			(tune_udp_avg * 7 + life) / 8 : life;
		tune_udp_samples++;
	}
}

static unsigned int tune_clamp(uint64_t v, unsigned int lo, unsigned int hi)
{
	if (v < lo)
		return lo;
	if (v > hi)
		return hi;
	return (unsigned int)v;
}

static unsigned int tune_round(unsigned int v, unsigned int step)
{
	return v - v % step;
}

/* Lifetime-derived TTLs are noisy: one long download lifts the EWMA by tens
 * of seconds, the next short flows drop it again, and without a limit the
 * TCP timeout flaps between 120 s and 450 s on every tick. Move at most
 * maxstep per update and only recompute the TTLs every third tick. */
static unsigned int tune_step(unsigned int old, unsigned int want,
			      unsigned int maxstep)
{
	if (want > old + maxstep)
		return old + maxstep;
	if (want + maxstep < old)
		return old - maxstep;
	return want;
}

static void tune_apply(const char *key, unsigned int val)
{
	char buf[16];
	char *argv[5];

	snprintf(buf, sizeof(buf), "%u", val);
	argv[0] = (char *)DPD_CTL;
	argv[1] = "set";
	argv[2] = (char *)key;
	argv[3] = buf;
	argv[4] = NULL;
	class_exec(argv);
}

static void tune_tick(void)
{
	time_t now = time(NULL);
	unsigned int accel = tune_accel, tcp = tune_tcp_ttl;
	unsigned int udp = tune_udp_ttl, uni = tune_udp_unidir;
	static unsigned int ttl_tick;
	int changed = 0, do_ttl;

	if (!auto_tune || now - tune_last < TUNE_INTERVAL)
		return;
	tune_last = now;
	do_ttl = (++ttl_tick % 3) == 0;

	if (tune_samples >= 32) {
		double r = (double)tune_short / (double)tune_samples;

		if (r > 0.60) {
			unsigned int v = tune_clamp((uint64_t)accel + 8,
						    tune_accel_min,
						    tune_accel_max);
			if (v != accel) {
				accel = v;
				changed = 1;
			}
		} else if (r < 0.25) {
			unsigned int v = tune_clamp(accel > 4 ? accel - 4 : 0,
						    tune_accel_min,
						    tune_accel_max);
			if (v != accel) {
				accel = v;
				changed = 1;
			}
		}
	}
	if (do_ttl && tune_tcp_samples >= 4) {
		unsigned int v = tune_round(tune_clamp(tune_tcp_avg * 4,
						       tune_tcp_min, tune_tcp_max),
					    10000);
		v = tune_step(tcp, v, 30000);
		if (v != tcp) {
			tcp = v;
			changed = 1;
		}
	}
	if (do_ttl && tune_udp_samples >= 4) {
		unsigned int v = tune_round(tune_clamp(tune_udp_avg * 4,
						       tune_udp_min, tune_udp_max),
					    10000);
		v = tune_step(udp, v, 20000);
		if (v != udp) {
			udp = v;
			changed = 1;
		}
		{
			unsigned int u = tune_round(tune_clamp(udp / 4,
							       tune_unidir_min,
							       tune_unidir_max),
						    5000);
			u = tune_step(uni, u, 5000);
			if (u != uni) {
				uni = u;
				changed = 1;
			}
		}
	}

	if (tune_samples && getenv("DPD_TUNE_DEBUG"))
		fprintf(stderr, "dpdfwd: tune tick samples=%lu short=%lu "
			"accel=%u tcp=%u udp=%u udp1=%u\n",
			tune_samples, tune_short, accel, tcp, udp, uni);

	/* Push the whole set, not just the values that moved: the data plane is
	 * a pinned map and a dpd-fastpath reload (upgrade, service restart)
	 * rewrites it with the compiled/UCI defaults while this process keeps
	 * its own state. Re-applying every TTL tick (30 s) makes the map
	 * converge again without restarting dpdfwd. */
	if (!tune_dry && (changed || do_ttl)) {
		tune_apply("accel", accel);
		tune_apply("tcp_ttl", tcp);
		tune_apply("udp_ttl", udp);
		tune_apply("udp_unidir_ttl", uni);
	}
	if (changed) {
		fprintf(stderr, "dpdfwd: tune accel=%u tcp=%u udp=%u "
			"udp1=%u samples=%lu short=%.0f%%%s\n",
			accel, tcp, udp, uni, tune_samples,
			tune_samples ? 100.0 * tune_short / tune_samples : 0.0,
			tune_dry ? " (dry-run)" : "");
	}
	tune_accel = accel;
	tune_tcp_ttl = tcp;
	tune_udp_ttl = udp;
	tune_udp_unidir = uni;
	tune_samples /= 2;
	tune_short /= 2;
}

static void tune_ct_msg(struct nlmsghdr *h, int ev)
{
	struct nfgenmsg *nfg = NLMSG_DATA(h);
	struct nlattr *attrs, *a;
	struct ct_tuple t;
	int len;

	if (!auto_tune)
		return;
	if (h->nlmsg_len < NLMSG_HDRLEN + sizeof(*nfg))
		return;
	attrs = (struct nlattr *)((char *)nfg + sizeof(*nfg));
	len = h->nlmsg_len - NLMSG_HDRLEN - sizeof(*nfg);
	a = nla_find(attrs, len, CTA_TUPLE_ORIG);
	if (a && !parse_tuple(a, &t))
		tune_ct(ev, &t);
}

/* Count conntrack events reporting the entry as offloaded. CTA_STATUS can be
 * resent on several updates of the same connection, so these count events,
 * not distinct flows. Observability only: acceleration is untouched. */
static void ct_status(struct nlmsghdr *h, struct stats *st)
{
	struct nfgenmsg *nfg = NLMSG_DATA(h);
	struct nlattr *attrs, *a;
	uint32_t status;
	int len;

	if (h->nlmsg_len < NLMSG_HDRLEN + sizeof(*nfg))
		return;
	attrs = (struct nlattr *)((char *)nfg + sizeof(*nfg));
	len = h->nlmsg_len - NLMSG_HDRLEN - sizeof(*nfg);
	a = nla_find(attrs, len, CTA_STATUS);
	if (!a || a->nla_len < NLA_ALIGN(sizeof(struct nlattr)) + 4)
		return;
	status = *(uint32_t *)nla_payload(a);
	if (status & IPS_OFFLOAD)
		st->ct_offload++;
	if (status & IPS_HW_OFFLOAD)
		st->ct_hw_offload++;

	/* ABI 22: feed the software/hardware handover. The original tuple names
	 * the datapath entry; conntrack always carries it on a NEW/UPDATE. */
	if (ppe_enabled) {
		struct ct_tuple t;

		memset(&t, 0, sizeof(t));
		a = nla_find(attrs, len, CTA_TUPLE_ORIG);
		if (a && !parse_tuple(a, &t))
			ppe_update(&t, status);
	}
}

static void ct_event(struct nlmsghdr *h, int ev, struct stats *st)
{
	ct_status(h, st);
	plugin_ct(h, ev);
	tune_ct_msg(h, ev);
}

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static int nl_open(int protocol, unsigned int groups)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK, .nl_groups = groups };
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);

	if (fd < 0)
		return -1;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* A link event on a bridge port does not change the bridge master's L2 path,
 * so it must not invalidate the flows learned on the master. Uplink, LAN
 * master and any non-port interface still bump. */
static int link_is_bridge_port(struct nlmsghdr *h)
{
	struct ifinfomsg *ifi = NLMSG_DATA(h);
	char name[IF_NAMESIZE], path[128];

	if (h->nlmsg_len < NLMSG_HDRLEN + sizeof(*ifi))
		return 0;
	if (!if_indextoname(ifi->ifi_index, name))
		return 0;
	snprintf(path, sizeof(path), "/sys/class/net/%s/master", name);
	return access(path, F_OK) == 0;
}

static void bump_epoch(int dry, struct stats *st)
{
	char cmd[128];

	st->bumps++;
	if (dry)
		return;
	snprintf(cmd, sizeof(cmd), "%s bump >/dev/null 2>&1", DPD_CTL);
	if (system(cmd) != 0)
		st->errors++;
}

/*
 * Refresh /var/run/ebpf/status.json from `dpdctl status -j`.
 *
 * It runs on its own 2 s tick and writes through a temp file + rename, so a
 * reader never sees half a JSON document. Failures are counted and otherwise
 * ignored: a dashboard that cannot read the file shows the chip as unknown,
 * which is the correct behaviour, and the datapath is unaffected.
 */
static void publish_status_json(struct stats *st)
{
	FILE *p;
	char buf[16384];
	size_t n;
	int rc;

	p = popen(DPD_CTL " status -j 2>/dev/null", "r");
	if (!p) {
		st->errors++;
		return;
	}
	n = fread(buf, 1, sizeof(buf) - 1, p);
	rc = pclose(p);
	if (n == 0 || rc != 0) {
		st->errors++;
		return;
	}
	buf[n] = 0;

	mkdir(UI_DIR, 0755);
	{
		FILE *f = fopen(UI_FILE ".tmp", "w");

		if (!f) {
			st->errors++;
			return;
		}
		if (fwrite(buf, 1, n, f) != n) {
			fclose(f);
			unlink(UI_FILE ".tmp");
			st->errors++;
			return;
		}
		fclose(f);
	}
	if (rename(UI_FILE ".tmp", UI_FILE) != 0) {
		unlink(UI_FILE ".tmp");
		st->errors++;
	}
}

static void publish(struct stats *st)
{
	char tmp[128];
	FILE *f;

	snprintf(tmp, sizeof(tmp), OUT_FILE ".tmp");
	f = fopen(tmp, "w");
	if (!f) {
		st->errors++;
		return;
	}
	fprintf(f,
		"{ \"uptime\": %ld, \"link\": %lu, \"link_port\": %lu,"
		" \"addr\": %lu, \"route\": %lu,"
		" \"neigh\": %lu, \"neigh_ignored\": %lu,"
		" \"neigh_forced\": %lu, \"ct_new\": %lu, \"ct_update\": %lu,"
		" \"ct_destroy\": %lu, \"ct_offload\": %lu,"
		" \"ct_hw_offload\": %lu, \"ppe_writes\": %lu,"
		" \"ppe_swept\": %lu, \"epoch_bumps\": %lu,"
		" \"unknown\": %lu, \"errors\": %lu, \"ct_delete_batches\": %lu,"
		" \"class_rules\": %lu, \"class_bad\": %lu,"
		" \"class_applied_at\": %ld, \"class_error\": %lu,"
		" \"tune\": { \"auto\": %d, \"accel\": %u,"
		" \"tcp_ttl_ms\": %u, \"udp_ttl_ms\": %u,"
		" \"udp_unidir_ttl_ms\": %u, \"samples\": %lu,"
		" \"short_ratio\": %.3f },"
		" \"last_event\": %ld }\n",
		(long)(time(NULL) - st->started), st->link, st->link_port,
		st->addr, st->route, st->neigh, st->neigh_ignored,
		st->neigh_forced, st->ct_new, st->ct_update,
		st->ct_destroy, st->ct_offload, st->ct_hw_offload, ppe_writes,
		ppe_swept, st->bumps,
		st->unknown, st->errors,
		ct_delete_batches, st->class_rules, st->class_bad,
		(long)st->class_applied_at, st->class_error,
		auto_tune, tune_accel, tune_tcp_ttl, tune_udp_ttl,
		tune_udp_unidir, tune_samples,
		tune_samples ? (double)tune_short / (double)tune_samples : 0.0,
		(long)st->last_event);
	fclose(f);
	if (rename(tmp, OUT_FILE) != 0)
		st->errors++;
}

int main(int argc, char **argv)
{
	int dry = 0, once = 0, i, ct_delete = 1;
	int rtnl, ct;
	struct stats st = { 0 };
	long long bump_at = 0;
	long long last_neigh_bump = 0;
	time_t next_publish = 0, next_status = 0, last_ct_flush = 0, next_prune = 0;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--dry-run"))
			dry = 1;
		else if (!strcmp(argv[i], "--once"))
			once = 1;
		else if (!strcmp(argv[i], "--no-ct-delete"))
			ct_delete = 0;
		else if (!strcmp(argv[i], "--no-class"))
			class_enabled = 0;
		else if (!strcmp(argv[i], "--class-file") && i + 1 < argc)
			class_file = argv[++i];
		else if (!strcmp(argv[i], "--no-plugins"))
			plugins_enabled = 0;
		else if (!strcmp(argv[i], "--plugin-dir") && i + 1 < argc)
			plugin_dir = argv[++i];
		else if (!strcmp(argv[i], "--auto-tune"))
			auto_tune = 1;
		else if (!strcmp(argv[i], "--no-auto-tune"))
			auto_tune = 0;
		else if (!strcmp(argv[i], "--accel") && i + 1 < argc)
			tune_accel = strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--tcp-ttl") && i + 1 < argc)
			tune_tcp_ttl = strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--udp-ttl") && i + 1 < argc)
			tune_udp_ttl = strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--udp-unidir") && i + 1 < argc)
			tune_udp_unidir = strtoul(argv[++i], NULL, 0);
	}
	signal(SIGTERM, on_signal);
	signal(SIGINT, on_signal);
	st.started = time(NULL);
	mkdir(OUT_DIR, 0755);
	plugin_dry = dry;
	tune_dry = dry;
	tune_accel = tune_clamp(tune_accel, tune_accel_min, tune_accel_max);
	tune_tcp_ttl = tune_clamp(tune_tcp_ttl, tune_tcp_min, tune_tcp_max);
	tune_udp_ttl = tune_clamp(tune_udp_ttl, tune_udp_min, tune_udp_max);
	tune_udp_unidir = tune_clamp(tune_udp_unidir, tune_unidir_min,
				     tune_unidir_max);
	if (auto_tune)
		fprintf(stderr, "dpdfwd: auto-tune on (accel=%u tcp=%u "
			"udp=%u udp1=%u)\n", tune_accel, tune_tcp_ttl,
			tune_udp_ttl, tune_udp_unidir);
	/* dpd_cfg lives in a pinned map, so it survives a dpdfwd restart while
	 * the tuner starts again from the init arguments. Push the starting
	 * point once: otherwise publish()/flowd.json report values the data
	 * plane is not using until the first change. */
	if (auto_tune && !tune_dry) {
		tune_apply("accel", tune_accel);
		tune_apply("tcp_ttl", tune_tcp_ttl);
		tune_apply("udp_ttl", tune_udp_ttl);
		tune_apply("udp_unidir_ttl", tune_udp_unidir);
	}
	if (plugins_enabled)
		plugin_load_dir(plugin_dir);

	rtnl = nl_open(NETLINK_ROUTE, RTNL_GROUPS);
	ct = nl_open(NETLINK_NETFILTER, CT_GROUPS);
	if (rtnl < 0) {
		fprintf(stderr, "dpdfwd: netlink route: %s\n", strerror(errno));
		return 2;
	}
	/* conntrack events are optional: a kernel without the module must not
	 * stop the route-based invalidation. */
	if (ct < 0)
		fprintf(stderr, "dpdfwd: conntrack events unavailable: %s\n",
			strerror(errno));

	while (!stop) {
		struct pollfd pfd[2];
		int n = 0, ret;
		long long now_ms;

		pfd[n].fd = rtnl;
		pfd[n].events = POLLIN;
		n++;
		if (ct >= 0) {
			pfd[n].fd = ct;
			pfd[n].events = POLLIN;
			n++;
		}
		ret = poll(pfd, n, 200);
		now_ms = (long long)time(NULL) * 1000;
		if (ret > 0) {
			for (i = 0; i < n; i++) {
				char buf[8192];
				ssize_t len;

				if (!(pfd[i].revents & POLLIN))
					continue;
				len = recv(pfd[i].fd, buf, sizeof(buf), 0);
				if (len <= 0) {
					st.errors++;
					continue;
				}
				st.last_event = time(NULL);
				if (i == 0) {
					struct nlmsghdr *h;
					int hard = 0, soft = 0;

					for (h = (struct nlmsghdr *)buf;
					     NLMSG_OK(h, (unsigned int)len);
					     h = NLMSG_NEXT(h, len)) {
						switch (h->nlmsg_type) {
						case RTM_NEWLINK:
						case RTM_DELLINK:
							st.link++;
							plugin_topology(DPD_EV_LINK, NULL);
							if (link_is_bridge_port(h))
								st.link_port++;
							else
								hard = 1;
							break;
						case RTM_NEWADDR:
						case RTM_DELADDR:
							st.addr++;
							plugin_topology(DPD_EV_ADDR, NULL);
							/* Router addresses feed the
							 * local-delivery map; a PPPoE
							 * redial changes them. */
							system(DPD_CTL " local sync "
							       ">/dev/null 2>&1");
							hard = 1;
							break;
						case RTM_NEWROUTE:
						case RTM_DELROUTE:
							st.route++;
							plugin_topology(DPD_EV_ROUTE, NULL);
							hard = 1;
							break;
						case RTM_NEWNEIGH:
						case RTM_DELNEIGH: {
							const char *why = "";

							st.neigh++;
							plugin_topology(DPD_EV_NEIGH, NULL);
							if (neigh_event(h, &why) > 0)
								soft = 1;
							else
								st.neigh_ignored++;
							break;
						}
						default:
							st.unknown++;
						}
					}
					/* A real topology change (link, address,
					 * route) invalidates every learned flow at
					 * once. Neighbour churn only affects one
					 * MAC, and bumping for it every couple of
					 * seconds means no short flow ever survives
					 * to accel_after; rate-limit it instead. */
					/* hard: link/address/route -- always.
					 * soft: a neighbour that actually broke
					 * or changed MAC (neigh_event() decided
					 * that). Rate-limit only the burst, so
					 * an ARP storm cannot become an epoch
					 * storm; the 30 s table-wide invalidation
					 * it used to cause is gone. */
					if (hard) {
						bump_at = now_ms + DEBOUNCE_MS;
					} else if (soft &&
						   now_ms - last_neigh_bump >=
							   NEIGH_BUMP_MS) {
						bump_at = now_ms + DEBOUNCE_MS;
						last_neigh_bump = now_ms;
					}
				} else {
					struct nlmsghdr *h;

					for (h = (struct nlmsghdr *)buf;
					     NLMSG_OK(h, (unsigned int)len);
					     h = NLMSG_NEXT(h, len)) {
						int msg = h->nlmsg_type & 0xff;

						if (msg == IPCTNL_MSG_CT_NEW) {
							st.ct_new++;
							ct_event(h, DPD_EV_CT_NEW,
								 &st);
						} else if (msg ==
							   IPCTNL_MSG_CT_DELETE) {
							st.ct_destroy++;
							ct_event(h,
								 DPD_EV_CT_DESTROY,
								 &st);
							if (ct_delete)
								ct_queue(h);
						} else {
							st.ct_update++;
							ct_event(h,
								 DPD_EV_CT_UPDATE,
								 &st);
						}
					}
				}
			}
		}
		class_tick(&st, dry);
		tune_tick();
		if (bump_at && now_ms >= bump_at) {
			bump_epoch(dry, &st);
			bump_at = 0;
			if (once)
				break;
		}
		/* Backstop: a cached dmac is trusted for NEIGH_SWEEP_MS. If
		 * nothing invalidated it by then, re-learn anyway. This is the
		 * only remaining periodic bump, and it is 5 min apart instead
		 * of the old 30 s neighbour rate-limit. */
		if (!neigh_sweep_at)
			neigh_sweep_at = now_ms + NEIGH_SWEEP_MS;
		else if (now_ms >= neigh_sweep_at) {
			st.neigh_forced++;
			bump_at = now_ms + DEBOUNCE_MS;
			neigh_sweep_at = now_ms + NEIGH_SWEEP_MS;
		}
		if (time(NULL) != last_ct_flush) {
			ct_flush(dry);
			/* The event stream cannot report an offload (see ppe_sweep),
			 * so poll the table, then push whatever changed in one
			 * batch. Both run on the same 1 s tick. */
			ppe_sweep(dry);
			ppe_flush(dry);
			last_ct_flush = time(NULL);
		}
		if (time(NULL) >= next_prune) {
			system(DPD_CTL " flows prune " PRUNE_AGE_STR
			       " >/dev/null 2>&1");
			next_prune = time(NULL) + PRUNE_S;
		}
		if (time(NULL) >= next_status) {
			publish_status_json(&st);
			next_status = time(NULL) + DPD_CTL_STATUS_S;
		}
		if (time(NULL) >= next_publish) {
			publish(&st);
			next_publish = time(NULL) + PUBLISH_MS / 1000;
			if (next_publish <= time(NULL))
				next_publish = time(NULL) + 1;
		}
	}
	publish(&st);
	plugin_unload();
	close(rtnl);
	if (ct >= 0)
		close(ct);
	return 0;
}
