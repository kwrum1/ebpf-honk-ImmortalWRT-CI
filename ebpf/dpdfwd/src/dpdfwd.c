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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

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
#define DPD_CTL "/usr/sbin/dpdctl"
#define CT_DELETE_FILE "/tmp/dpd-ct-delete"
#define DEBOUNCE_MS 300
#define PUBLISH_MS 2000

/* ctnetlink attribute numbers (linux/netfilter/nfnetlink_conntrack.h). */
#define CTA_TUPLE_ORIG 1
#define CTA_TUPLE_REPLY 2
#define CTA_TUPLE_IP 1
#define CTA_TUPLE_PROTO 2
#define CTA_IP_V4_SRC 1
#define CTA_IP_V4_DST 2
#define CTA_IP_V6_SRC 3
#define CTA_IP_V6_DST 4
#define CTA_PROTO_NUM 1
#define CTA_PROTO_SRC_PORT 2
#define CTA_PROTO_DST_PORT 3

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
	unsigned long addr;
	unsigned long route;
	unsigned long neigh;
	unsigned long ct_new;
	unsigned long ct_update;
	unsigned long ct_destroy;
	unsigned long bumps;
	unsigned long unknown;
	unsigned long errors;
	time_t started;
	time_t last_event;
};

static struct ct_tuple ct_pending[CT_PENDING_MAX];
static int ct_pending_n;
static unsigned long ct_delete_batches;

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
		"{ \"uptime\": %ld, \"link\": %lu, \"addr\": %lu, \"route\": %lu,"
		" \"neigh\": %lu, \"ct_new\": %lu, \"ct_update\": %lu,"
		" \"ct_destroy\": %lu, \"epoch_bumps\": %lu,"
		" \"unknown\": %lu, \"errors\": %lu, \"ct_delete_batches\": %lu,"
		" \"last_event\": %ld }\n",
		(long)(time(NULL) - st->started), st->link, st->addr,
		st->route, st->neigh, st->ct_new, st->ct_update,
		st->ct_destroy, st->bumps, st->unknown, st->errors,
		ct_delete_batches, (long)st->last_event);
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
	time_t next_publish = 0, last_ct_flush = 0;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--dry-run"))
			dry = 1;
		else if (!strcmp(argv[i], "--once"))
			once = 1;
		else if (!strcmp(argv[i], "--no-ct-delete"))
			ct_delete = 0;
	}
	signal(SIGTERM, on_signal);
	signal(SIGINT, on_signal);
	st.started = time(NULL);
	mkdir(OUT_DIR, 0755);

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

					for (h = (struct nlmsghdr *)buf;
					     NLMSG_OK(h, (unsigned int)len);
					     h = NLMSG_NEXT(h, len)) {
						switch (h->nlmsg_type) {
						case RTM_NEWLINK:
						case RTM_DELLINK:
							st.link++;
							break;
						case RTM_NEWADDR:
						case RTM_DELADDR:
							st.addr++;
							break;
						case RTM_NEWROUTE:
						case RTM_DELROUTE:
							st.route++;
							break;
						case RTM_NEWNEIGH:
						case RTM_DELNEIGH:
							st.neigh++;
							break;
						default:
							st.unknown++;
						}
					}
					/* topology changed: one debounced bump */
					bump_at = now_ms + DEBOUNCE_MS;
				} else {
					struct nlmsghdr *h;

					for (h = (struct nlmsghdr *)buf;
					     NLMSG_OK(h, (unsigned int)len);
					     h = NLMSG_NEXT(h, len)) {
						int msg = h->nlmsg_type & 0xff;

						if (msg == IPCTNL_MSG_CT_NEW) {
							st.ct_new++;
						} else if (msg ==
							   IPCTNL_MSG_CT_DELETE) {
							st.ct_destroy++;
							if (ct_delete)
								ct_queue(h);
						} else {
							st.ct_update++;
						}
					}
				}
			}
		}
		if (bump_at && now_ms >= bump_at) {
			bump_epoch(dry, &st);
			bump_at = 0;
			if (once)
				break;
		}
		if (time(NULL) != last_ct_flush) {
			ct_flush(dry);
			last_ct_flush = time(NULL);
		}
		if (time(NULL) >= next_publish) {
			publish(&st);
			next_publish = time(NULL) + PUBLISH_MS / 1000;
			if (next_publish <= time(NULL))
				next_publish = time(NULL) + 1;
		}
	}
	publish(&st);
	close(rtnl);
	if (ct >= 0)
		close(ct);
	return 0;
}
