// dpd-napi-netdev: per-NAPI control through the kernel's "netdev" generic
// netlink family (kernel >= 6.10, present in the unified 6.18 build).
//
// sysfs only exposes gro_flush_timeout / napi_defer_hard_irqs per *device*
// (they are written into every NAPI at registration). The netdev family
// exposes the real instances, so a queue can be tuned individually and the
// threaded-NAPI and irq-suspend-timeout knobs (which have no sysfs file at all)
// become reachable.
//
// No libmnl/libnl dependency: plain NETLINK_GENERIC. Exit code 2 means "the
// family or the attribute is unavailable on this kernel"; the caller then
// falls back to the sysfs path.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#ifndef NETDEV_FAMILY_NAME
#define NETDEV_FAMILY_NAME "netdev"
#endif
#ifndef NETDEV_FAMILY_VERSION
#define NETDEV_FAMILY_VERSION 1
#endif
/* UAPI values are stable; copied from linux/netdev.h so the package builds
 * against the SDK headers, which do not carry the file yet. */
#ifndef NETDEV_A_NAPI_IFINDEX
#define NETDEV_A_NAPI_IFINDEX		1
#define NETDEV_A_NAPI_ID		2
#define NETDEV_A_NAPI_IRQ		3
#define NETDEV_A_NAPI_PID		4
#define NETDEV_A_NAPI_DEFER_HARD_IRQS	5
#define NETDEV_A_NAPI_GRO_FLUSH_TIMEOUT	6
#define NETDEV_A_NAPI_IRQ_SUSPEND_TIMEOUT 7
#define NETDEV_A_NAPI_THREADED		8
#endif
#ifndef NETDEV_CMD_NAPI_GET
/* DEV_GET 1 .. PAGE_POOL_STATS_GET 9, QUEUE_GET 10, NAPI_GET 11,
 * QSTATS_GET 12, BIND_RX 13, NAPI_SET 14, BIND_TX 15. */
#define NETDEV_CMD_NAPI_GET	11
#define NETDEV_CMD_NAPI_SET	14
#endif

#define MAX_NAPI 1024

struct napi {
	uint32_t ifindex;
	uint32_t id;
	uint32_t irq;
	uint32_t pid;
	uint32_t defer_hard_irqs;
	uint32_t gro_flush_timeout;
	uint32_t irq_suspend_timeout;
	uint8_t threaded;
	uint8_t have_threaded;
};

static int nl_fd = -1;
static uint32_t nl_seq = 1;
static uint16_t family_id;

static int nl_open(void)
{
	struct sockaddr_nl sa;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };

	nl_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	if (nl_fd < 0)
		return -1;
	setsockopt(nl_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(nl_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(nl_fd);
		nl_fd = -1;
		return -1;
	}
	return 0;
}

static struct nlattr *nla_put(char *buf, size_t buflen, size_t *off, int type,
			      const void *data, size_t len)
{
	size_t total = NLA_HDRLEN + len;
	struct nlattr *nla;

	if (*off + NLA_ALIGN(total) > buflen)
		return NULL;
	nla = (struct nlattr *)(buf + *off);
	nla->nla_type = type;
	nla->nla_len = total;
	if (len)
		memcpy((char *)nla + NLA_HDRLEN, data, len);
	memset((char *)nla + total, 0, NLA_ALIGN(total) - total);
	*off += NLA_ALIGN(total);
	return nla;
}

static void nla_put_u32(char *buf, size_t buflen, size_t *off, int type, uint32_t v)
{
	nla_put(buf, buflen, off, type, &v, sizeof(v));
}

static void nla_put_u8(char *buf, size_t buflen, size_t *off, int type, uint8_t v)
{
	nla_put(buf, buflen, off, type, &v, sizeof(v));
}

/* one parse pass over a genl message; returns the first matching attr */
static struct nlattr *nla_find(struct nlattr *head, int len, int type)
{
	struct nlattr *nla;

	while (len >= (int)sizeof(*nla)) {
		nla = head;
		if (nla->nla_len < sizeof(*nla) || nla->nla_len > len)
			break;
		if ((nla->nla_type & NLA_TYPE_MASK) == type)
			return nla;
		len -= NLA_ALIGN(nla->nla_len);
		head = (struct nlattr *)((char *)head + NLA_ALIGN(nla->nla_len));
	}
	return NULL;
}

static int nla_get_u32(struct nlattr *nla, uint32_t *out)
{
	if (!nla || nla->nla_len < NLA_HDRLEN + 4)
		return -1;
	memcpy(out, (char *)nla + NLA_HDRLEN, 4);
	return 0;
}

static int nla_get_u8(struct nlattr *nla, uint8_t *out)
{
	if (!nla || nla->nla_len < NLA_HDRLEN + 1)
		return -1;
	memcpy(out, (char *)nla + NLA_HDRLEN, 1);
	return 0;
}

static int nla_get_u16(struct nlattr *nla, uint16_t *out)
{
	if (!nla || nla->nla_len < NLA_HDRLEN + 2)
		return -1;
	memcpy(out, (char *)nla + NLA_HDRLEN, 2);
	return 0;
}

/* send a request and feed every matching reply to cb */
static int nl_talk(struct nlmsghdr *nlh, int (*cb)(struct nlmsghdr *, void *),
		   void *arg)
{
	struct sockaddr_nl sa;
	char buf[65536];
	uint32_t seq = nl_seq++;

	nlh->nlmsg_seq = seq;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (getenv("DPD_NAPI_DEBUG"))
		fprintf(stderr, "send type=%u len=%u seq=%u\n", nlh->nlmsg_type,
			nlh->nlmsg_len, seq);
	if (sendto(nl_fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa,
		   sizeof(sa)) < 0)
		return -errno;

	for (;;) {
		ssize_t n = recv(nl_fd, buf, sizeof(buf), 0);
		struct nlmsghdr *h;

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return -ETIMEDOUT;
			return -errno;
		}
		for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned int)n);
		     h = NLMSG_NEXT(h, n)) {
			if (getenv("DPD_NAPI_DEBUG"))
				fprintf(stderr, "recv type=%u len=%u seq=%u want=%u\n",
					h->nlmsg_type, h->nlmsg_len,
					h->nlmsg_seq, seq);
			if (h->nlmsg_seq != seq)
				continue;
			if (h->nlmsg_type == NLMSG_DONE)
				return 0;
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = NLMSG_DATA(h);

				return e->error;
			}
			if (cb && cb(h, arg))
				return 0;
		}
	}
}

struct fam_arg {
	uint16_t id;
};

/* CTRL_ATTR_FAMILY_ID is a u16 even though most netdev attributes are u32. */
static int fam_cb(struct nlmsghdr *h, void *arg)
{
	struct fam_arg *fa = arg;
	struct genlmsghdr *g = NLMSG_DATA(h);
	struct nlattr *nla;
	uint16_t id;

	nla = (struct nlattr *)((char *)g + GENL_HDRLEN);
	nla = nla_find(nla, h->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN,
		       CTRL_ATTR_FAMILY_ID);
	if (!nla || nla_get_u16(nla, &id))
		return 0;
	fa->id = id;
	return 1;
}

static int resolve_family(void)
{
	struct fam_arg fa = { 0 };
	char buf[512] = { 0 };
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *g;
	size_t off;
	int ret;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	g = NLMSG_DATA(nlh);
	g->cmd = CTRL_CMD_GETFAMILY;
	g->version = 1;
	off = NLMSG_HDRLEN + GENL_HDRLEN;
	nla_put(buf, sizeof(buf), &off, CTRL_ATTR_FAMILY_NAME,
		NETDEV_FAMILY_NAME, sizeof(NETDEV_FAMILY_NAME));
	nlh->nlmsg_len = off;
	ret = nl_talk(nlh, fam_cb, &fa);
	if (ret < 0)
		return ret;
	family_id = fa.id;
	return family_id ? 0 : -ENOENT;
}

static void napi_parse(struct genlmsghdr *g, int len, struct napi *n)
{
	struct nlattr *nla = (struct nlattr *)((char *)g + GENL_HDRLEN);
	uint8_t u8;

	len -= GENL_HDRLEN;
	memset(n, 0, sizeof(*n));
	if (nla_get_u32(nla_find(nla, len, NETDEV_A_NAPI_IFINDEX), &n->ifindex))
		return;
	if (nla_get_u32(nla_find(nla, len, NETDEV_A_NAPI_ID), &n->id))
		return;
	nla_get_u32(nla_find(nla, len, NETDEV_A_NAPI_IRQ), &n->irq);
	nla_get_u32(nla_find(nla, len, NETDEV_A_NAPI_PID), &n->pid);
	nla_get_u32(nla_find(nla, len, NETDEV_A_NAPI_DEFER_HARD_IRQS),
		    &n->defer_hard_irqs);
	nla_get_u32(nla_find(nla, len, NETDEV_A_NAPI_GRO_FLUSH_TIMEOUT),
		    &n->gro_flush_timeout);
	nla_get_u32(nla_find(nla, len, NETDEV_A_NAPI_IRQ_SUSPEND_TIMEOUT),
		    &n->irq_suspend_timeout);
	if (!nla_get_u8(nla_find(nla, len, NETDEV_A_NAPI_THREADED), &u8)) {
		n->threaded = u8;
		n->have_threaded = 1;
	}
}

struct list_arg {
	struct napi *v;
	int n;
	int max;
	uint32_t ifindex;	/* 0 = every device */
};

static int list_cb(struct nlmsghdr *h, void *arg)
{
	struct list_arg *la = arg;
	struct genlmsghdr *g = NLMSG_DATA(h);
	struct napi n;

	napi_parse(g, h->nlmsg_len - NLMSG_HDRLEN, &n);
	if (!n.id)
		return 0;
	if (la->ifindex && n.ifindex != la->ifindex)
		return 0;
	if (la->n < la->max)
		la->v[la->n++] = n;
	return 0;
}

/* The kernel's dump does not accept an ifindex filter on every release
 * (6.17 returns -EINVAL for NAPI_GET + NETDEV_A_NAPI_IFINDEX even though the
 * spec lists the attribute), so filter in userspace: the dump is small. */
static int napi_list(uint32_t ifindex, struct napi *out, int max)
{
	struct list_arg la = { out, 0, max, ifindex };
	char buf[256] = { 0 };
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *g;
	int ret;

	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	g = NLMSG_DATA(nlh);
	g->cmd = NETDEV_CMD_NAPI_GET;
	g->version = NETDEV_FAMILY_VERSION;
	ret = nl_talk(nlh, list_cb, &la);
	if (ret < 0)
		return ret;
	return la.n;
}

static int napi_set_attr(uint32_t id, int attr, uint32_t v, int is_u8)
{
	char buf[256] = { 0 };
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *g;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	g = NLMSG_DATA(nlh);
	g->cmd = NETDEV_CMD_NAPI_SET;
	g->version = NETDEV_FAMILY_VERSION;
	off = NLMSG_HDRLEN + GENL_HDRLEN;
	nla_put_u32(buf, sizeof(buf), &off, NETDEV_A_NAPI_ID, id);
	if (is_u8)
		nla_put_u8(buf, sizeof(buf), &off, attr, (uint8_t)v);
	else
		nla_put_u32(buf, sizeof(buf), &off, attr, v);
	nlh->nlmsg_len = off;
	return nl_talk(nlh, NULL, NULL);
}

static uint32_t ifindex_of(const char *name)
{
	unsigned int idx = if_nametoindex(name);

	return idx;
}

static int cmd_list(int argc, char **argv)
{
	struct napi v[MAX_NAPI];
	uint32_t ifindex = 0;
	int n, i;

	if (argc > 0) {
		ifindex = ifindex_of(argv[0]);
		if (!ifindex) {
			fprintf(stderr, "dpd-napi-netdev: no such device '%s'\n",
				argv[0]);
			return 1;
		}
	}
	n = napi_list(ifindex, v, MAX_NAPI);
	if (n < 0) {
		fprintf(stderr, "dpd-napi-netdev: netdev family: %s\n",
			strerror(-n));
		return 2;
	}
	for (i = 0; i < n; i++) {
		printf("ifindex=%u napi=%u irq=%u pid=%u defer_hard_irqs=%u "
		       "gro_flush_timeout=%u irq_suspend_timeout=%u",
		       v[i].ifindex, v[i].id, v[i].irq, v[i].pid,
		       v[i].defer_hard_irqs, v[i].gro_flush_timeout,
		       v[i].irq_suspend_timeout);
		if (v[i].have_threaded)
			printf(" threaded=%u", v[i].threaded);
		printf("\n");
	}
	return 0;
}

static int cmd_set(int argc, char **argv)
{
	struct napi v[MAX_NAPI];
	uint32_t ifindex;
	int n, i, k, ret = 0;

	if (argc < 3 || ((argc - 1) & 1)) {
		fprintf(stderr, "usage: dpd-napi-netdev set <dev> <key> <value> [...]\n");
		return 1;
	}
	ifindex = ifindex_of(argv[0]);
	if (!ifindex) {
		fprintf(stderr, "dpd-napi-netdev: no such device '%s'\n", argv[0]);
		return 1;
	}
	for (k = 1; k < argc; k += 2) {
		if (strcmp(argv[k], "defer_hard_irqs") &&
		    strcmp(argv[k], "gro_flush_timeout") &&
		    strcmp(argv[k], "irq_suspend_timeout") &&
		    strcmp(argv[k], "threaded")) {
			fprintf(stderr, "dpd-napi-netdev: unknown key '%s'\n",
				argv[k]);
			return 1;
		}
	}
	n = napi_list(ifindex, v, MAX_NAPI);
	if (n < 0) {
		fprintf(stderr, "dpd-napi-netdev: netdev family: %s\n",
			strerror(-n));
		return 2;
	}
	if (n == 0) {
		/* no NAPI (veth, bridge, tun): not an error */
		return 0;
	}
	for (i = 0; i < n; i++) {
		for (k = 1; k < argc; k += 2) {
			uint32_t val = strtoul(argv[k + 1], NULL, 0);
			int attr, is_u8 = 0;

			if (!strcmp(argv[k], "defer_hard_irqs"))
				attr = NETDEV_A_NAPI_DEFER_HARD_IRQS;
			else if (!strcmp(argv[k], "gro_flush_timeout"))
				attr = NETDEV_A_NAPI_GRO_FLUSH_TIMEOUT;
			else if (!strcmp(argv[k], "irq_suspend_timeout"))
				attr = NETDEV_A_NAPI_IRQ_SUSPEND_TIMEOUT;
			else {
				attr = NETDEV_A_NAPI_THREADED;
				is_u8 = 1;
			}
			ret = napi_set_attr(v[i].id, attr, val, is_u8);
			if (ret < 0) {
				/* a kernel without one of the attrs must not
				 * abort the rest of the settings */
				if (ret == -EOPNOTSUPP || ret == -EINVAL)
					continue;
				fprintf(stderr,
					"dpd-napi-netdev: set napi %u %s: %s\n",
					v[i].id, argv[k], strerror(-ret));
				return 2;
			}
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	int ret;

	if (argc < 2) {
		fprintf(stderr,
			"usage: dpd-napi-netdev list [dev]\n"
			"       dpd-napi-netdev set <dev> <key> <value> [...]\n"
			"keys: defer_hard_irqs gro_flush_timeout "
			"irq_suspend_timeout threaded\n");
		return 1;
	}
	if (nl_open()) {
		fprintf(stderr, "dpd-napi-netdev: netlink: %s\n",
			strerror(errno));
		return 2;
	}
	ret = resolve_family();
	if (ret < 0) {
		fprintf(stderr, "dpd-napi-netdev: netdev family unavailable: %s\n",
			strerror(-ret));
		return 2;
	}
	if (!strcmp(argv[1], "list"))
		return cmd_list(argc - 2, argv + 2);
	if (!strcmp(argv[1], "set"))
		return cmd_set(argc - 2, argv + 2);
	fprintf(stderr, "dpd-napi-netdev: unknown command '%s'\n", argv[1]);
	return 1;
}
