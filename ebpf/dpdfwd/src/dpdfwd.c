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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

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
#define DPD_CTL "/usr/sbin/dpdctl"
#define CT_DELETE_FILE "/tmp/dpd-ct-delete"
#define DEBOUNCE_MS 300
#define PUBLISH_MS 2000

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
	unsigned long class_rules;
	unsigned long class_bad;
	unsigned long class_error;
	time_t class_applied_at;
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
		" \"class_rules\": %lu, \"class_bad\": %lu,"
		" \"class_applied_at\": %ld, \"class_error\": %lu,"
		" \"last_event\": %ld }\n",
		(long)(time(NULL) - st->started), st->link, st->addr,
		st->route, st->neigh, st->ct_new, st->ct_update,
		st->ct_destroy, st->bumps, st->unknown, st->errors,
		ct_delete_batches, st->class_rules, st->class_bad,
		(long)st->class_applied_at, st->class_error,
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
	time_t next_publish = 0, last_ct_flush = 0;

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
	}
	signal(SIGTERM, on_signal);
	signal(SIGINT, on_signal);
	st.started = time(NULL);
	mkdir(OUT_DIR, 0755);
	plugin_dry = dry;
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

					for (h = (struct nlmsghdr *)buf;
					     NLMSG_OK(h, (unsigned int)len);
					     h = NLMSG_NEXT(h, len)) {
						switch (h->nlmsg_type) {
						case RTM_NEWLINK:
						case RTM_DELLINK:
							st.link++;
							plugin_topology(DPD_EV_LINK, NULL);
							break;
						case RTM_NEWADDR:
						case RTM_DELADDR:
							st.addr++;
							plugin_topology(DPD_EV_ADDR, NULL);
							break;
						case RTM_NEWROUTE:
						case RTM_DELROUTE:
							st.route++;
							plugin_topology(DPD_EV_ROUTE, NULL);
							break;
						case RTM_NEWNEIGH:
						case RTM_DELNEIGH:
							st.neigh++;
							plugin_topology(DPD_EV_NEIGH, NULL);
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
							plugin_ct(h, DPD_EV_CT_NEW);
						} else if (msg ==
							   IPCTNL_MSG_CT_DELETE) {
							st.ct_destroy++;
							plugin_ct(h,
								  DPD_EV_CT_DESTROY);
							if (ct_delete)
								ct_queue(h);
						} else {
							st.ct_update++;
							plugin_ct(h,
								  DPD_EV_CT_UPDATE);
						}
					}
				}
			}
		}
		class_tick(&st, dry);
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
	plugin_unload();
	close(rtnl);
	if (ct >= 0)
		close(ct);
	return 0;
}
