// SPDX-License-Identifier: GPL-2.0-only
/*
 * dpdctl - userspace control for the dpd_fastpath TC BPF program.
 *
 * Deliberately narrow: map access only. Qdisc/filter (de)attachment lives in
 * files/dpd_fastpath.init because shell is easier to debug on a router and is
 * where OpenWrt users expect to find it.
 *
 * Maps are pinned by name (see dpd_fastpath.bpf.c), so the normal case is a
 * plain dpd_bpf_obj_get("/sys/fs/bpf/dpd_cfg"). When pinning was not honoured by
 * whoever loaded the object, we fall back to walking the global map id space
 * and matching on the BTF map name.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>

#include "dpd_common.h"
#include "dpd_bpf.h"

/* monotonic ms, to compare against values stored by bpf_ktime_get_ns() */
static uint64_t mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Age of a dpd_flow_val: the BPF side stores CLOCK_MONOTONIC truncated to 32
 * bits of milliseconds, so the difference has to be taken modulo 2^32 and read
 * as signed (see dpd_flow_val in dpd_common.h). Negative means "timestamp in
 * the future", i.e. the entry predates one 49.7-day wrap: report it as stale. */
static uint64_t flow_age_ms(uint32_t last_seen_ms)
{
	uint32_t now = (uint32_t)(mono_ns() / 1000000ULL);
	int32_t age = (int32_t)(now - last_seen_ms);

	return age > 0 ? (uint64_t)age : 0;
}

static const char *pin_path(const char *name)
{
	static char buf[128];

	snprintf(buf, sizeof(buf), "%s/%s", DPD_PIN_DIR, name);
	return buf;
}

/* Open a map: try the pin first, then scan map ids for a matching BTF name. */
static int map_open(const char *name)
{
	int fd = dpd_bpf_obj_get(pin_path(name));

	if (fd >= 0)
		return fd;

	for (uint32_t id = 0;;) {
		struct bpf_map_info info = {};
		uint32_t len = sizeof(info);

		if (dpd_bpf_map_get_next_id(id, &id))
			break;
		fd = dpd_bpf_map_get_fd_by_id(id);
		if (fd < 0)
			continue;
		if (dpd_bpf_map_get_info_by_fd(fd, &info, &len) == 0 &&
		    !strcmp((char *)info.name, name))
			return fd;
		close(fd);
	}
	fprintf(stderr, "dpdctl: map '%s' not found (is the program attached?)\n",
		name);
	return -1;
}

static int cfg_read(int fd, struct dpd_config *cfg)
{
	uint32_t k = 0;
	int n = dpd_num_possible_cpus();
	struct dpd_cpu *buf;

	if (n <= 0)
		n = 1;
	buf = calloc((size_t)n, sizeof(*buf));
	if (!buf)
		return -1;
	if (dpd_bpf_map_lookup_elem(fd, &k, buf)) {
		free(buf);
		return -1;
	}
	/* every CPU's copy holds the same config (cfg_write keeps them in
	 * step), so the first block is authoritative for readers. */
	*cfg = buf[0].cfg;
	free(buf);
	return 0;
}

/*
 * Write the config for every CPU. The value is a per-CPU block that also holds
 * the counters, and a map update replaces the whole value -- so this is a
 * read-modify-write: keep .stats from the current block and change only .cfg.
 * Without that, `dpdctl set mode ...` would silently zero every counter.
 */
static int cfg_write(int fd, const struct dpd_config *cfg)
{
	uint32_t k = 0;
	int n = dpd_num_possible_cpus();
	struct dpd_cpu *buf;
	int r;

	if (n <= 0)
		n = 1;
	buf = calloc((size_t)n, sizeof(*buf));
	if (!buf)
		return -1;
	/* A failed lookup (fresh map) leaves the zeroed buffer, which is the
	 * correct initial state. */
	dpd_bpf_map_lookup_elem(fd, &k, buf);
	for (int i = 0; i < n; i++)
		buf[i].cfg = *cfg;
	r = dpd_bpf_map_update_elem(fd, &k, buf, BPF_ANY);
	free(buf);
	return r;
}

static const char *ifname(uint32_t ifindex)
{
	static char buf[IF_NAMESIZE];

	if (!if_indextoname(ifindex, buf))
		snprintf(buf, sizeof(buf), "if%u", ifindex);
	return buf;
}

static const char *mode_name(uint32_t m)
{
	switch (m) {
	case DPD_MODE_OFF:		return "off";
	case DPD_MODE_OBSERVE:		return "observe";
	case DPD_MODE_STATELESS:	return "stateless";
	case DPD_MODE_STATEFUL:		return "stateful";
	case DPD_MODE_NEIGH_PROBE:	return "neigh-probe";
	default:			return "?";
	}
}

static int mode_parse(const char *s, uint32_t *out)
{
	if (!strcmp(s, "off"))			*out = DPD_MODE_OFF;
	else if (!strcmp(s, "observe"))		*out = DPD_MODE_OBSERVE;
	else if (!strcmp(s, "stateless"))	*out = DPD_MODE_STATELESS;
	else if (!strcmp(s, "stateful"))	*out = DPD_MODE_STATEFUL;
	else if (!strcmp(s, "neigh-probe"))	*out = DPD_MODE_NEIGH_PROBE;
	else return -1;
	return 0;
}

static const char *policy_name(uint32_t p)
{
	switch (p) {
	case DPD_POLICY_ALLOW_ALL:	return "allow-all";
	case DPD_POLICY_VLANS_ONLY:	return "vlans-only";
	default:			return "?";
	}
}

static int policy_parse(const char *s, uint32_t *out)
{
	if (!strcmp(s, "allow-all") || !strcmp(s, "allow_all"))	*out = DPD_POLICY_ALLOW_ALL;
	else if (!strcmp(s, "vlans-only") || !strcmp(s, "vlans_only"))	*out = DPD_POLICY_VLANS_ONLY;
	else return -1;
	return 0;
}

static const char *stat_name(int i)
{
	static const char *n[ST__MAX] = {
		"pkt_total", "bytes", "non_ip", "fib_ok", "fib_fail",
		"redirect_ok", "neigh_ok", "neigh_fail", "flow_hit",
		"flow_miss", "flow_write", "ttl_drop", "local",
		"v6_skip", "vlan_skip", "frag_skip", "dns_skip", "fib_retry",
		"dhcp_skip", "bcast_skip", "v6_ok", "mss_clamp", "mss_skip",
		"tag_pop", "tag_skip",
	};

	return (i >= 0 && i < ST__MAX && n[i]) ? n[i] : "?";
}

/* ---- commands ---------------------------------------------------------- */

static int cmd_set(int argc, char **argv)
{
	struct dpd_config cfg = {};
	int fd;

	if (argc < 2) {
		fprintf(stderr, "usage: dpdctl set "
			"<mode M | enable E | redirect R | ttl MS | policy P>\n");
		return 1;
	}
	fd = map_open("dpd_cfg");
	if (fd < 0)
		return 1;
	if (cfg_read(fd, &cfg)) {
		fprintf(stderr, "dpdctl: read dpd_cfg: %s\n", strerror(errno));
		return 1;
	}

	if (!strcmp(argv[0], "mode")) {
		if (mode_parse(argv[1], &cfg.mode)) {
			fprintf(stderr, "dpdctl: bad mode '%s'\n", argv[1]);
			return 1;
		}
	} else if (!strcmp(argv[0], "enable")) {
		cfg.enable = strtoul(argv[1], NULL, 0);
	} else if (!strcmp(argv[0], "redirect")) {
		if (!strcmp(argv[1], "auto"))
			cfg.redirect = DPD_REDIR_AUTO;
		else if (!strcmp(argv[1], "neigh"))
			cfg.redirect = DPD_REDIR_FORCE_NEIGH;
		else if (!strcmp(argv[1], "dev"))
			cfg.redirect = DPD_REDIR_FORCE_DEV;
		else {
			fprintf(stderr, "dpdctl: bad redirect '%s'\n", argv[1]);
			return 1;
		}
	} else if (!strcmp(argv[0], "ttl")) {
		cfg.flow_ttl_ms = strtoul(argv[1], NULL, 0);
	} else if (!strcmp(argv[0], "refresh")) {
		cfg.flow_refresh_ms = strtoul(argv[1], NULL, 0);
	} else if (!strcmp(argv[0], "epoch")) {
		cfg.epoch = strtoul(argv[1], NULL, 0) & 0xff;
	} else if (!strcmp(argv[0], "ipv6")) {
		cfg.ipv6 = strtoul(argv[1], NULL, 0) ? 1 : 0;
	} else if (!strcmp(argv[0], "mss")) {
		cfg.mss_clamp = strtoul(argv[1], NULL, 0) ? 1 : 0;
	} else if (!strcmp(argv[0], "policy")) {
		if (policy_parse(argv[1], &cfg.policy)) {
			fprintf(stderr, "dpdctl: bad policy '%s'\n", argv[1]);
			return 1;
		}
	} else {
		fprintf(stderr, "dpdctl: unknown key '%s'\n", argv[0]);
		return 1;
	}

	cfg.abi_version = DPD_ABI_VERSION;
	if (cfg_write(fd, &cfg)) {
		fprintf(stderr, "dpdctl: write dpd_cfg: %s\n", strerror(errno));
		return 1;
	}
	return 0;
}

static int cmd_show(void)
{
	struct dpd_config cfg = {};
	struct dpd_flow_key k, nk;
	struct bpf_map_info info = {};
	uint32_t len = sizeof(info);
	int fd;
	int have_k = 0;

	fd = map_open("dpd_cfg");
	if (fd < 0)
		return 1;
	if (cfg_read(fd, &cfg)) {
		fprintf(stderr, "dpdctl: read dpd_cfg: %s\n", strerror(errno));
		return 1;
	}
	printf("abi_version  %u\n", cfg.abi_version);
	printf("enable       %u\n", cfg.enable);
	printf("mode         %s (%u)\n", mode_name(cfg.mode), cfg.mode);
	printf("redirect     %u\n", cfg.redirect);
	printf("flow_ttl_ms  %u\n", cfg.flow_ttl_ms);
	printf("policy       %s (%u)\n", policy_name(cfg.policy), cfg.policy);
	printf("epoch        %u\n", cfg.epoch);
	printf("flow_refresh %u ms%s\n", cfg.flow_refresh_ms,
	       cfg.flow_refresh_ms ? "" : " (every packet)");
	printf("ipv6         %u%s\n", cfg.ipv6,
	       cfg.ipv6 ? "" : " (IPv4 only)");

	fd = map_open("dpd_vlans");
	if (fd >= 0) {
		uint16_t vk, vn;
		int nv = 0;

		printf("vlans        ");
		if (!dpd_bpf_map_get_next_key(fd, NULL, &vk)) {
			for (;;) {
				printf("%u ", vk);
				nv++;
				if (dpd_bpf_map_get_next_key(fd, &vk, &vn))
					break;
				vk = vn;
			}
		}
		if (!nv)
			printf("(none -- nothing is eligible in vlans-only)");
		printf("\n");
		close(fd);
	}

	fd = map_open("dpd_iface");
	if (fd < 0)
		return 0;
	printf("iface flags:\n");
	if (dpd_bpf_map_get_next_key(fd, NULL, &k))
		return 0;
	for (;;) {
		uint32_t v = 0;

		if (!dpd_bpf_map_lookup_elem(fd, &k, &v))
			printf("  %-16s 0x%08x%s%s%s%s\n", ifname(k.ifindex), v,
			       v & DPD_IF_F_UP ? " UP" : "",
			       v & DPD_IF_F_NOARP ? " NOARP" : "",
			       v & DPD_IF_F_POINTOPOINT ? " POINTOPOINT" : "",
			       v & DPD_IF_F_LOWER ? " LOWER" : "");
		if (dpd_bpf_map_get_next_key(fd, &k, &nk))
			break;
		k = nk;
		have_k = 1;
	}
	(void)have_k;
	(void)len;
	return 0;
}

static int stats_read(uint64_t *out);

static int cmd_stats(void)
{
	uint64_t st[ST__MAX] = {};

	if (stats_read(st)) {
		fprintf(stderr, "dpdctl: read dpd_stats: %s\n", strerror(errno));
		return 1;
	}
	printf("  idx  %-13s %s\n", "name", "total");
	for (uint32_t i = 0; i < ST__MAX; i++)
		printf("  %3u  %-13s %llu\n", i, stat_name((int)i),
		       (unsigned long long)st[i]);
	return 0;
}

/* Print the ABI version the *loaded object* was built with (0 when no map is
 * pinned). The init script compares this with the version installed by the
 * package and drops stale pins when they differ: a map whose value layout
 * changed cannot be reused in place. */
static int cmd_abi(void)
{
	struct dpd_config cfg = {};
	int fd = map_open("dpd_cfg");

	if (fd < 0) {
		printf("0\n");
		return 0;
	}
	if (cfg_read(fd, &cfg)) {
		printf("0\n");
		return 0;
	}
	printf("%u\n", cfg.abi_version);
	return 0;
}

/* Move the flow-cache generation. Every entry remembers the epoch it was
 * learned in; bumping it makes the whole cache stale in one store, without
 * walking 16k entries from userspace. Called on link/address/route/neighbour
 * changes and whenever the multi-WAN table is rewritten. */
static int cmd_bump(void)
{
	struct dpd_config cfg = {};
	int fd = map_open("dpd_cfg");

	if (fd < 0)
		return 1;
	if (cfg_read(fd, &cfg)) {
		fprintf(stderr, "dpdctl: read dpd_cfg: %s\n", strerror(errno));
		return 1;
	}
	cfg.epoch = (cfg.epoch + 1) & 0xff;
	cfg.abi_version = DPD_ABI_VERSION;
	if (cfg_write(fd, &cfg)) {
		fprintf(stderr, "dpdctl: write dpd_cfg: %s\n", strerror(errno));
		return 1;
	}
	printf("%u\n", cfg.epoch);
	return 0;
}

/*
 * Learn each iface's L2 capabilities from /sys/class/net so the BPF AUTO
 * redirect decision does not have to guess. ppp is the interesting case:
 * IFF_POINTOPOINT|IFF_NOARP means there is no neighbour table and no L2 header
 * to rewrite, so AUTO must fall back to bpf_redirect().
 */
static int cmd_ifaces(int argc, char **argv)
{
	int fd, mfd;

	if (argc == 0) {
		fprintf(stderr, "usage: dpdctl ifaces <ifname>...\n");
		return 1;
	}
	fd = map_open("dpd_iface");
	if (fd < 0)
		return 1;
	/* ABI 11: the MSS clamp needs each egress device's MTU. Optional on
	 * purpose -- an older object has no dpd_mtu map, and then the clamp
	 * degrades to "count a skip" instead of breaking the attach. */
	mfd = map_open("dpd_mtu");
	if (mfd < 0) {
		fprintf(stderr,
			"dpdctl: no dpd_mtu map (object older than ABI 11); "
			"MSS clamp will stay inactive\n");
		mfd = -1;
	}

	for (int i = 0; i < argc; i++) {
		char path[256];
		uint32_t ifindex = if_nametoindex(argv[i]);
		uint32_t v = 0, mtu = 0;
		FILE *f;
		unsigned long flags = 0;
		unsigned long iflink = 0;

		if (!ifindex) {
			fprintf(stderr, "dpdctl: no such iface '%s'\n", argv[i]);
			continue;
		}
		snprintf(path, sizeof(path), "/sys/class/net/%s/flags", argv[i]);
		f = fopen(path, "r");
		if (!f || fscanf(f, "%lx", (unsigned long *)&flags) != 1) {
			if (f)
				fclose(f);
			fprintf(stderr, "dpdctl: cannot read %s\n", path);
			continue;
		}
		fclose(f);

		/* iflink != ifindex: the device is stacked on a lower one (vlan,
		 * macvlan, veth, tunnel). dev_hard_header() does real work for
		 * those, so the BPF side must not write the L2 header itself. */
		snprintf(path, sizeof(path), "/sys/class/net/%s/iflink", argv[i]);
		f = fopen(path, "r");
		if (f) {
			if (fscanf(f, "%lx", &iflink) != 1)
				iflink = 0;
			fclose(f);
		}

		snprintf(path, sizeof(path), "/sys/class/net/%s/mtu", argv[i]);
		f = fopen(path, "r");
		if (f) {
			if (fscanf(f, "%u", &mtu) != 1)
				mtu = 0;
			fclose(f);
		}

		if (flags & IFF_UP)		v |= DPD_IF_F_UP;
		if (flags & IFF_NOARP)		v |= DPD_IF_F_NOARP;
		if (flags & IFF_POINTOPOINT)	v |= DPD_IF_F_POINTOPOINT;
		if (iflink && iflink != ifindex) v |= DPD_IF_F_LOWER;

		if (dpd_bpf_map_update_elem(fd, &ifindex, &v, BPF_ANY)) {
			fprintf(stderr, "dpdctl: update dpd_iface[%s]: %s\n",
				argv[i], strerror(errno));
			return 1;
		}
		if (mfd >= 0 && mtu &&
		    dpd_bpf_map_update_elem(mfd, &ifindex, &mtu, BPF_ANY))
			fprintf(stderr, "dpdctl: update dpd_mtu[%s]: %s\n",
				argv[i], strerror(errno));

		printf("%-16s ifindex=%-4u mtu=%-5u flags=0x%08x%s%s%s%s\n",
		       argv[i], ifindex, mtu, v,
		       v & DPD_IF_F_UP ? " UP" : "",
		       v & DPD_IF_F_NOARP ? " NOARP" : "",
		       v & DPD_IF_F_POINTOPOINT ? " POINTOPOINT" : "",
		       v & DPD_IF_F_LOWER ? " LOWER" : "");
	}
	if (mfd >= 0)
		close(mfd);
	return 0;
}

static int cmd_flows(int argc, char **argv)
{
	struct dpd_flow_key k, nk;
	struct dpd_flow_val v;
	int fd, n = 0, max = 32;

	if (argc >= 1 && !strcmp(argv[0], "-a"))
		max = 1 << 20;
	fd = map_open("dpd_flows");
	if (fd < 0)
		return 1;
	if (dpd_bpf_map_get_next_key(fd, NULL, &k))
		return 0;
	for (;;) {
		if (!dpd_bpf_map_lookup_elem(fd, &k, &v)) {
			uint64_t age_ms = flow_age_ms(v.last_seen_ms);

			printf("%-10s fam=%u proto=%u egress=%-10s wan=%u epoch=%u "
			       "cls=%s age=%llums "
			       "dmac=%02x:%02x:%02x:%02x:%02x:%02x "
			       "smac=%02x:%02x:%02x:%02x:%02x:%02x%s\n",
			       ifname(k.ifindex), k.family, k.proto,
			       ifname(v.egress_ifindex),
			       (unsigned)(v.wan & 0xff),
			       (unsigned)((v.wan & DPD_FLOW_EPOCH_MASK) >> 8),
			       (v.flags & DPD_FLOW_F_L2) ? "l2" :
			       (v.flags & DPD_FLOW_F_DEV) ? "dev" : "neigh",
			       (unsigned long long)age_ms,
			       v.dmac[0], v.dmac[1], v.dmac[2],
			       v.dmac[3], v.dmac[4], v.dmac[5],
			       v.smac[0], v.smac[1], v.smac[2],
			       v.smac[3], v.smac[4], v.smac[5],
			       (v.flags & DPD_FLOW_F_NO_NEIGH) ? " no-neigh" : "");
			if (++n >= max)
				break;
		}
		if (dpd_bpf_map_get_next_key(fd, &k, &nk))
			break;
		k = nk;
	}
	printf("flows shown: %d\n", n);
	return 0;
}

/*
 * dpd_vlans: the segment allow-list consulted only in vlans-only policy.
 * Populated from files/dpd_fastpath.config by the init script, so a reboot
 * restores the list without anyone running dpdctl by hand.
 */
static int cmd_vlan(int argc, char **argv)
{
	int fd;

	if (argc < 1) {
		fprintf(stderr, "usage: dpdctl vlan <add ID | del ID | "
			"list | flush>\n");
		return 1;
	}
	fd = map_open("dpd_vlans");
	if (fd < 0)
		return 1;

	if (!strcmp(argv[0], "add")) {
		uint16_t id = (uint16_t)strtoul(argv[1], NULL, 0);
		uint8_t one = 1;

		if (argc < 2) {
			fprintf(stderr, "dpdctl: vlan add needs an id\n");
			return 1;
		}
		if (id > 4094) {
			fprintf(stderr, "dpdctl: bad vlan id %u\n", id);
			return 1;
		}
		if (dpd_bpf_map_update_elem(fd, &id, &one, BPF_ANY)) {
			fprintf(stderr, "dpdctl: vlan add %u: %s\n", id,
				strerror(errno));
			return 1;
		}
		printf("vlan %u added\n", id);
	} else if (!strcmp(argv[0], "del")) {
		uint16_t id;

		if (argc < 2) {
			fprintf(stderr, "dpdctl: vlan del needs an id\n");
			return 1;
		}
		id = (uint16_t)strtoul(argv[1], NULL, 0);
		if (dpd_bpf_map_delete_elem(fd, &id) && errno != ENOENT) {
			fprintf(stderr, "dpdctl: vlan del %u: %s\n", id,
				strerror(errno));
			return 1;
		}
		printf("vlan %u deleted\n", id);
	} else if (!strcmp(argv[0], "flush")) {
		uint16_t k, n;

		if (dpd_bpf_map_get_next_key(fd, NULL, &k))
			return 0;
		for (;;) {
			dpd_bpf_map_delete_elem(fd, &k);
			if (dpd_bpf_map_get_next_key(fd, &k, &n))
				break;
			k = n;
		}
		printf("vlans flushed\n");
	} else if (!strcmp(argv[0], "list")) {
		uint16_t k, n;
		int cnt = 0;

		if (dpd_bpf_map_get_next_key(fd, NULL, &k))
			return 0;
		for (;;) {
			printf("vlan %u\n", k);
			cnt++;
			if (dpd_bpf_map_get_next_key(fd, &k, &n))
				break;
			k = n;
		}
		fprintf(stderr, "(%d entries)\n", cnt);
	} else {
		fprintf(stderr, "dpdctl: unknown vlan subcommand '%s'\n", argv[0]);
		return 1;
	}
	return 0;
}

/* Sum the per-CPU counter blocks into out[]. ABI 12: the counters live in the
 * same per-CPU value as the config, so one lookup returns every CPU's block. */
static int stats_read(uint64_t *out)
{
	uint32_t k = 0;
	int fd, ncpu;
	struct dpd_cpu *buf;

	fd = map_open("dpd_cfg");
	if (fd < 0)
		return -1;
	ncpu = dpd_num_possible_cpus();
	if (ncpu <= 0)
		ncpu = 1;
	buf = calloc((size_t)ncpu, sizeof(*buf));
	if (!buf) {
		close(fd);
		return -1;
	}
	if (dpd_bpf_map_lookup_elem(fd, &k, buf)) {
		free(buf);
		close(fd);
		return -1;
	}
	for (uint32_t i = 0; i < ST__MAX; i++) {
		uint64_t sum = 0;

		for (int c = 0; c < ncpu; c++)
			sum += buf[c].stats.v[i];
		out[i] = sum;
	}
	free(buf);
	close(fd);
	return 0;
}

/* ---- status ------------------------------------------------------------- */

static const char *redirect_name(uint32_t r)
{
	switch (r) {
	case DPD_REDIR_AUTO:		return "auto";
	case DPD_REDIR_FORCE_NEIGH:	return "neigh";
	case DPD_REDIR_FORCE_DEV:	return "dev";
	default:			return "?";
	}
}

static long read_text_file(const char *path, char *buf, size_t n)
{
	FILE *f = fopen(path, "r");
	size_t r;

	if (!f)
		return -1;
	r = fread(buf, 1, n - 1, f);
	fclose(f);
	buf[r] = '\0';
	return (long)r;
}

/* Is this buffer one JSON object? The gate file is written by shell, so a
 * half-written file (or an older one) must not be pasted into our output:
 * only a leading '{' and a trailing '}' are accepted, the caller otherwise
 * omits the key. */
static int looks_like_json_object(const char *s)
{
	const char *p = s, *q;

	while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
		p++;
	if (*p != '{')
		return 0;
	q = p + strlen(p) - 1;
	while (q > p && (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r'))
		q--;
	return *q == '}';
}

static int map_count(int fd, uint32_t key_size)
{
	unsigned char key[64], next[64];
	int n = 0;

	if (!key_size || key_size > sizeof(key))
		return -1;
	if (dpd_bpf_map_get_next_key(fd, NULL, key))
		return 0;
	for (;;) {
		n++;
		if (n > 65536)
			break;
		if (dpd_bpf_map_get_next_key(fd, key, next))
			break;
		memcpy(key, next, key_size);
	}
	return n;
}

/* One map's capacity (and, for the small tables, its occupancy). */
static void map_limits(const char *name, uint32_t *max_entries, int *entries)
{
	struct bpf_map_info info = {};
	uint32_t len = sizeof(info);
	int fd = map_open(name);

	*max_entries = 0;
	*entries = -1;
	if (fd < 0)
		return;
	if (dpd_bpf_map_get_info_by_fd(fd, &info, &len) == 0) {
		*max_entries = info.max_entries;
		/* dpd_flows is an LRU hash with 16k entries: walking it on every
		 * status poll would cost more than the answer is worth, and the
		 * LRU evicts anyway, so occupancy is not a stable fact. */
		if (strcmp(name, "dpd_flows"))
			*entries = map_count(fd, info.key_size);
	}
	close(fd);
}

static void json_string(const char *s)
{
	putchar('"');
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;

		if (c == '"' || c == '\\')
			printf("\\%c", c);
		else if (c < 0x20)
			printf("\\u%04x", c);
		else
			putchar(c);
	}
	putchar('"');
}

static void json_iface_flags(uint32_t v)
{
	int first = 1;

	putchar('"');
#define DPD_FLAG(n, bit)						\
	do {								\
		if (v & (bit)) {					\
			printf("%s%s", first ? "" : " ", (n));		\
			first = 0;					\
		}							\
	} while (0)
	DPD_FLAG("UP", DPD_IF_F_UP);
	DPD_FLAG("NOARP", DPD_IF_F_NOARP);
	DPD_FLAG("POINTOPOINT", DPD_IF_F_POINTOPOINT);
	DPD_FLAG("LOWER", DPD_IF_F_LOWER);
#undef DPD_FLAG
	putchar('"');
}

static int status_json(void)
{
	struct dpd_config cfg = {};
	uint64_t st[ST__MAX] = {};
	struct dpd_flow_key k, nk;
	struct dpd_wan_tbl tbl = {};
	char gate[8192];
	long glen = read_text_file(DPD_GATE_FILE, gate, sizeof(gate));
	uint32_t max;
	int cnt, fd, first;
	int have_cfg;
	int have_wans = 0;

	fd = map_open("dpd_cfg");
	have_cfg = fd >= 0 && cfg_read(fd, &cfg) == 0;
	if (fd >= 0)
		close(fd);

	/* read the uplink table once: both the maps block (entries) and the
	 * wans array below report it. */
	fd = map_open("dpd_wans");
	if (fd >= 0) {
		uint32_t zero = 0;

		have_wans = dpd_bpf_map_lookup_elem(fd, &zero, &tbl) == 0;
		close(fd);
	}

	printf("{\n");
	printf("  \"tool\": \"dpdctl\",\n");
	printf("  \"abi\": %u,\n", DPD_ABI_VERSION);
	printf("  \"attached\": %s,\n", have_cfg ? "true" : "false");
	printf("  \"loaded_abi\": %u,\n", have_cfg ? cfg.abi_version : 0);

	printf("  \"cfg\": ");
	if (have_cfg) {
		printf("{ \"enable\": %u, \"mode\": ", cfg.enable);
		json_string(mode_name(cfg.mode));
		printf(", \"redirect\": ");
		json_string(redirect_name(cfg.redirect));
		printf(", \"flow_ttl_ms\": %u, \"flow_refresh_ms\": %u",
		       cfg.flow_ttl_ms, cfg.flow_refresh_ms);
		printf(", \"ipv6\": %u, \"mss_clamp\": %u, \"epoch\": %u",
		       cfg.ipv6, cfg.mss_clamp, cfg.epoch);
		printf(", \"policy\": ");
		json_string(policy_name(cfg.policy));
		printf(" },\n");
	} else {
		printf("null,\n");
	}

	printf("  \"maps\": {\n");
	map_limits("dpd_flows", &max, &cnt);
	/* occupancy of the 16k LRU is deliberately not walked; max_entries is
	 * what tells a reader whether the table is undersized. */
	printf("    \"flows\": { \"max_entries\": %u, \"entries\": null },\n", max);
	map_limits("dpd_iface", &max, &cnt);
	printf("    \"iface\": { \"max_entries\": %u, \"entries\": %d },\n",
	       max, cnt);
	map_limits("dpd_mtu", &max, &cnt);
	printf("    \"mtu\": { \"max_entries\": %u, \"entries\": %d },\n",
	       max, cnt);
	map_limits("dpd_vlans", &max, &cnt);
	printf("    \"vlans\": { \"max_entries\": %u, \"entries\": %d },\n",
	       max, cnt);
	map_limits("dpd_wans", &max, &cnt);
	/* dpd_wans is an ARRAY map with max_entries 1: counting its keys always
	 * says "1". What a reader wants is how many uplinks the table holds. */
	printf("    \"wans\": { \"max_entries\": %u, \"entries\": ", max);
	if (have_wans)
		printf("%u", tbl.count);
	else
		printf("null");
	printf(" }\n");
	printf("  },\n");

	printf("  \"ifaces\": [");
	first = 1;
	fd = map_open("dpd_iface");
	if (fd >= 0) {
		int mfd = map_open("dpd_mtu");

		if (!dpd_bpf_map_get_next_key(fd, NULL, &k)) {
			for (;;) {
				uint32_t v = 0, mtu = 0;

				if (!dpd_bpf_map_lookup_elem(fd, &k, &v)) {
					if (mfd >= 0)
						dpd_bpf_map_lookup_elem(mfd, &k.ifindex,
									&mtu);
					printf("%s\n    { \"name\": ", first ? "" : ",");
					json_string(ifname(k.ifindex));
					printf(", \"ifindex\": %u, \"mtu\": %u, \"flags\": ",
					       k.ifindex, mtu);
					json_iface_flags(v);
					printf(" }");
					first = 0;
				}
				if (dpd_bpf_map_get_next_key(fd, &k, &nk))
					break;
				k = nk;
			}
		}
		if (mfd >= 0)
			close(mfd);
		close(fd);
	}
	printf("%s],\n", first ? "" : "\n  ");

	printf("  \"vlans\": [");
	first = 1;
	fd = map_open("dpd_vlans");
	if (fd >= 0) {
		uint16_t vk, vn;

		if (!dpd_bpf_map_get_next_key(fd, NULL, &vk)) {
			for (;;) {
				printf("%s%u", first ? "" : ", ", vk);
				first = 0;
				if (dpd_bpf_map_get_next_key(fd, &vk, &vn))
					break;
				vk = vn;
			}
		}
		close(fd);
	}
	printf("],\n");

	printf("  \"wans\": [");
	first = 1;
	if (have_wans) {
		for (uint32_t i = 0; i < DPD_WAN_MAX && i < tbl.count; i++) {
			struct dpd_wan *w = &tbl.wan[i];

			if (!w->ifindex && !w->weight)
				continue;
			printf("%s\n    { \"index\": %u, \"ifname\": ",
			       first ? "" : ",", i + 1);
			json_string(ifname(w->ifindex));
			printf(", \"ifindex\": %u, \"mark\": %u, "
			       "\"weight\": %u, \"up\": %s }",
			       w->ifindex, w->mark, w->weight,
			       (w->flags & DPD_WAN_F_UP) ? "true" : "false");
			first = 0;
		}
	}
	printf("%s],\n", first ? "" : "\n  ");

	printf("  \"stats\": {");
	if (stats_read(st) == 0) {
		for (uint32_t i = 0; i < ST__MAX; i++)
			printf("%s\"%s\": %llu", i ? ", " : " ",
			       stat_name((int)i), (unsigned long long)st[i]);
		printf(" },\n");
	} else {
		printf(" null,\n");
	}

	if (glen > 0 && looks_like_json_object(gate)) {
		/* the file ends with a newline; trimming it keeps the outer object
		 * readable (and the blank line out of the JSON) */
		char *endp = gate + strlen(gate);

		while (endp > gate && isspace((unsigned char)endp[-1]))
			*--endp = '\0';
		printf("  \"gate\": %s\n", gate);
	} else {
		printf("  \"gate\": null\n");
	}
	printf("}\n");
	return 0;
}

static int status_text(void)
{
	struct dpd_config cfg = {};
	uint64_t st[ST__MAX] = {};
	char txt[8192];
	char *line[4] = { NULL };
	struct dpd_flow_key k, nk;
	uint32_t max;
	int cnt;
	int fd = map_open("dpd_cfg");

	printf("dpd status\n");
	if (fd < 0 || cfg_read(fd, &cfg)) {
		printf("  attached      no (no dpd_cfg pin; is the program loaded?)\n");
		if (fd >= 0)
			close(fd);
		return 0;
	}
	close(fd);

	printf("  attached      yes (ABI %u loaded, %u built)\n",
	       cfg.abi_version, DPD_ABI_VERSION);
	printf("  mode          %s (effective; the requested mode is in the gate)\n",
	       mode_name(cfg.mode));
	printf("  enable        %u\n", cfg.enable);
	printf("  redirect      %s\n", redirect_name(cfg.redirect));
	printf("  policy        %s\n", policy_name(cfg.policy));
	printf("  ttl/refresh   %u ms / %u ms%s\n", cfg.flow_ttl_ms,
	       cfg.flow_refresh_ms, cfg.flow_refresh_ms ? "" : " (every packet)");
	printf("  ipv6          %u\n", cfg.ipv6);
	printf("  mss_clamp     %s\n", cfg.mss_clamp ? "on" : "off");
	printf("  epoch         %u\n", cfg.epoch);

	/* Gate: four lines requested/effective/code/reason (DPD_GATE_TEXT). */
	if (read_text_file(DPD_GATE_TEXT, txt, sizeof(txt)) > 0) {
		char *p = txt;

		for (int i = 0; i < 4 && p; i++) {
			line[i] = p;
			char *nl = strchr(p, '\n');

			if (nl) {
				*nl = '\0';
				p = nl + 1;
			} else {
				p = NULL;
			}
		}
		printf("  gate          %s (%s)\n", line[1] ? line[1] : "?",
		       line[2] ? line[2] : "?");
		if (line[3] && *line[3])
			printf("  gate reason   %s\n", line[3]);
	} else {
		printf("  gate          unknown (no %s yet)\n", DPD_GATE_TEXT);
	}

	map_limits("dpd_flows", &max, &cnt);
	printf("  flow cache    %u max (LRU)\n", max);
	map_limits("dpd_mtu", &max, &cnt);
	printf("  mtu table     %d/%u\n", cnt, max);

	printf("  ifaces\n");
	fd = map_open("dpd_iface");
	if (fd >= 0) {
		int mfd = map_open("dpd_mtu");

		if (!dpd_bpf_map_get_next_key(fd, NULL, &k)) {
			for (;;) {
				uint32_t v = 0, mtu = 0;

				if (!dpd_bpf_map_lookup_elem(fd, &k, &v)) {
					if (mfd >= 0)
						dpd_bpf_map_lookup_elem(mfd, &k.ifindex,
									&mtu);
					printf("    %-16s mtu=%-5u%s%s%s%s\n",
					       ifname(k.ifindex), mtu,
					       v & DPD_IF_F_UP ? " UP" : "",
					       v & DPD_IF_F_NOARP ? " NOARP" : "",
					       v & DPD_IF_F_POINTOPOINT ? " POINTOPOINT" : "",
					       v & DPD_IF_F_LOWER ? " LOWER" : "");
				}
				if (dpd_bpf_map_get_next_key(fd, &k, &nk))
					break;
				k = nk;
			}
		}
		if (mfd >= 0)
			close(mfd);
		close(fd);
	}

	if (stats_read(st) == 0) {
		printf("  counters      pkt=%llu flow_hit=%llu flow_miss=%llu "
		       "mss_clamp=%llu\n",
		       (unsigned long long)st[ST_PKT_TOTAL],
		       (unsigned long long)st[ST_FLOW_HIT],
		       (unsigned long long)st[ST_FLOW_MISS],
		       (unsigned long long)st[ST_MSS_CLAMP]);
		printf("                redirect=%llu neigh=%llu fib_ok=%llu "
		       "fib_fail=%llu\n",
		       (unsigned long long)st[ST_REDIRECT_OK],
		       (unsigned long long)st[ST_NEIGH_OK],
		       (unsigned long long)st[ST_FIB_OK],
		       (unsigned long long)st[ST_FIB_FAIL]);
	} else {
		printf("  counters      unavailable\n");
	}
	return 0;
}

static int cmd_status(int argc, char **argv)
{
	for (int i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-j") || !strcmp(argv[i], "--json"))
			return status_json();
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			printf("usage: dpdctl status [-j]\n");
			return 0;
		}
		fprintf(stderr, "dpdctl: unknown status option '%s'\n", argv[i]);
		return 1;
	}
	return status_text();
}

static void usage(const char *argv0)
{
		fprintf(stderr,
		"usage: %s <command>\n"
		"  status [-j]             one-screen status (human, or JSON for\n"
		"                          scripts/LuCI: cfg, gate, maps, counters)\n"
		"  show                    dump dpd_cfg + dpd_iface + dpd_vlans\n"
		"  set mode <off|observe|stateless|stateful|neigh-probe>\n"
		"  set enable <0|1>\n"
		"  set redirect <auto|neigh|dev>\n"
		"  set ttl <ms>\n"
		"  set refresh <ms>        0 = touch the flow timestamp on every packet\n"
		"  set ipv6 <0|1>          accelerate IPv6 TCP/UDP too (default 0)\n"
		"  set mss <0|1>           clamp TCP MSS to the egress MTU (default 1)\n"
		"  set policy <allow-all|vlans-only>\n"
		"  bump                    move the flow-cache epoch (drop all cached\n"
		"                          egress decisions without a map walk)\n"
		"  abi                     print the ABI of the loaded object (0 = none)\n"
		"  vlan add <id>|del <id>|list|flush\n"
		"  stats                   per-reason counters (all cpus summed)\n"
		"  ifaces <ifname>...      learn IFF_* flags and MTU into the maps\n"
		"  flows [-a]              dump dpd_flows\n",
		argv0);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}
	if (!strcmp(argv[1], "show"))
		return cmd_show();
	if (!strcmp(argv[1], "status"))
		return cmd_status(argc - 2, argv + 2);
	if (!strcmp(argv[1], "set"))
		return cmd_set(argc - 2, argv + 2);
	if (!strcmp(argv[1], "vlan"))
		return cmd_vlan(argc - 2, argv + 2);
	if (!strcmp(argv[1], "stats"))
		return cmd_stats();
	if (!strcmp(argv[1], "bump"))
		return cmd_bump();
	if (!strcmp(argv[1], "abi"))
		return cmd_abi();
	if (!strcmp(argv[1], "ifaces"))
		return cmd_ifaces(argc - 2, argv + 2);
	if (!strcmp(argv[1], "flows"))
		return cmd_flows(argc - 2, argv + 2);
	if (!strcmp(argv[1], "version")) {
		printf("dpdctl abi %d\n", DPD_ABI_VERSION);
		return 0;
	}
	usage(argv[0]);
	return 1;
}
