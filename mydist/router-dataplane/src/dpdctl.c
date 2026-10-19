// SPDX-License-Identifier: GPL-2.0-only
/*
 * dpdctl - userspace control for the dpd_fastpath TC BPF program.
 *
 * Deliberately narrow: map access only. Qdisc/filter (de)attachment lives in
 * files/dpd_fastpath.init because shell is easier to debug on a router and is
 * where OpenWrt users expect to find it.
 *
 * Maps are pinned by name (see dpd_fastpath.bpf.c), so the normal case is a
 * plain bpf_obj_get("/sys/fs/bpf/dpd_cfg"). When pinning was not honoured by
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

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "dpd_common.h"

/* monotonic ms, to compare against values stored by bpf_ktime_get_ns() */
static uint64_t mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
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
	int fd = bpf_obj_get(pin_path(name));

	if (fd >= 0)
		return fd;

	for (uint32_t id = 0;;) {
		struct bpf_map_info info = {};
		uint32_t len = sizeof(info);

		if (bpf_map_get_next_id(id, &id))
			break;
		fd = bpf_map_get_fd_by_id(id);
		if (fd < 0)
			continue;
		if (bpf_map_get_info_by_fd(fd, &info, &len) == 0 &&
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

	return bpf_map_lookup_elem(fd, &k, cfg);
}

static int cfg_write(int fd, const struct dpd_config *cfg)
{
	uint32_t k = 0;

	return bpf_map_update_elem(fd, &k, cfg, BPF_ANY);
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

	fd = map_open("dpd_vlans");
	if (fd >= 0) {
		uint16_t vk, vn;
		int nv = 0;

		printf("vlans        ");
		if (!bpf_map_get_next_key(fd, NULL, &vk)) {
			for (;;) {
				printf("%u ", vk);
				nv++;
				if (bpf_map_get_next_key(fd, &vk, &vn))
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
	if (bpf_map_get_next_key(fd, NULL, &k))
		return 0;
	for (;;) {
		uint32_t v = 0;

		if (!bpf_map_lookup_elem(fd, &k, &v))
			printf("  %-16s 0x%08x%s%s%s\n", ifname(k.ifindex), v,
			       v & DPD_IF_F_UP ? " UP" : "",
			       v & DPD_IF_F_NOARP ? " NOARP" : "",
			       v & DPD_IF_F_POINTOPOINT ? " POINTOPOINT" : "");
		if (bpf_map_get_next_key(fd, &k, &nk))
			break;
		k = nk;
		have_k = 1;
	}
	(void)have_k;
	(void)len;
	return 0;
}

static int cmd_stats(void)
{
	uint64_t *vals;
	int fd, ncpu;

	fd = map_open("dpd_stats");
	if (fd < 0)
		return 1;
	ncpu = libbpf_num_possible_cpus();
	if (ncpu <= 0)
		ncpu = 1;
	vals = calloc((size_t)ncpu, sizeof(uint64_t));
	if (!vals) {
		fprintf(stderr, "dpdctl: out of memory\n");
		return 1;
	}

	printf("  idx  %-13s %s\n", "name", "total");
	for (uint32_t i = 0; i < ST__MAX; i++) {
		uint64_t sum = 0;

		if (bpf_map_lookup_elem(fd, &i, vals))
			continue;
		for (int c = 0; c < ncpu; c++)
			sum += vals[c];
		printf("  %3u  %-13s %llu\n", i, stat_name(i),
		       (unsigned long long)sum);
	}
	free(vals);
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
	int fd;

	if (argc == 0) {
		fprintf(stderr, "usage: dpdctl ifaces <ifname>...\n");
		return 1;
	}
	fd = map_open("dpd_iface");
	if (fd < 0)
		return 1;

	for (int i = 0; i < argc; i++) {
		char path[256];
		uint32_t ifindex = if_nametoindex(argv[i]);
		uint32_t v = 0;
		FILE *f;
		unsigned long flags = 0;

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

		if (flags & IFF_UP)		v |= DPD_IF_F_UP;
		if (flags & IFF_NOARP)		v |= DPD_IF_F_NOARP;
		if (flags & IFF_POINTOPOINT)	v |= DPD_IF_F_POINTOPOINT;

		if (bpf_map_update_elem(fd, &ifindex, &v, BPF_ANY)) {
			fprintf(stderr, "dpdctl: update dpd_iface[%s]: %s\n",
				argv[i], strerror(errno));
			return 1;
		}
		printf("%-16s ifindex=%-4u flags=0x%08x%s%s%s\n", argv[i], ifindex, v,
		       v & DPD_IF_F_UP ? " UP" : "",
		       v & DPD_IF_F_NOARP ? " NOARP" : "",
		       v & DPD_IF_F_POINTOPOINT ? " POINTOPOINT" : "");
	}
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
	if (bpf_map_get_next_key(fd, NULL, &k))
		return 0;
	for (;;) {
		if (!bpf_map_lookup_elem(fd, &k, &v)) {
			uint64_t age_ms = 0;

			if (mono_ns() > v.last_seen_ns)
				age_ms = (mono_ns() - v.last_seen_ns) / 1000000ULL;
			printf("%-10s fam=%u proto=%u egress=%-10s age=%llums "
			       "dmac=%02x:%02x:%02x:%02x:%02x:%02x\n",
			       ifname(k.ifindex), k.family, k.proto,
			       ifname(v.egress_ifindex),
			       (unsigned long long)age_ms,
			       v.dmac[0], v.dmac[1], v.dmac[2],
			       v.dmac[3], v.dmac[4], v.dmac[5]);
			if (++n >= max)
				break;
		}
		if (bpf_map_get_next_key(fd, &k, &nk))
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
		if (bpf_map_update_elem(fd, &id, &one, BPF_ANY)) {
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
		if (bpf_map_delete_elem(fd, &id) && errno != ENOENT) {
			fprintf(stderr, "dpdctl: vlan del %u: %s\n", id,
				strerror(errno));
			return 1;
		}
		printf("vlan %u deleted\n", id);
	} else if (!strcmp(argv[0], "flush")) {
		uint16_t k, n;

		if (bpf_map_get_next_key(fd, NULL, &k))
			return 0;
		for (;;) {
			bpf_map_delete_elem(fd, &k);
			if (bpf_map_get_next_key(fd, &k, &n))
				break;
			k = n;
		}
		printf("vlans flushed\n");
	} else if (!strcmp(argv[0], "list")) {
		uint16_t k, n;
		int cnt = 0;

		if (bpf_map_get_next_key(fd, NULL, &k))
			return 0;
		for (;;) {
			printf("vlan %u\n", k);
			cnt++;
			if (bpf_map_get_next_key(fd, &k, &n))
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

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s <command>\n"
		"  show                    dump dpd_cfg + dpd_iface + dpd_vlans\n"
		"  set mode <off|observe|stateless|stateful|neigh-probe>\n"
		"  set enable <0|1>\n"
		"  set redirect <auto|neigh|dev>\n"
		"  set ttl <ms>\n"
		"  set policy <allow-all|vlans-only>\n"
		"  vlan add <id>|del <id>|list|flush\n"
		"  stats                   per-reason counters (all cpus summed)\n"
		"  ifaces <ifname>...      learn IFF_* flags into dpd_iface\n"
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
	if (!strcmp(argv[1], "set"))
		return cmd_set(argc - 2, argv + 2);
	if (!strcmp(argv[1], "vlan"))
		return cmd_vlan(argc - 2, argv + 2);
	if (!strcmp(argv[1], "stats"))
		return cmd_stats();
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
