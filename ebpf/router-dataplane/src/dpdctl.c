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
#include <arpa/inet.h>
#include <sys/socket.h>

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
		"bytes_v4", "bytes_v6", "bytes_hit_v4", "bytes_hit_v6",
		"l2_v4", "l2_v6", "nat_gone", "flow_fin",
		"flow_bind", "flow_block", "flow_skip", "nat_dnat",
		"nat_snat", "nat_alloc", "nat_exhaust",
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
	} else if (!strcmp(argv[0], "nat")) {
		cfg.nat_offload = strtoul(argv[1], NULL, 0) ? 1 : 0;
	} else if (!strcmp(argv[0], "accel")) {
		cfg.accel_after_pkts = strtoul(argv[1], NULL, 0) & 0x7f;
	} else if (!strcmp(argv[0], "tcp_ttl")) {
		cfg.tcp_ttl_ms = strtoul(argv[1], NULL, 0);
	} else if (!strcmp(argv[0], "udp_ttl")) {
		cfg.udp_ttl_ms = strtoul(argv[1], NULL, 0);
	} else if (!strcmp(argv[0], "udp_unidir_ttl")) {
		cfg.udp_unidir_ttl_ms = strtoul(argv[1], NULL, 0);
	} else if (!strcmp(argv[0], "counters")) {
		cfg.flow_counters = strtoul(argv[1], NULL, 0) ? 1 : 0;
	} else if (!strcmp(argv[0], "class")) {
		cfg.class_enable = strtoul(argv[1], NULL, 0) ? 1 : 0;
	} else if (!strcmp(argv[0], "nat_ingress")) {
		cfg.nat_ingress = strtoul(argv[1], NULL, 0) ? 1 : 0;
	} else if (!strcmp(argv[0], "nat_forward")) {
		cfg.nat_forward = strtoul(argv[1], NULL, 0) ? 1 : 0;
	} else if (!strcmp(argv[0], "nat_port_min")) {
		cfg.nat_port_min = strtoul(argv[1], NULL, 0);
	} else if (!strcmp(argv[0], "nat_port_max")) {
		cfg.nat_port_max = strtoul(argv[1], NULL, 0);
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
	printf("nat_offload  %u%s\n", cfg.nat_offload,
	       cfg.nat_offload ? " (einat owns SNAT)"
			       : " (uplink half on the stack)");
	printf("accel_after  %u packets\n", cfg.accel_after_pkts);
	printf("ttl          tcp %u ms / udp %u ms / one-way udp %u ms\n",
	       cfg.tcp_ttl_ms, cfg.udp_ttl_ms, cfg.udp_unidir_ttl_ms);
	printf("ufs          counters %u / class cache %u\n",
	       cfg.flow_counters, cfg.class_enable);
	printf("nat_ingress  %u%s\n", cfg.nat_ingress,
	       cfg.nat_ingress ? " (DPD does return-path DNAT)"
			       : " (einat ingress owns it)");
	printf("nat_forward  %u%s\n", cfg.nat_forward,
	       cfg.nat_forward ? " (DPD egress does SNAT + port allocation)"
			       : " (einat egress owns SNAT)");
	printf("nat_ports    %u-%u%s\n",
	       cfg.nat_port_min ? cfg.nat_port_min : 20000,
	       cfg.nat_port_max ? cfg.nat_port_max : 29999,
	       (cfg.nat_port_min && cfg.nat_port_max) ? "" : " (default)");

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
		/* the map value is struct dpd_iface_val, not a bare u32: reading
		 * it into a uint32_t overflowed the stack and corrupted the
		 * key/iterator, which made this loop repeat the same entry
		 * forever (found 2026-11-09 while testing ABI 17). */
		struct dpd_iface_val iv = {};

		if (!dpd_bpf_map_lookup_elem(fd, &k, &iv))
			printf("  %-16s 0x%08x%s%s%s%s\n", ifname(k.ifindex),
			       iv.flags,
			       iv.flags & DPD_IF_F_UP ? " UP" : "",
			       iv.flags & DPD_IF_F_NOARP ? " NOARP" : "",
			       iv.flags & DPD_IF_F_POINTOPOINT ?
					" POINTOPOINT" : "",
			       iv.flags & DPD_IF_F_LOWER ? " LOWER" : "");
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
		struct dpd_iface_val val = {};
		uint32_t mtu = 0;
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

		if (flags & IFF_UP)		val.flags |= DPD_IF_F_UP;
		if (flags & IFF_NOARP)		val.flags |= DPD_IF_F_NOARP;
		if (flags & IFF_POINTOPOINT)	val.flags |= DPD_IF_F_POINTOPOINT;
		if (iflink && iflink != ifindex) val.flags |= DPD_IF_F_LOWER;

		/* Preserve the nexthop another call may have taught; `dpdctl gw`
		 * is a separate command because it runs after the interface
		 * exists and the default route has been installed. */
		{
			struct dpd_iface_val old = {};

			if (dpd_bpf_map_lookup_elem(fd, &ifindex, &old) == 0) {
				val.gw4 = old.gw4;
				val.addr4 = old.addr4;
			}
		}

		if (dpd_bpf_map_update_elem(fd, &ifindex, &val, BPF_ANY)) {
			fprintf(stderr, "dpdctl: update dpd_iface[%s]: %s\n",
				argv[i], strerror(errno));
			return 1;
		}
		if (mfd >= 0 && mtu &&
		    dpd_bpf_map_update_elem(mfd, &ifindex, &mtu, BPF_ANY))
			fprintf(stderr, "dpdctl: update dpd_mtu[%s]: %s\n",
				argv[i], strerror(errno));

		printf("%-16s ifindex=%-4u mtu=%-5u flags=0x%08x%s%s%s%s gw=%s\n",
		       argv[i], ifindex, mtu, val.flags,
		       val.flags & DPD_IF_F_UP ? " UP" : "",
		       val.flags & DPD_IF_F_NOARP ? " NOARP" : "",
		       val.flags & DPD_IF_F_POINTOPOINT ? " POINTOPOINT" : "",
		       val.flags & DPD_IF_F_LOWER ? " LOWER" : "",
		       val.gw4 ? inet_ntoa(*(struct in_addr *)&val.gw4) : "-");
	}
	if (mfd >= 0)
		close(mfd);
	return 0;
}

/*
 * Teach the IPv4 nexthop of one egress. The fast path hands it to
 * bpf_redirect_neigh() so the helper does not have to run
 * ip_route_output_flow() per packet -- on a router whose LAN source only
 * resolves with iif set (policy routing), that lookup returns -ENETUNREACH and
 * the packet is freed after the program already said "redirect".
 */
static int cmd_gw(int argc, char **argv)
{
	struct dpd_iface_val v = {};
	struct in_addr a;
	uint32_t ifindex;
	int fd;

	if (argc < 2) {
		fprintf(stderr, "usage: dpdctl gw <ifname> <ipv4-next-hop>\n");
		return 1;
	}
	ifindex = if_nametoindex(argv[0]);
	if (!ifindex) {
		fprintf(stderr, "dpdctl: no such iface '%s'\n", argv[0]);
		return 1;
	}
	if (inet_pton(AF_INET, argv[1], &a) != 1) {
		fprintf(stderr, "dpdctl: not an IPv4 address: '%s'\n", argv[1]);
		return 1;
	}
	fd = map_open("dpd_iface");
	if (fd < 0)
		return 1;
	/* preserve flags: no entry yet means "not taught", which is fine */
	dpd_bpf_map_lookup_elem(fd, &ifindex, &v);
	v.gw4 = a.s_addr;
	if (dpd_bpf_map_update_elem(fd, &ifindex, &v, BPF_ANY)) {
		fprintf(stderr, "dpdctl: update dpd_iface[%s].gw4: %s\n",
			argv[0], strerror(errno));
		return 1;
	}
	printf("%-16s gw=%s\n", argv[0], argv[1]);
	return 0;
}

/*
 * ABI 20: teach an uplink's NAT source address. The egress SNAT program uses
 * dpd_iface[ifindex].addr4 as the external address; leaving it unset is also
 * how every non-uplink device opts out of the egress program.
 */
static int cmd_nat_addr(int argc, char **argv)
{
	struct dpd_iface_val v = {};
	struct in_addr a;
	uint32_t ifindex;
	int fd;

	if (argc < 2) {
		fprintf(stderr, "usage: dpdctl nat_addr <ifname> <ipv4|0.0.0.0>\n");
		return 1;
	}
	ifindex = if_nametoindex(argv[0]);
	if (!ifindex) {
		fprintf(stderr, "dpdctl: no such iface '%s'\n", argv[0]);
		return 1;
	}
	if (inet_pton(AF_INET, argv[1], &a) != 1) {
		fprintf(stderr, "dpdctl: not an IPv4 address: '%s'\n", argv[1]);
		return 1;
	}
	fd = map_open("dpd_iface");
	if (fd < 0)
		return 1;
	/* preserve flags and gw4: this is one field of the same entry */
	dpd_bpf_map_lookup_elem(fd, &ifindex, &v);
	v.addr4 = a.s_addr;
	if (dpd_bpf_map_update_elem(fd, &ifindex, &v, BPF_ANY)) {
		fprintf(stderr, "dpdctl: update dpd_iface[%s].addr4: %s\n",
			argv[0], strerror(errno));
		return 1;
	}
	printf("%-16s nat_addr=%s\n", argv[0], argv[1]);
	return 0;
}

static const char *proto_name(uint32_t p)
{
	switch (p) {
	case IPPROTO_TCP:	return "tcp";
	case IPPROTO_UDP:	return "udp";
	case IPPROTO_ICMP:	return "icmp";
	default:		return "ip";
	}
}

/* ABI 20: dump the NAT tables. `-a` adds the reverse (return-path) table,
 * whose timestamp is CLOCK_MONOTONIC ms (0 = mirrored from einat). */
static int cmd_nat(int argc, char **argv)
{
	struct dpd_nat_key k, nk;
	struct dpd_nat_val v;
	struct dpd_nat_rev_key rk, rnk;
	struct dpd_nat_rev_val rv;
	int fd, n = 0, rn = 0;
	int all = argc > 0 && !strcmp(argv[0], "-a");

	fd = map_open("dpd_nat");
	if (fd >= 0) {
		if (!dpd_bpf_map_get_next_key(fd, NULL, &k)) {
			for (;;) {
				char sa[INET_ADDRSTRLEN] = "?";
				char ea[INET_ADDRSTRLEN] = "?";

				memset(&v, 0, sizeof(v));
				if (!dpd_bpf_map_lookup_elem(fd, &k, &v)) {
					inet_ntop(AF_INET, &k.saddr, sa, sizeof(sa));
					inet_ntop(AF_INET, &v.to_addr, ea, sizeof(ea));
					printf("%-4s %s:%-5u -> %s:%u\n",
					       proto_name(k.proto), sa,
					       ntohs(k.sport), ea, ntohs(v.to_port));
					n++;
				}
				if (dpd_bpf_map_get_next_key(fd, &k, &nk))
					break;
				k = nk;
			}
		}
		close(fd);
	}
	printf("forward bindings: %d\n", n);
	if (!all)
		return 0;

	fd = map_open("dpd_nat_rev");
	if (fd >= 0) {
		if (!dpd_bpf_map_get_next_key(fd, NULL, &rk)) {
			for (;;) {
				char ea[INET_ADDRSTRLEN] = "?";
				char ia[INET_ADDRSTRLEN] = "?";

				memset(&rv, 0, sizeof(rv));
				if (!dpd_bpf_map_lookup_elem(fd, &rk, &rv)) {
					inet_ntop(AF_INET, &rk.daddr, ea, sizeof(ea));
					inet_ntop(AF_INET, &rv.saddr, ia, sizeof(ia));
					printf("rev  %-4s %s:%-5u -> %s:%u ts=%u\n",
					       proto_name(rk.proto), ea,
					       ntohs(rk.dport), ia, ntohs(rv.sport),
					       rv.ts_ms);
					rn++;
				}
				if (dpd_bpf_map_get_next_key(fd, &rk, &rnk))
					break;
				rk = rnk;
			}
		}
		close(fd);
	}
	printf("reverse bindings: %d\n", rn);
	return 0;
}

static const char *state_name(uint32_t s)
{
	switch (s) {
	case DPD_FLOW_STATE_NEW:	return "new";
	case DPD_FLOW_STATE_OBSERVE:	return "observe";
	case DPD_FLOW_STATE_BIND:	return "bind";
	case DPD_FLOW_STATE_FIN:	return "fin";
	default:			return "?";
	}
}

static const char *action_name(uint32_t a)
{
	switch (a) {
	case DPD_ACT_FORWARD:	return "forward";
	case DPD_ACT_PROXY:	return "proxy";
	case DPD_ACT_BLOCK:	return "block";
	case DPD_ACT_LOCAL:	return "local";
	default:		return "?";
	}
}

static int action_parse(const char *s, uint32_t *out)
{
	char *e;
	unsigned long v;

	if (!strcmp(s, "forward")) { *out = DPD_ACT_FORWARD; return 0; }
	if (!strcmp(s, "proxy")) { *out = DPD_ACT_PROXY; return 0; }
	if (!strcmp(s, "block")) { *out = DPD_ACT_BLOCK; return 0; }
	if (!strcmp(s, "local")) { *out = DPD_ACT_LOCAL; return 0; }
	v = strtoul(s, &e, 0);
	if (*e || v > DPD_ACT_LOCAL)
		return -1;
	*out = (uint32_t)v;
	return 0;
}

/* class add|del <if> <tcp|udp|proto> <saddr> <sport> <daddr> <dport>
 *           <forward|proxy|block|local> [skb_priority]
 * The key is exactly struct dpd_flow_key, so it matches the UFS entry the
 * learn path will create for the same ingress interface. */
static int class_key_from_args(int argc, char **argv, struct dpd_flow_key *k)
{
	struct in_addr a4;
	struct in6_addr a6;
	char *e;
	unsigned long v;
	unsigned idx;

	memset(k, 0, sizeof(*k));
	if (argc < 6)
		return -1;
	if (!strcmp(argv[0], "any") || !strcmp(argv[0], "0")) {
		idx = 0;	/* wildcard: any ingress interface */
	} else {
		idx = if_nametoindex(argv[0]);
		if (!idx) {
			v = strtoul(argv[0], &e, 0);
			if (*e || !v)
				return -1;
			idx = v;
		}
	}
	k->ifindex = (uint32_t)idx;

	if (!strcmp(argv[1], "tcp"))
		k->proto = IPPROTO_TCP;
	else if (!strcmp(argv[1], "udp"))
		k->proto = IPPROTO_UDP;
	else {
		v = strtoul(argv[1], &e, 0);
		if (*e || v > 255)
			return -1;
		k->proto = (uint8_t)v;
	}

	if (inet_pton(AF_INET, argv[2], &a4) == 1) {
		k->family = AF_INET;
		k->saddr[3] = a4.s_addr;
	} else if (inet_pton(AF_INET6, argv[2], &a6) == 1) {
		k->family = AF_INET6;
		__builtin_memcpy(k->saddr, &a6, sizeof(a6));
	} else {
		return -1;
	}

	if (k->family == AF_INET) {
		if (inet_pton(AF_INET, argv[4], &a4) != 1)
			return -1;
		k->daddr[3] = a4.s_addr;
	} else {
		if (inet_pton(AF_INET6, argv[4], &a6) != 1)
			return -1;
		__builtin_memcpy(k->daddr, &a6, sizeof(a6));
	}

	v = strtoul(argv[3], &e, 0);
	if (*e || v > 65535)
		return -1;
	k->sport = htons((uint16_t)v);
	v = strtoul(argv[5], &e, 0);
	if (*e || v > 65535)
		return -1;
	k->dport = htons((uint16_t)v);
	return 0;
}

static void class_print(const struct dpd_flow_key *k)
{
	char sa[INET6_ADDRSTRLEN] = "?", da[INET6_ADDRSTRLEN] = "?";

	if (k->family == AF_INET) {
		inet_ntop(AF_INET, &k->saddr[3], sa, sizeof(sa));
		inet_ntop(AF_INET, &k->daddr[3], da, sizeof(da));
	} else {
		inet_ntop(AF_INET6, k->saddr, sa, sizeof(sa));
		inet_ntop(AF_INET6, k->daddr, da, sizeof(da));
	}
	printf("%-10s fam=%u proto=%u %s:%u -> %s:%u\n",
	       ifname(k->ifindex), k->family, k->proto, sa,
	       ntohs(k->sport), da, ntohs(k->dport));
}

static int cmd_class(int argc, char **argv)
{
	struct dpd_flow_key k = {}, nk;
	struct dpd_class_val v;
	int fd, n = 0;

	if (argc < 1) {
		fprintf(stderr, "usage: dpdctl class add|del <if> <tcp|udp> "
			"<saddr> <sport> <daddr> <dport> "
			"<forward|proxy|block|local> [priority]\n"
			"       dpdctl class list|flush\n");
		return 1;
	}
	fd = map_open("dpd_class");
	if (fd < 0)
		return 1;

	if (!strcmp(argv[0], "flush")) {
		while (!dpd_bpf_map_get_next_key(fd, NULL, &k))
			if (dpd_bpf_map_delete_elem(fd, &k))
				break;
		printf("dpd_class flushed\n");
		return 0;
	}
	if (!strcmp(argv[0], "list")) {
		if (dpd_bpf_map_get_next_key(fd, NULL, &k))
			return 0;
		for (;;) {
			memset(&v, 0, sizeof(v));
			if (!dpd_bpf_map_lookup_elem(fd, &k, &v)) {
				class_print(&k);
				printf("           action=%s priority=%u\n",
				       action_name(v.action), v.skb_priority);
				n++;
			}
			if (dpd_bpf_map_get_next_key(fd, &k, &nk))
				break;
			k = nk;
		}
		printf("classes: %d\n", n);
		return 0;
	}
	if (strcmp(argv[0], "add") && strcmp(argv[0], "del")) {
		fprintf(stderr, "dpdctl: class: unknown op '%s'\n", argv[0]);
		return 1;
	}
	if (argc < 7) {
		fprintf(stderr, "dpdctl: class: need 6 arguments after '%s'\n",
			argv[0]);
		return 1;
	}
	if (!strcmp(argv[0], "add") && argc < 8) {
		fprintf(stderr, "dpdctl: class add: need the action\n");
		return 1;
	}
	if (class_key_from_args(argc - 1, argv + 1, &k)) {
		fprintf(stderr, "dpdctl: class: bad 5-tuple\n");
		return 1;
	}
	if (!strcmp(argv[0], "del")) {
		if (dpd_bpf_map_delete_elem(fd, &k)) {
			fprintf(stderr, "dpdctl: class del: %s\n",
				strerror(errno));
			return 1;
		}
		printf("deleted ");
		class_print(&k);
		return 0;
	}
	memset(&v, 0, sizeof(v));
	if (action_parse(argv[7], &v.action)) {
		fprintf(stderr, "dpdctl: class: bad action '%s'\n", argv[7]);
		return 1;
	}
	if (argc >= 9)
		v.skb_priority = strtoul(argv[8], NULL, 0);
	if (dpd_bpf_map_update_elem(fd, &k, &v, BPF_ANY)) {
		fprintf(stderr, "dpdctl: class add: %s\n", strerror(errno));
		return 1;
	}
	printf("added ");
	class_print(&k);
	printf("           action=%s priority=%u\n",
	       action_name(v.action), v.skb_priority);
	return 0;
}

/* ABI 18: targeted UFS invalidation. A pattern with 0/any fields matches
 * everything in that field; port 0 is a wildcard. The scan is O(flows) and is
 * meant for control-plane events (policy change, conntrack destroy), not for
 * the packet path. */
struct flow_match {
	uint32_t ifindex;	/* 0 = any */
	uint8_t proto;		/* 0 = any */
	uint8_t family;		/* 0 = any */
	int has_s, has_d;
	__be32 saddr[4], daddr[4];
	uint16_t sport, dport;	/* 0 = any */
};

static int addr_is_any(const char *s)
{
	return !strcmp(s, "any") || !strcmp(s, "0") ||
	       !strcmp(s, "0.0.0.0") || !strcmp(s, "::");
}

static int match_set(struct flow_match *m, const char *ifn, const char *proto,
		     const char *sa, const char *sp, const char *da,
		     const char *dp)
{
	struct in_addr a4;
	struct in6_addr a6;
	char *e;
	unsigned long v;

	memset(m, 0, sizeof(*m));
	if (strcmp(ifn, "any") && strcmp(ifn, "0")) {
		v = if_nametoindex(ifn);
		if (!v) {
			v = strtoul(ifn, &e, 0);
			if (*e || !v)
				return -1;
		}
		m->ifindex = (uint32_t)v;
	}
	if (strcmp(proto, "any") && strcmp(proto, "0")) {
		if (!strcmp(proto, "tcp"))
			m->proto = IPPROTO_TCP;
		else if (!strcmp(proto, "udp"))
			m->proto = IPPROTO_UDP;
		else {
			v = strtoul(proto, &e, 0);
			if (*e || v > 255)
				return -1;
			m->proto = (uint8_t)v;
		}
	}
	if (!addr_is_any(sa)) {
		if (inet_pton(AF_INET, sa, &a4) == 1) {
			m->has_s = 1;
			m->family = AF_INET;
			m->saddr[3] = a4.s_addr;
		} else if (inet_pton(AF_INET6, sa, &a6) == 1) {
			m->has_s = 1;
			m->family = AF_INET6;
			__builtin_memcpy(m->saddr, &a6, sizeof(a6));
		} else {
			return -1;
		}
	}
	if (!addr_is_any(da)) {
		if (inet_pton(AF_INET, da, &a4) == 1) {
			if (m->family == AF_INET6)
				return -1;
			m->has_d = 1;
			m->family = AF_INET;
			m->daddr[3] = a4.s_addr;
		} else if (inet_pton(AF_INET6, da, &a6) == 1) {
			if (m->family == AF_INET)
				return -1;
			m->has_d = 1;
			m->family = AF_INET6;
			__builtin_memcpy(m->daddr, &a6, sizeof(a6));
		} else {
			return -1;
		}
	}
	v = strtoul(sp, &e, 0);
	if (*e || v > 65535)
		return -1;
	m->sport = (uint16_t)v;
	v = strtoul(dp, &e, 0);
	if (*e || v > 65535)
		return -1;
	m->dport = (uint16_t)v;
	return 0;
}

static int match_key(const struct flow_match *m, const struct dpd_flow_key *k)
{
	if (m->ifindex && k->ifindex != m->ifindex)
		return 0;
	if (m->proto && k->proto != m->proto)
		return 0;
	if (m->family && k->family != m->family)
		return 0;
	if (m->has_s && __builtin_memcmp(k->saddr, m->saddr, 16))
		return 0;
	if (m->has_d && __builtin_memcmp(k->daddr, m->daddr, 16))
		return 0;
	if (m->sport && k->sport != htons(m->sport))
		return 0;
	if (m->dport && k->dport != htons(m->dport))
		return 0;
	return 1;
}

#define DPD_DELETE_PATTERNS 256

/*
 * ABI 20: release the NAT binding that belongs to a destroyed flow. dpdfwd
 * feeds the same file to this command, and its first line per connection is
 * the original (pre-SNAT) tuple, which is exactly the dpd_nat key. The
 * reverse entry is found through the value and removed too. A missing NAT
 * map (einat mode with an older object) is not an error.
 */
static int nat_release(const struct flow_match *m, int nm)
{
	struct dpd_nat_key nk;
	struct dpd_nat_rev_key rk;
	struct dpd_nat_val nv;
	int nfd, rfd, i, released = 0;

	nfd = map_open("dpd_nat");
	if (nfd < 0)
		return 0;
	rfd = map_open("dpd_nat_rev");
	for (i = 0; i < nm; i++) {
		if (!m[i].has_s || !m[i].sport || !m[i].proto ||
		    m[i].family != AF_INET)
			continue;
		memset(&nk, 0, sizeof(nk));
		nk.saddr = m[i].saddr[3];
		nk.sport = htons(m[i].sport);
		nk.proto = m[i].proto;
		memset(&nv, 0, sizeof(nv));
		if (dpd_bpf_map_lookup_elem(nfd, &nk, &nv) || !nv.to_addr)
			continue;
		if (dpd_bpf_map_delete_elem(nfd, &nk))
			continue;
		released++;
		if (rfd >= 0) {
			memset(&rk, 0, sizeof(rk));
			rk.daddr = nv.to_addr;
			rk.dport = nv.to_port;
			rk.proto = nk.proto;
			dpd_bpf_map_delete_elem(rfd, &rk);
		}
	}
	if (rfd >= 0)
		close(rfd);
	close(nfd);
	if (released)
		printf("released %d nat binding(s)\n", released);
	return released;
}

static int delete_patterns(struct flow_match *m, int nm)
{
	struct dpd_flow_key k, nk, *hits = NULL;
	size_t n = 0, cap = 0;
	int fd, i, deleted = 0;

	fd = map_open("dpd_flows");
	if (fd < 0)
		return 1;
	if (dpd_bpf_map_get_next_key(fd, NULL, &k)) {
		printf("deleted 0 flows\n");
		return 0;
	}
	for (;;) {
		int hit = 0;

		for (i = 0; i < nm; i++)
			if (match_key(&m[i], &k)) {
				hit = 1;
				break;
			}
		if (hit) {
			if (n == cap) {
				size_t ncap = cap ? cap * 2 : 64;
				struct dpd_flow_key *p = realloc(hits,
						ncap * sizeof(*hits));

				if (!p) {
					free(hits);
					return 1;
				}
				hits = p;
				cap = ncap;
			}
			hits[n++] = k;
		}
		if (dpd_bpf_map_get_next_key(fd, &k, &nk))
			break;
		k = nk;
	}
	for (i = 0; i < (int)n; i++)
		if (!dpd_bpf_map_delete_elem(fd, &hits[i]))
			deleted++;
	free(hits);
	printf("deleted %d flow(s)\n", deleted);
	return 0;
}

/* delete <if|any> <proto|any> <saddr|any> <sport|0> <daddr|any> <dport|0>
 * delete -f <file>   lines: <proto> <saddr> <sport> <daddr> <dport>
 * The -f mode is what dpdfwd uses: it batches conntrack destroys into one
 * scan per second instead of forking one process per event. It also releases
 * the dpd_nat binding keyed by each line's (saddr,sport,proto), so a destroyed
 * connection hands its external port back immediately (ABI 20). */
static int cmd_delete(int argc, char **argv)
{
	struct flow_match m[DPD_DELETE_PATTERNS];
	int nm = 0;

	if (argc >= 2 && !strcmp(argv[0], "-f")) {
		FILE *fp = fopen(argv[1], "r");
		char line[256];

		if (!fp)
			return 0;
		while (nm < DPD_DELETE_PATTERNS &&
		       fgets(line, sizeof(line), fp)) {
			char *tok[5];
			int t = 0;
			char *p = strtok(line, " \t\r\n");

			while (p && t < 5) {
				tok[t++] = p;
				p = strtok(NULL, " \t\r\n");
			}
			if (t == 5 &&
			    !match_set(&m[nm], "any", tok[0], tok[1], tok[2],
				       tok[3], tok[4]))
				nm++;
		}
		fclose(fp);
		if (!nm) {
			printf("deleted 0 flows\n");
			return 0;
		}
		/* A destroyed conntrack also frees its external port; otherwise
		 * a client that reuses the same source port would keep a stale
		 * binding until the TTL. */
		nat_release(m, nm);
		return delete_patterns(m, nm);
	}
	if (argc < 6) {
		fprintf(stderr, "usage: dpdctl delete <if|any> <proto|any> "
			"<saddr|any> <sport|0> <daddr|any> <dport|0>\n"
			"       dpdctl delete -f <file>\n");
		return 1;
	}
	if (match_set(&m[0], argv[0], argv[1], argv[2], argv[3], argv[4],
		      argv[5])) {
		fprintf(stderr, "dpdctl: delete: bad pattern\n");
		return 1;
	}
	return delete_patterns(m, 1);
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
			char sa[INET6_ADDRSTRLEN] = "-";
			char da[INET6_ADDRSTRLEN] = "-";

			/* v4 is stored in the last word (see the BPF key
			 * builder); v6 fills the whole array. Printing the
			 * tuple is what makes a flow identifiable at all. */
			if (k.family == AF_INET) {
				inet_ntop(AF_INET, &k.saddr[3], sa, sizeof(sa));
				inet_ntop(AF_INET, &k.daddr[3], da, sizeof(da));
			} else if (k.family == AF_INET6) {
				inet_ntop(AF_INET6, k.saddr, sa, sizeof(sa));
				inet_ntop(AF_INET6, k.daddr, da, sizeof(da));
			}
			printf("%s:%u > %s:%u\n", sa, ntohs(k.sport), da,
			       ntohs(k.dport));
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
			printf("           state=%s action=%s prio=%u dscp=%u "
			       "pkt=%llu bytes=%llu\n",
			       state_name(v.state), action_name(v.action),
			       v.skb_priority, v.dscp,
			       (unsigned long long)v.packets,
			       (unsigned long long)v.bytes);
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

/* dpd_flows occupancy, split by address family: the status card shows the
 * active flow count as "v4 / v6" and the family is part of the key, so one
 * walk gives both the total and the split. */
static void flow_count(uint32_t *max_entries, int *total, int *v4, int *v6)
{
	unsigned char key[64], next[64];
	struct bpf_map_info info = {};
	uint32_t len = sizeof(info);
	int fd = map_open("dpd_flows");

	*max_entries = 0;
	*total = *v4 = *v6 = -1;
	if (fd < 0)
		return;
	if (dpd_bpf_map_get_info_by_fd(fd, &info, &len)) {
		close(fd);
		return;
	}
	*max_entries = info.max_entries;
	*total = *v4 = *v6 = 0;
	if (info.key_size != sizeof(struct dpd_flow_key) ||
	    info.key_size > sizeof(key) ||
	    dpd_bpf_map_get_next_key(fd, NULL, key))
		goto out;
	for (;;) {
		const struct dpd_flow_key *k = (const void *)key;

		(*total)++;
		if (k->family == AF_INET)
			(*v4)++;
		else if (k->family == AF_INET6)
			(*v6)++;
		if (dpd_bpf_map_get_next_key(fd, key, next))
			break;
		memcpy(key, next, info.key_size);
	}
out:
	close(fd);
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
		/* Every map is counted now: the homepage shows the number of
		 * active flows, and a 16k-key walk is a few milliseconds at the
		 * 5 s / 20 s cadence the status page and the watchdog use. */
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
	int cnt, f4, f6, fd, first;
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
		printf(", \"nat_offload\": %u", cfg.nat_offload);
		printf(", \"accel_after_pkts\": %u, \"tcp_ttl_ms\": %u, "
		       "\"udp_ttl_ms\": %u, \"udp_unidir_ttl_ms\": %u",
		       cfg.accel_after_pkts, cfg.tcp_ttl_ms, cfg.udp_ttl_ms,
		       cfg.udp_unidir_ttl_ms);
		printf(", \"flow_counters\": %u, \"class_enable\": %u",
		       cfg.flow_counters, cfg.class_enable);
		printf(", \"nat_ingress\": %u", cfg.nat_ingress);
		printf(", \"nat_forward\": %u, \"nat_port_min\": %u, "
		       "\"nat_port_max\": %u", cfg.nat_forward,
		       cfg.nat_port_min, cfg.nat_port_max);
		printf(", \"policy\": ");
		json_string(policy_name(cfg.policy));
		printf(" },\n");
	} else {
		printf("null,\n");
	}

	printf("  \"maps\": {\n");
	flow_count(&max, &cnt, &f4, &f6);
	printf("    \"flows\": { \"max_entries\": %u, \"entries\": %d, "
	       "\"v4\": %d, \"v6\": %d },\n", max, cnt, f4, f6);
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
				struct dpd_iface_val v = {};
				uint32_t mtu = 0;

				if (!dpd_bpf_map_lookup_elem(fd, &k, &v)) {
					if (mfd >= 0)
						dpd_bpf_map_lookup_elem(mfd, &k.ifindex,
									&mtu);
					printf("%s\n    { \"name\": ", first ? "" : ",");
					json_string(ifname(k.ifindex));
					printf(", \"ifindex\": %u, \"mtu\": %u, \"flags\": ",
					       k.ifindex, mtu);
					json_iface_flags(v.flags);
					printf(", \"gw4\": \"%s\"",
					       v.gw4 ? inet_ntoa(*(struct in_addr *)&v.gw4)
						     : "");
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
	int cnt, f4, f6;
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

	flow_count(&max, &cnt, &f4, &f6);
	printf("  flow cache    %d/%u (LRU, v4 %d, v6 %d)\n", cnt, max, f4, f6);
	map_limits("dpd_mtu", &max, &cnt);
	printf("  mtu table     %d/%u\n", cnt, max);

	printf("  ifaces\n");
	fd = map_open("dpd_iface");
	if (fd >= 0) {
		int mfd = map_open("dpd_mtu");

		if (!dpd_bpf_map_get_next_key(fd, NULL, &k)) {
			for (;;) {
				struct dpd_iface_val iv = {};
				char na[INET_ADDRSTRLEN] = "-";
				uint32_t mtu = 0;

				/* read the whole value: the syscall copies
				 * sizeof(value) bytes, so a bare uint32_t here
				 * overflows the stack (the same bug fixed in
				 * cmd_show while testing ABI 17). */
				if (!dpd_bpf_map_lookup_elem(fd, &k, &iv)) {
					if (mfd >= 0)
						dpd_bpf_map_lookup_elem(mfd, &k.ifindex,
									&mtu);
					if (iv.addr4)
						inet_ntop(AF_INET, &iv.addr4, na,
							  sizeof(na));
					printf("    %-16s mtu=%-5u nat=%-15s%s%s%s%s\n",
					       ifname(k.ifindex), mtu, na,
					       iv.flags & DPD_IF_F_UP ? " UP" : "",
					       iv.flags & DPD_IF_F_NOARP ? " NOARP" : "",
					       iv.flags & DPD_IF_F_POINTOPOINT ? " POINTOPOINT" : "",
					       iv.flags & DPD_IF_F_LOWER ? " LOWER" : "");
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
		"  set nat <0|1>           1 = einat owns uplink SNAT; take the\n"
		"                          forward half over once a binding exists\n"
		"  set accel <n>           packets of a new direction that still walk\n"
		"                          the stack before it is accelerated (0..127)\n"
		"  set tcp_ttl <ms>        TCP flow idle timeout (0 = flow_ttl_ms)\n"
		"  set udp_ttl <ms>        UDP timeout once the flow is bidirectional\n"
		"  set udp_unidir_ttl <ms> UDP timeout while still one-way\n"
		"  set counters <0|1>      per-flow packets/bytes in the UFS entry\n"
		"  set class <0|1>         consult the dpd_class policy cache\n"
		"  set nat_ingress <0|1>   1 = DPD does return-path DNAT from\n"
		"                          dpd_nat_rev (einat ingress must be off)\n"
		"  set nat_forward <0|1>   1 = DPD's egress program does SNAT and\n"
		"                          port allocation (einat egress must be off)\n"
		"  set nat_port_min <p>    external port range (default 20000)\n"
		"  set nat_port_max <p>    external port range (default 29999)\n"
		"  nat_addr <ifname> <ipv4>  teach the NAT source address of an uplink\n"
		"  nat [-a]                dump forward bindings (-a: reverse too)\n"
		"  class add|del <if> <tcp|udp> <saddr> <sport> <daddr> <dport>\n"
		"        <forward|proxy|block|local> [skb_priority]\n"
		"  class list|flush        inspect/clear the policy cache\n"
		"  delete <if|any> <proto|any> <saddr|any> <sport|0> <daddr|any>\n"
		"         <dport|0>        delete matching UFS entries (targeted\n"
		"                          invalidation from a control-plane event)\n"
		"  set policy <allow-all|vlans-only>\n"
		"  bump                    move the flow-cache epoch (drop all cached\n"
		"                          egress decisions without a map walk)\n"
		"  abi                     print the ABI of the loaded object (0 = none)\n"
		"  vlan add <id>|del <id>|list|flush\n"
		"  stats                   per-reason counters (all cpus summed)\n"
		"  ifaces <ifname>...      learn IFF_* flags and MTU into the maps\n"
	"  gw <ifname> <ipv4>      set the nexthop used by the neigh emit\n"
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
	if (!strcmp(argv[1], "gw"))
		return cmd_gw(argc - 2, argv + 2);
	if (!strcmp(argv[1], "nat_addr"))
		return cmd_nat_addr(argc - 2, argv + 2);
	if (!strcmp(argv[1], "nat"))
		return cmd_nat(argc - 2, argv + 2);
	if (!strcmp(argv[1], "flows"))
		return cmd_flows(argc - 2, argv + 2);
	if (!strcmp(argv[1], "class"))
		return cmd_class(argc - 2, argv + 2);
	if (!strcmp(argv[1], "delete"))
		return cmd_delete(argc - 2, argv + 2);
	if (!strcmp(argv[1], "version")) {
		printf("dpdctl abi %d\n", DPD_ABI_VERSION);
		return 0;
	}
	usage(argv[0]);
	return 1;
}
