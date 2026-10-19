// SPDX-License-Identifier: GPL-2.0-only
/*
 * aclctl - userspace control for the router-acl TC BPF programs.
 *
 * Map access only, exactly like dpdctl: qdisc/filter (de)attachment and the
 * generated fw4 snippets live in files/router_acl.init, because shell is easier
 * to debug on a router and is where OpenWrt users look for it.
 *
 * Maps are pinned by name, so the normal case is a plain
 * bpf_obj_get("/sys/fs/bpf/acl_cfg"). When pinning was not honoured by whoever
 * loaded the object, fall back to walking the global map id space and matching
 * on the BTF map name.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "acl_common.h"

static const char *pin_path(const char *name)
{
	static char buf[128];

	snprintf(buf, sizeof(buf), "%s/%s", ACL_PIN_DIR, name);
	return buf;
}

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
	fprintf(stderr, "aclctl: map '%s' not found (is the program attached?)\n",
		name);
	return -1;
}

static void cfg_defaults(struct acl_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->abi_version = ACL_ABI_VERSION;
	cfg->mode = ACL_MODE_OFF;
	cfg->udp_timeout_ms = 120000;
	cfg->tcp_timeout_ms = 3600000;
	cfg->icmp_timeout_ms = 30000;
	cfg->mark = ACL_MARK_BIT;
}

/* Read-modify-write so `aclctl set` never clobbers unrelated fields. */
static int cfg_load(int *fdp, struct acl_config *cfg)
{
	uint32_t k = 0;

	*fdp = map_open("acl_cfg");
	if (*fdp < 0)
		return -1;
	if (bpf_map_lookup_elem(*fdp, &k, cfg)) {
		/* attached but never configured: start from defaults */
		cfg_defaults(cfg);
		return 0;
	}
	if (cfg->abi_version != ACL_ABI_VERSION)
		fprintf(stderr, "aclctl: warning: cfg abi %u, expected %u\n",
			cfg->abi_version, ACL_ABI_VERSION);
	return 0;
}

static int cfg_store(int fd, const struct acl_config *cfg)
{
	uint32_t k = 0;

	if (bpf_map_update_elem(fd, &k, cfg, BPF_ANY)) {
		fprintf(stderr, "aclctl: write acl_cfg: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static const char *mode_name(uint32_t m)
{
	switch (m) {
	case ACL_MODE_OFF:	return "off";
	case ACL_MODE_GUARD:	return "guard";
	case ACL_MODE_BYPASS:	return "bypass";
	default:		return "?";
	}
}

static int mode_parse(const char *s, uint32_t *out)
{
	if (!strcmp(s, "off"))		*out = ACL_MODE_OFF;
	else if (!strcmp(s, "guard"))	*out = ACL_MODE_GUARD;
	else if (!strcmp(s, "bypass"))	*out = ACL_MODE_BYPASS;
	else return -1;
	return 0;
}

static int proto_parse(const char *s, uint16_t *out)
{
	if (!strcmp(s, "tcp"))		*out = 6;
	else if (!strcmp(s, "udp"))	*out = 17;
	else if (!strcmp(s, "icmp"))	*out = 1;
	else if (!strcmp(s, "icmpv6"))	*out = 58;
	else {
		char *end;
		unsigned long v = strtoul(s, &end, 10);

		if (*s == '\0' || *end != '\0' || v > 255)
			return -1;
		*out = (uint16_t)v;
	}
	return 0;
}

static const char *proto_name(uint16_t p)
{
	static char buf[8];

	switch (p) {
	case 6:		return "tcp";
	case 17:	return "udp";
	case 1:		return "icmp";
	case 58:	return "icmpv6";
	default:
		snprintf(buf, sizeof(buf), "%u", p);
		return buf;
	}
}

static int scope_parse(const char *s, uint16_t *out)
{
	if (!strcmp(s, "forward"))	*out = ACL_SCOPE_FORWARD;
	else if (!strcmp(s, "input"))	*out = ACL_SCOPE_INPUT;
	else return -1;
	return 0;
}

static const char *scope_name(uint16_t s)
{
	switch (s) {
	case ACL_SCOPE_FORWARD:	return "forward";
	case ACL_SCOPE_INPUT:	return "input";
	default:		return "?";
	}
}

static int family_parse(const char *s, uint16_t *out)
{
	if (!strcmp(s, "4") || !strcmp(s, "ipv4") || !strcmp(s, "inet"))
		*out = ACL_AF_INET;
	else if (!strcmp(s, "6") || !strcmp(s, "ipv6") || !strcmp(s, "inet6"))
		*out = ACL_AF_INET6;
	else return -1;
	return 0;
}

static const char *family_name(uint16_t f)
{
	return f == ACL_AF_INET6 ? "ipv6" : "ipv4";
}

/* ---- stats ------------------------------------------------------------- */

static const char *stat_name(int i)
{
	static const char *n[] = {
		"ingress_pkt", "ingress_mapped", "ingress_forward",
		"ingress_input", "ingress_icmp_err", "ingress_echo",
		"ingress_fullcone", "ingress_drop", "ingress_nonip",
		"egress_pkt", "egress_learn", "egress_nonip",
		"v6_ingress_pkt", "v6_ingress_state", "v6_ingress_icmp6",
		"v6_ingress_forward", "v6_ingress_drop",
		"v6_egress_pkt", "v6_egress_learn", "marked",
	};

	/* This table and the enum in acl_common.h must not drift. A missing
	 * entry does not fail to compile on its own -- it silently shifts every
	 * name after it, which is exactly how "marked 1" once made it into a
	 * report while the real counter (9) printed as "(null)". */
	_Static_assert(sizeof(n) / sizeof(n[0]) == AS_MAX,
		       "stat_name[] is out of sync with enum acl_stats_idx");

	return (i >= 0 && i < AS_MAX) ? n[i] : "?";
}

static int cmd_stats(void)
{
	int fd = map_open("acl_stats");
	int ncpu = libbpf_num_possible_cpus();
	uint64_t *vals;

	if (fd < 0)
		return 1;
	if (ncpu <= 0)
		ncpu = 1;
	vals = calloc((size_t)ncpu, sizeof(*vals));
	if (!vals) {
		fprintf(stderr, "aclctl: out of memory\n");
		return 1;
	}

	for (uint32_t i = 0; i < AS_MAX; i++) {
		uint64_t sum = 0;

		if (bpf_map_lookup_elem(fd, &i, vals))
			continue;
		for (int c = 0; c < ncpu; c++)
			sum += vals[c];
		if (sum)
			printf("%-20s %llu\n", stat_name((int)i),
			       (unsigned long long)sum);
	}
	free(vals);
	close(fd);
	return 0;
}

/* ---- config ------------------------------------------------------------ */

static int cmd_show(void)
{
	struct acl_config cfg;
	uint32_t i;
	int fd;

	if (cfg_load(&fd, &cfg))
		return 1;
	printf("abi_version    %u\n", cfg.abi_version);
	printf("mode           %s (%u)\n", mode_name(cfg.mode), cfg.mode);
	printf("allow_v4_echo  %u\n", cfg.allow_v4_echo);
	printf("allow_v6_echo  %u\n", cfg.allow_v6_echo);
	printf("udp_timeout_ms %u\n", cfg.udp_timeout_ms);
	printf("tcp_timeout_ms %u\n", cfg.tcp_timeout_ms);
	printf("icmp_timeout_ms %u\n", cfg.icmp_timeout_ms);
	printf("mark           0x%08x (mask 0x%08x)\n", cfg.mark, ACL_MARK_MASK);
	printf("fullcone       %u\n", cfg.fullcone);
	printf("lan_count      %u\n", cfg.lan_count);
	for (i = 0; i < cfg.lan_count && i < ACL_MAX_LAN_V4; i++) {
		char nb[INET_ADDRSTRLEN], mb[INET_ADDRSTRLEN];
		struct in_addr a, m;

		a.s_addr = cfg.lan_v4[i].net;
		m.s_addr = cfg.lan_v4[i].mask;
		inet_ntop(AF_INET, &a, nb, sizeof(nb));
		inet_ntop(AF_INET, &m, mb, sizeof(mb));
		printf("lan_v4[%u]      %s/%s\n", i, nb, mb);
	}
	close(fd);
	return 0;
}

/* "192.168.10.0/24" -> network + mask. Only needed for the fullcone option. */
static int cidr_parse(const char *s, struct acl_lan_v4 *out)
{
	char buf[64];
	char *slash;
	struct in_addr a;
	uint32_t bits, mask;

	if (strlen(s) >= sizeof(buf))
		return -1;
	strcpy(buf, s);
	slash = strchr(buf, '/');
	if (!slash)
		return -1;
	*slash = '\0';
	if (inet_pton(AF_INET, buf, &a) != 1)
		return -1;
	bits = (uint32_t)strtoul(slash + 1, NULL, 10);
	if (bits > 32)
		return -1;
	mask = bits ? htonl(~0u << (32 - bits)) : 0;
	out->net = a.s_addr & mask;
	out->mask = mask;
	return 0;
}

static int cmd_set(int argc, char **argv)
{
	struct acl_config cfg;
	int fd, ret = 0;

	if (argc < 2) {
		fprintf(stderr, "usage: aclctl set "
			"<mode off|guard|bypass | echo 0|1 | v6echo 0|1 | "
			"timeouts UDP_MS TCP_MS ICMP_MS | mark HEX>\n");
		return 1;
	}
	if (cfg_load(&fd, &cfg))
		return 1;

	if (!strcmp(argv[0], "mode")) {
		if (mode_parse(argv[1], &cfg.mode)) {
			fprintf(stderr, "aclctl: bad mode '%s'\n", argv[1]);
			ret = 1;
			goto out;
		}
	} else if (!strcmp(argv[0], "echo")) {
		cfg.allow_v4_echo = atoi(argv[1]) ? 1 : 0;
	} else if (!strcmp(argv[0], "v6echo")) {
		cfg.allow_v6_echo = atoi(argv[1]) ? 1 : 0;
	} else if (!strcmp(argv[0], "timeouts")) {
		if (argc < 4) {
			fprintf(stderr, "aclctl: timeouts needs 3 values\n");
			ret = 1;
			goto out;
		}
		cfg.udp_timeout_ms = (uint32_t)strtoul(argv[1], NULL, 10);
		cfg.tcp_timeout_ms = (uint32_t)strtoul(argv[2], NULL, 10);
		cfg.icmp_timeout_ms = (uint32_t)strtoul(argv[3], NULL, 10);
	} else if (!strcmp(argv[0], "mark")) {
		cfg.mark = (uint32_t)strtoul(argv[1], NULL, 0);
	} else if (!strcmp(argv[0], "fullcone")) {
		cfg.fullcone = atoi(argv[1]) ? 1 : 0;
	} else if (!strcmp(argv[0], "lan")) {
		uint32_t n = 0;
		int i;

		for (i = 1; i < argc && n < ACL_MAX_LAN_V4; i++) {
			if (cidr_parse(argv[i], &cfg.lan_v4[n])) {
				fprintf(stderr, "aclctl: bad CIDR '%s'\n",
					argv[i]);
				ret = 1;
				goto out;
			}
			n++;
		}
		/* clear the tail so a shrinking list leaves nothing stale */
		for (; n < ACL_MAX_LAN_V4; n++) {
			cfg.lan_v4[n].net = 0;
			cfg.lan_v4[n].mask = 0;
		}
		cfg.lan_count = n;
	} else {
		fprintf(stderr, "aclctl: unknown setting '%s'\n", argv[0]);
		ret = 1;
		goto out;
	}

	/* stamp the ABI on every write so a freshly attached, never-configured
	 * map stops reporting "abi 0" from `aclctl show` */
	cfg.abi_version = ACL_ABI_VERSION;
	if (cfg_store(fd, &cfg))
		ret = 1;
out:
	close(fd);
	return ret;
}

/* ---- port allow list --------------------------------------------------- */

static int port_key(const char *fams, const char *prots, const char *scopes,
		    const char *ports, struct acl_port_key *k)
{
	if (family_parse(fams, &k->family)) {
		fprintf(stderr, "aclctl: bad family '%s'\n", fams);
		return -1;
	}
	if (proto_parse(prots, &k->proto)) {
		fprintf(stderr, "aclctl: bad proto '%s'\n", prots);
		return -1;
	}
	if (scope_parse(scopes, &k->scope)) {
		fprintf(stderr, "aclctl: bad scope '%s'\n", scopes);
		return -1;
	}
	k->port = htons((uint16_t)strtoul(ports, NULL, 10));
	return 0;
}

static int cmd_port(int argc, char **argv)
{
	struct acl_port_key k;
	struct acl_port_val v = {};
	int fd;

	if (argc < 1) {
		fprintf(stderr, "usage: aclctl port "
			"<add 4|6 PROTO forward|input PORT | "
			"del 4|6 PROTO forward|input PORT | flush | list>\n");
		return 1;
	}
	fd = map_open("acl_ports");
	if (fd < 0)
		return 1;

	if (!strcmp(argv[0], "flush")) {
		struct acl_port_key cur;

		while (bpf_map_get_next_key(fd, NULL, &cur) == 0)
			if (bpf_map_delete_elem(fd, &cur))
				break;
		close(fd);
		return 0;
	}

	if (!strcmp(argv[0], "list")) {
		struct acl_port_key cur, next;
		int have = bpf_map_get_next_key(fd, NULL, &cur) == 0;

		while (have) {
			if (bpf_map_get_next_key(fd, &cur, &next))
				have = 0;
			printf("%-5s %-7s %-8s %u\n", family_name(cur.family),
			       proto_name(cur.proto), scope_name(cur.scope),
			       ntohs(cur.port));
			cur = next;
		}
		close(fd);
		return 0;
	}

	if (argc < 5) {
		fprintf(stderr, "aclctl: port %s needs 4 arguments\n", argv[0]);
		close(fd);
		return 1;
	}
	if (port_key(argv[1], argv[2], argv[3], argv[4], &k)) {
		close(fd);
		return 1;
	}

	if (!strcmp(argv[0], "add")) {
		if (bpf_map_update_elem(fd, &k, &v, BPF_NOEXIST) &&
		    errno != EEXIST) {
			fprintf(stderr, "aclctl: add: %s\n", strerror(errno));
			close(fd);
			return 1;
		}
	} else if (!strcmp(argv[0], "del")) {
		if (bpf_map_delete_elem(fd, &k) && errno != ENOENT) {
			fprintf(stderr, "aclctl: del: %s\n", strerror(errno));
			close(fd);
			return 1;
		}
	} else {
		fprintf(stderr, "aclctl: unknown port command '%s'\n", argv[0]);
		close(fd);
		return 1;
	}
	close(fd);
	return 0;
}

/* ---- learned state ----------------------------------------------------- */

static int cmd_flush(void)
{
	struct acl_v4_key k4;
	struct acl_v6_key k6;
	int fd = map_open("acl_v4_flows");

	if (fd < 0)
		return 1;
	/* always take the first key and delete it, so there is no cursor to
	 * invalidate while the map shrinks underneath us */
	while (bpf_map_get_next_key(fd, NULL, &k4) == 0)
		if (bpf_map_delete_elem(fd, &k4))
			break;
	close(fd);

	fd = map_open("acl_v6_flows");
	if (fd < 0)
		return 1;
	while (bpf_map_get_next_key(fd, NULL, &k6) == 0)
		if (bpf_map_delete_elem(fd, &k6))
			break;
	close(fd);
	return 0;
}

static int cmd_flows(void)
{
	struct acl_v4_key k, next;
	int fd = map_open("acl_v4_flows");
	int have;

	if (fd < 0)
		return 1;
	have = bpf_map_get_next_key(fd, NULL, &k) == 0;
	while (have) {
		struct acl_v4_val v;

		if (bpf_map_get_next_key(fd, &k, &next))
			have = 0;
		if (bpf_map_lookup_elem(fd, &k, &v) == 0) {
			char ip[INET_ADDRSTRLEN];
			struct in_addr a;

			a.s_addr = k.ip;
			if (!inet_ntop(AF_INET, &a, ip, sizeof(ip)))
				strcpy(ip, "?");
			printf("%-7s %-16s %-6u %-10s %u\n", proto_name(k.proto),
			       ip, ntohs(k.port),
			       v.forwarded ? "forwarded" : "local",
			       v.packets);
		}
		k = next;
	}
	close(fd);
	return 0;
}

static int cmd_version(void)
{
	printf("aclctl %u (abi %u)\n", 1, ACL_ABI_VERSION);
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
		"usage: aclctl <command>\n"
		"  show                      configuration\n"
		"  stats                     packet counters\n"
		"  set mode off|guard|bypass\n"
		"  set echo 0|1              allow ICMP echo from the WAN\n"
		"  set v6echo 0|1            allow ICMPv6 echo from the WAN\n"
		"  set timeouts UDP TCP ICMP (milliseconds)\n"
		"  set mark HEX              skb mark written in bypass mode\n"
		"  set fullcone 0|1          also accept inbound to a LAN prefix\n"
		"  set lan CIDR [CIDR...]    the LAN prefixes fullcone matches\n"
		"  port add|del 4|6 PROTO forward|input PORT\n"
		"  port list | port flush\n"
		"  flows                     learned IPv4 flows (proto, remote)\n"
		"  flush                     forget all learned state\n"
		"  version\n");
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage();
		return 1;
	}
	if (!strcmp(argv[1], "show"))
		return cmd_show();
	if (!strcmp(argv[1], "stats"))
		return cmd_stats();
	if (!strcmp(argv[1], "set"))
		return cmd_set(argc - 2, argv + 2);
	if (!strcmp(argv[1], "port"))
		return cmd_port(argc - 2, argv + 2);
	if (!strcmp(argv[1], "flows"))
		return cmd_flows();
	if (!strcmp(argv[1], "flush"))
		return cmd_flush();
	if (!strcmp(argv[1], "version"))
		return cmd_version();

	usage();
	return 1;
}
