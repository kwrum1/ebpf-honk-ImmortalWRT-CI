// dpd-einat-sync: mirror einat's full-cone bindings into DPD's dpd_nat map.
//
// einat owns the allocation; this daemon only copies the ORIGIN-direction
// binding (key.flags has BINDING_ORIG_DIR_FLAG: internal addr/port ->
// external addr/port) into the map the DPD BPF hit path reads.
//
// No libbpf dependency: raw bpf(2) syscalls. The two maps are resolved from
// the *live* programs' map_ids instead of by name: a restart of einat or of
// dpd-fastpath leaves stale maps with the same name behind, and a name lookup
// would silently mirror into (or read from) the dead instance.
#include <linux/bpf.h>
#include <linux/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>

#define BINDING_ORIG_DIR_FLAG 1
#define ADDR_IPV4_FLAG 2

struct binding_key {
	__u32 ifindex;
	__u8 flags;
	__u8 l4proto;
	__u16 from_port;
	__u32 from_addr;
} __attribute__((packed));

struct binding_val {
	__u32 to_addr;
	__u16 to_port;
	__u8 flags;
	__u8 is_static;
	__u32 outbound_ref;
	__u32 ref;
	__u32 seq;
	__u32 ct_state_cached;
	__u32 ct_touch_ms;
} __attribute__((packed));

struct nat_key {
	__u32 saddr;
	__u16 sport;
	__u8 proto;
	__u8 pad;
} __attribute__((packed));

struct nat_val {
	__u32 to_addr;
	__u16 to_port;
	__u16 pad;
} __attribute__((packed));

/* ABI 19: reverse binding (external tuple -> internal tuple). */
struct nat_rev_key {
	__u32 daddr;
	__u16 dport;
	__u8 proto;
	__u8 pad;
} __attribute__((packed));

struct nat_rev_val {
	__u32 saddr;
	__u16 sport;
	__u16 pad;
	__u32 ts_ms;	/* ABI 20: 0 = mirrored/foreign, never a DPD stamp */
} __attribute__((packed));

static int bpf_call(enum bpf_cmd cmd, union bpf_attr *attr)
{
	return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int map_fd_by_id(__u32 id)
{
	union bpf_attr a;

	memset(&a, 0, sizeof(a));
	a.map_id = id;
	return bpf_call(BPF_MAP_GET_FD_BY_ID, &a);
}

static int map_name(int fd, char *out, size_t len)
{
	struct bpf_map_info info;
	union bpf_attr a;

	memset(&info, 0, sizeof(info));
	memset(&a, 0, sizeof(a));
	a.info.bpf_fd = fd;
	a.info.info_len = sizeof(info);
	a.info.info = (uintptr_t)&info;
	if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &a) < 0)
		return -1;
	snprintf(out, len, "%s", (char *)info.name);
	return 0;
}

static int map_fd_by_name(const char *want)
{
	__u32 id = 0;

	for (;;) {
		union bpf_attr a;
		char name[32];
		int fd;

		memset(&a, 0, sizeof(a));
		a.start_id = id;
		if (bpf_call(BPF_MAP_GET_NEXT_ID, &a) < 0)
			return -1;
		id = a.next_id;
		fd = map_fd_by_id(id);
		if (fd < 0)
			continue;
		if (map_name(fd, name, sizeof(name)) == 0 &&
		    strcmp(name, want) == 0)
			return fd;
		close(fd);
	}
}

static int prog_fd_by_name(const char *want)
{
	__u32 id = 0;

	for (;;) {
		union bpf_attr a;
		struct bpf_prog_info info;
		char name[32];
		int fd;

		memset(&a, 0, sizeof(a));
		a.start_id = id;
		if (bpf_call(BPF_PROG_GET_NEXT_ID, &a) < 0)
			return -1;
		id = a.next_id;

		memset(&a, 0, sizeof(a));
		a.prog_id = id;
		fd = bpf_call(BPF_PROG_GET_FD_BY_ID, &a);
		if (fd < 0)
			continue;

		memset(&info, 0, sizeof(info));
		memset(&a, 0, sizeof(a));
		a.info.bpf_fd = fd;
		a.info.info_len = sizeof(info);
		a.info.info = (uintptr_t)&info;
		if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &a) < 0) {
			close(fd);
			continue;
		}
		snprintf(name, sizeof(name), "%s", (char *)info.name);
		if (strcmp(name, want) == 0)
			return fd;
		close(fd);
	}
}

/* Resolve a map owned by the given program, by name. This is what keeps us on
 * the live instance when a previous one left orphaned maps behind. */
static int map_fd_in_prog(int prog_fd, const char *want)
{
	struct bpf_prog_info info;
	union bpf_attr a;
	__u32 *ids;
	__u32 len;
	int found = -1;

	memset(&info, 0, sizeof(info));
	memset(&a, 0, sizeof(a));
	a.info.bpf_fd = prog_fd;
	a.info.info_len = sizeof(info);
	a.info.info = (uintptr_t)&info;
	if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &a) < 0)
		return -1;

	if (info.nr_map_ids == 0)
		return -1;
	ids = calloc(info.nr_map_ids, sizeof(*ids));
	if (!ids)
		return -1;

	memset(&info, 0, sizeof(info));
	info.nr_map_ids = 0;
	info.map_ids = (uintptr_t)ids;
	memset(&a, 0, sizeof(a));
	a.info.bpf_fd = prog_fd;
	a.info.info_len = sizeof(info);
	a.info.info = (uintptr_t)&info;
	if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &a) < 0) {
		free(ids);
		return -1;
	}

	len = info.nr_map_ids;
	for (__u32 i = 0; i < len; i++) {
		char name[32];
		int fd = map_fd_by_id(ids[i]);

		if (fd < 0)
			continue;
		if (map_name(fd, name, sizeof(name)) == 0 &&
		    strcmp(name, want) == 0) {
			found = fd;
			break;
		}
		close(fd);
	}
	free(ids);
	return found;
}

static int pinned_fd(const char *path)
{
	union bpf_attr a;

	memset(&a, 0, sizeof(a));
	a.pathname = (uintptr_t)path;
	return bpf_call(BPF_OBJ_GET, &a);
}

static int nat_fd(void)
{
	int pfd = prog_fd_by_name("dpd_fastpath_l2");
	int fd = -1;

	if (pfd >= 0) {
		fd = map_fd_in_prog(pfd, "dpd_nat");
		close(pfd);
	}
	if (fd < 0)
		fd = pinned_fd("/sys/fs/bpf/tc/globals/dpd_nat");
	if (fd < 0)
		fd = map_fd_by_name("dpd_nat");
	return fd;
}

static int rev_fd(void)
{
	int pfd = prog_fd_by_name("dpd_fastpath_l2");
	int fd = -1;

	if (pfd >= 0) {
		fd = map_fd_in_prog(pfd, "dpd_nat_rev");
		close(pfd);
	}
	if (fd < 0)
		fd = pinned_fd("/sys/fs/bpf/tc/globals/dpd_nat_rev");
	if (fd < 0)
		fd = map_fd_by_name("dpd_nat_rev");
	return fd;
}

static int binding_fd(void)
{
	static const char *const progs[] = { "egress_snat", "ingress_rev_snat" };

	for (unsigned int i = 0; i < sizeof(progs) / sizeof(progs[0]); i++) {
		int pfd = prog_fd_by_name(progs[i]);
		int fd;

		if (pfd < 0)
			continue;
		fd = map_fd_in_prog(pfd, "map_binding");
		close(pfd);
		if (fd >= 0)
			return fd;
	}
	return map_fd_by_name("map_binding");
}

static int sync_once(int bind_fd, int nat, int rev)
{
	struct binding_key key, next;
	struct binding_val val;
	int have = 0, updated = 0;

	for (;;) {
		union bpf_attr a;

		memset(&a, 0, sizeof(a));
		a.map_fd = bind_fd;
		a.key = have ? (uintptr_t)&key : 0;
		a.next_key = (uintptr_t)&next;
		if (bpf_call(BPF_MAP_GET_NEXT_KEY, &a) < 0)
			break;

		memset(&a, 0, sizeof(a));
		a.map_fd = bind_fd;
		a.key = (uintptr_t)&next;
		a.value = (uintptr_t)&val;
		if (bpf_call(BPF_MAP_LOOKUP_ELEM, &a) == 0 &&
		    next.l4proto != 0 &&
		    val.to_addr != 0 && val.to_port != 0 &&
		    /* identity entries are the NAT host's own traffic */
		    (val.to_addr != next.from_addr ||
		     val.to_port != next.from_port)) {
			if (next.flags & BINDING_ORIG_DIR_FLAG) {
				/* internal -> external: forward SNAT gate */
				struct nat_key nk;
				struct nat_val nv;

				memset(&nk, 0, sizeof(nk));
				memset(&nv, 0, sizeof(nv));
				nk.saddr = next.from_addr;
				nk.sport = next.from_port;
				nk.proto = next.l4proto;
				nv.to_addr = val.to_addr;
				nv.to_port = val.to_port;

				if (nat >= 0) {
					memset(&a, 0, sizeof(a));
					a.map_fd = nat;
					a.key = (uintptr_t)&nk;
					a.value = (uintptr_t)&nv;
					a.flags = BPF_ANY;
					if (bpf_call(BPF_MAP_UPDATE_ELEM,
						     &a) == 0)
						updated++;
				}
			} else if (rev >= 0) {
				/* external -> internal: return-path DNAT */
				struct nat_rev_key rk;
				struct nat_rev_val rv;

				memset(&rk, 0, sizeof(rk));
				memset(&rv, 0, sizeof(rv));
				rk.daddr = next.from_addr;
				rk.dport = next.from_port;
				rk.proto = next.l4proto;
				rv.saddr = val.to_addr;
				rv.sport = val.to_port;

				memset(&a, 0, sizeof(a));
				a.map_fd = rev;
				a.key = (uintptr_t)&rk;
				a.value = (uintptr_t)&rv;
				a.flags = BPF_ANY;
				if (bpf_call(BPF_MAP_UPDATE_ELEM, &a) == 0)
					updated++;
			}
		}
		key = next;
		have = 1;
	}
	return updated;
}

int main(void)
{
	int bind_fd = -1, nat = -1, rev = -1;
	time_t last_log = 0;
	time_t last_resolve = 0;

	for (;;) {
		time_t now = time(NULL);

		if (bind_fd < 0 || (nat < 0 && rev < 0) ||
		    now - last_resolve >= 5) {
			if (bind_fd >= 0)
				close(bind_fd);
			if (nat >= 0)
				close(nat);
			if (rev >= 0)
				close(rev);
			bind_fd = binding_fd();
			nat = nat_fd();
			rev = rev_fd();
			last_resolve = now;
		}

		if (bind_fd >= 0 && (nat >= 0 || rev >= 0)) {
			int n = sync_once(bind_fd, nat, rev);

			if (now - last_log >= 60 || n) {
				printf("dpd-einat-sync: mirrored %d binding(s)\n", n);
				fflush(stdout);
				last_log = now;
			}
		}
		sleep(1);
	}
}
