/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * dpd_bpf.h - the four bpf(2) operations dpdctl needs, without libbpf.
 *
 * dpdctl only ever *reads and writes pinned maps*. libbpf would give us the
 * same thing plus an ELF loader, a ring-buffer API and a dependency chain
 * (libbpf -> libelf -> zlib) that a 20 KB control tool does not use. Keeping
 * the syscall layer here instead has two concrete benefits:
 *
 *   - the package's control binary has no runtime dependency beyond libc, so
 *     it can be built with any cross compiler (including a static musl one)
 *     and still run on an image whose libbpf version differs;
 *   - CI can compile it with `cc` alone, without installing libbpf-dev just
 *     to check that a typo in a printf does not reach the image build.
 *
 * The wrappers mirror the libbpf prototypes dpdctl used before, so the call
 * sites stay readable. Nothing here loads a program: pinning and tc(8) own
 * that (see files/dpd_fastpath.init).
 */

#ifndef __DPD_BPF_H
#define __DPD_BPF_H

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <linux/bpf.h>

/* Some musl headers put __NR_bpf behind _GNU_SOURCE; dpdctl defines it. */
#ifndef __NR_bpf
#error "no __NR_bpf on this architecture"
#endif

static inline int dpd_sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			      unsigned int size)
{
	return (int)syscall(__NR_bpf, cmd, attr, size);
}

static inline int dpd_bpf_obj_get(const char *path)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.pathname = (unsigned long)path;
	return dpd_sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

static inline int dpd_bpf_map_get_next_id(__u32 id, __u32 *next)
{
	union bpf_attr attr;
	int r;

	memset(&attr, 0, sizeof(attr));
	attr.start_id = id;
	r = dpd_sys_bpf(BPF_MAP_GET_NEXT_ID, &attr, sizeof(attr));
	if (!r)
		*next = attr.next_id;
	return r;
}

static inline int dpd_bpf_map_get_fd_by_id(__u32 id)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_id = id;
	return dpd_sys_bpf(BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
}

static inline int dpd_bpf_map_get_info_by_fd(int fd, struct bpf_map_info *info,
					     __u32 *len)
{
	union bpf_attr attr;
	int r;

	memset(&attr, 0, sizeof(attr));
	attr.info.bpf_fd = (__u32)fd;
	attr.info.info_len = *len;
	attr.info.info = (unsigned long)info;
	r = dpd_sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
	if (!r)
		*len = attr.info.info_len;
	return r;
}

static inline int dpd_bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (__u32)fd;
	attr.key = (unsigned long)key;
	attr.value = (unsigned long)value;
	return dpd_sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static inline int dpd_bpf_map_update_elem(int fd, const void *key,
					  const void *value, __u64 flags)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (__u32)fd;
	attr.key = (unsigned long)key;
	attr.value = (unsigned long)value;
	attr.flags = flags;
	return dpd_sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static inline int dpd_bpf_map_get_next_key(int fd, const void *key, void *next)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (__u32)fd;
	attr.key = (unsigned long)key;
	attr.next_key = (unsigned long)next;
	return dpd_sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

static inline int dpd_bpf_map_delete_elem(int fd, const void *key)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (__u32)fd;
	attr.key = (unsigned long)key;
	return dpd_sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

/*
 * Number of possible CPUs, i.e. the stride of a per-CPU map value. libbpf
 * reads the first line of /sys/devices/system/cpu/possible and counts the
 * CPUs in its ranges ("0-3,8-9" -> 6); the same parse lives here so a
 * per-CPU stats block is decoded identically. 1 on any failure, which is
 * what the kernel does for a missing file too.
 */
static inline int dpd_num_possible_cpus(void)
{
	FILE *f;
	char buf[256];
	int n = 0;
	char *p;

	f = fopen("/sys/devices/system/cpu/possible", "r");
	if (!f)
		return 1;
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return 1;
	}
	fclose(f);

	buf[strcspn(buf, "\n")] = '\0';
	p = buf;
	while (*p) {
		long lo, hi;

		while (*p == ',' || isspace((unsigned char)*p))
			p++;
		if (!isdigit((unsigned char)*p))
			break;
		lo = strtol(p, &p, 10);
		hi = lo;
		if (*p == '-') {
			p++;
			hi = strtol(p, &p, 10);
		}
		if (hi >= lo)
			n += (int)(hi - lo + 1);
	}
	return n > 0 ? n : 1;
}

#endif /* __DPD_BPF_H */
