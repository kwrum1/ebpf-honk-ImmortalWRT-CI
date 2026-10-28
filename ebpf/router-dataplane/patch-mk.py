import io
p = r"C:\路由设计\work\gh\src\ebpf\router-dataplane\Makefile"
s = io.open(p, encoding="utf-8").read()

old = '''\t$(CLANG) $(DPD_BPF_FLAGS) $(DPD_BPF_INCLUDES) \\
\t\t-c $(PKG_BUILD_DIR)/src/dpd_fastpath.bpf.c \\
\t\t-o $(PKG_BUILD_DIR)/dpd_fastpath.bpf.o
'''
new = '''\t$(CLANG) $(DPD_BPF_FLAGS) $(DPD_BPF_INCLUDES) \\
\t\t-c $(PKG_BUILD_DIR)/src/dpd_fastpath.bpf.c \\
\t\t-o $(PKG_BUILD_DIR)/dpd_fastpath.bpf.o
\t# ABI stamp: the init script compares it with the ABI of the pinned maps and
\t# drops the pins when an upgrade changed the value layout.
\tgrep -oP '^#define DPD_ABI_VERSION\\s+\\K[0-9]+' \\
\t\t$(PKG_BUILD_DIR)/src/dpd_common.h > $(PKG_BUILD_DIR)/abi
'''
assert old in s
s = s.replace(old, new)

old = '''\t$(INSTALL_DIR) $(1)/lib/bpf
'''
new = '''\t$(INSTALL_DIR) $(1)/lib/bpf
\t$(INSTALL_DIR) $(1)/usr/lib/dpd
'''
assert old in s
s = s.replace(old, new)

old = '''\t$(INSTALL_DATA) $(PKG_BUILD_DIR)/dpd_fastpath.bpf.o $(1)/lib/bpf/
'''
new = '''\t$(INSTALL_DATA) $(PKG_BUILD_DIR)/dpd_fastpath.bpf.o $(1)/lib/bpf/
\t$(INSTALL_DATA) $(PKG_BUILD_DIR)/abi $(1)/usr/lib/dpd/abi
'''
assert old in s
s = s.replace(old, new)

io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("Makefile patched")
