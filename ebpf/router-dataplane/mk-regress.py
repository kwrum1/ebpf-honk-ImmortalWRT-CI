import io
p = r"C:\路由设计\work\gh\src\ebpf\router-dataplane\Makefile"
s = io.open(p, encoding="utf-8").read()
old = "\t$(INSTALL_BIN) ./files/dpd-gate-watchdog $(1)/usr/libexec/dpd-gate-watchdog\n"
new = old + "\t$(INSTALL_BIN) ./files/dpd-regress.sh $(1)/usr/libexec/dpd-regress.sh\n"
assert old in s
s = s.replace(old, new)
io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("regress installed")
