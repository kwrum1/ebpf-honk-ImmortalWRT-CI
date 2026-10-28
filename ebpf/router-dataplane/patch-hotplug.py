import io
p = r"C:\路由设计\work\gh\src\mydist\router-dataplane\files\90-dpd-fastpath"
s = io.open(p, encoding="utf-8").read()

old = '''\tconfig_get DPD_TTL global flow_ttl_ms 5000
'''
new = '''\tconfig_get DPD_TTL global flow_ttl_ms 5000
\tconfig_get DPD_REFRESH global flow_refresh_ms 250
'''
assert old in s
s = s.replace(old, new)

old = '''\t"$DPD_CTL" set ttl "$DPD_TTL" 2>/dev/null
'''
new = '''\t"$DPD_CTL" set ttl "$DPD_TTL" 2>/dev/null
\t"$DPD_CTL" set refresh "$DPD_REFRESH" 2>/dev/null
'''
assert old in s
s = s.replace(old, new)

# bump the epoch on every link/address event: a cached entry may now point at a
# device, route or neighbour that moved
old = '''case "$ACTION" in
ifup|ifupdate|add|update)
\tdpd_uci
'''
new = '''case "$ACTION" in
ifup|ifupdate|add|update)
\tdpd_uci
\t# Any link/address event can invalidate a cached egress (new device index,
\t# new route, flushed neighbour). One store drops the whole cache instead
\t# of the per-packet re-validation ABI 9 removed.
\tdpd_bump_epoch
'''
assert old in s
s = s.replace(old, new)

old = '''ifdown|remove)
\t[ -n "$DEVICE" ] || exit 0
\tdpd_detach_if "$DEVICE"
'''
new = '''ifdown|remove)
\t[ -n "$DEVICE" ] || exit 0
\tdpd_detach_if "$DEVICE"
\tdpd_bump_epoch
'''
assert old in s
s = s.replace(old, new)

io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("hotplug patched")
