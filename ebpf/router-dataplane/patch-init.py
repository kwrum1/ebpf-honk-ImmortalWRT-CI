import io
p = r"C:\路由设计\work\gh\src\mydist\router-dataplane\files\dpd_fastpath.init"
s = io.open(p, encoding="utf-8").read()

old = '''\tlocal enabled attach mode emode policy vlans redirect ttl ifaces i dev nok=0 pending=
'''
new = '''\tlocal enabled attach mode emode policy vlans redirect ttl refresh ifaces i dev nok=0 pending=
'''
assert old in s
s = s.replace(old, new)

old = '''\tconfig_get ttl global flow_ttl_ms 5000
\tconfig_get ifaces global interfaces 'lan'
'''
new = '''\tconfig_get ttl global flow_ttl_ms 5000
\tconfig_get refresh global flow_refresh_ms 250
\tconfig_get ifaces global interfaces 'lan'
'''
assert old in s
s = s.replace(old, new)

old = '''\t# On restart/reload the program may already be loaded, so publish first;
\t# attaching below does not change these values.
\tdpd_push_uci "$enabled" "$emode" "$redirect" "$ttl" "$policy"
'''
new = '''\t# An upgraded image may leave pins whose map value layout no longer matches
\t# the object (dpd_stats became a block in ABI 9). libbpf then refuses to
\t# reuse them and the attach fails with a pin error; drop them first.
\tdpd_pins_compat

\t# On restart/reload the program may already be loaded, so publish first;
\t# attaching below does not change these values.
\tdpd_push_uci "$enabled" "$emode" "$redirect" "$ttl" "$policy" "$refresh"
'''
assert old in s
s = s.replace(old, new)

s = s.replace('dpd_push_uci "$enabled" "$emode" "$redirect" "$ttl" "$policy"',
              'dpd_push_uci "$enabled" "$emode" "$redirect" "$ttl" "$policy" "$refresh"')

io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("init patched")
