import io
p = r"C:\路由设计\work\gh\src\ebpf\router-dataplane\files\dpd-fastpath.sh"
s = io.open(p, encoding="utf-8").read()

old = '''dpd_gate_refresh_uci() {
\tlocal enabled mode redirect ttl policy vlans emode

\tconfig_load dpd_fastpath
\tconfig_get_bool enabled global enabled 1
\tconfig_get mode global mode off
\tconfig_get redirect global redirect auto
\tconfig_get ttl global flow_ttl_ms 5000
\tconfig_get policy global policy 'allow_all'
\tconfig_get vlans global vlans ''

\temode="$(dpd_gate_mode "$mode")"
\tdpd_push_uci "$enabled" "$emode" "$redirect" "$ttl" "$policy"
\tdpd_push_vlans "$policy" "$vlans"
'''
new = '''dpd_gate_refresh_uci() {
\tlocal enabled mode redirect ttl policy vlans refresh emode

\tconfig_load dpd_fastpath
\tconfig_get_bool enabled global enabled 1
\tconfig_get mode global mode off
\tconfig_get redirect global redirect auto
\tconfig_get ttl global flow_ttl_ms 5000
\tconfig_get refresh global flow_refresh_ms 250
\tconfig_get policy global policy 'allow_all'
\tconfig_get vlans global vlans ''

\temode="$(dpd_gate_mode "$mode")"
\tdpd_push_uci "$enabled" "$emode" "$redirect" "$ttl" "$policy" "$refresh"
\tdpd_push_vlans "$policy" "$vlans"
'''
assert old in s
s = s.replace(old, new)
io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("refresh wired into gate refresh")
