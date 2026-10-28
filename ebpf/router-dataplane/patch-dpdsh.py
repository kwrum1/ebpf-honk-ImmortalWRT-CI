import io
p = r"C:\路由设计\work\gh\src\ebpf\router-dataplane\files\dpd-fastpath.sh"
s = io.open(p, encoding="utf-8").read()

old = '''dpd_push_uci() {
\tlocal enabled="$1" mode="$2" redirect="$3" ttl="$4" policy="$5"

\t[ -x "$DPD_CTL" ] || return 0
\t"$DPD_CTL" set mode "$mode" 2>/dev/null
\t"$DPD_CTL" set redirect "$redirect" 2>/dev/null
\t"$DPD_CTL" set ttl "$ttl" 2>/dev/null
\t[ -n "$policy" ] && "$DPD_CTL" set policy "$policy" 2>/dev/null
\t"$DPD_CTL" set enable "$enabled" 2>/dev/null
\treturn 0
}
'''
new = '''dpd_push_uci() {
\tlocal enabled="$1" mode="$2" redirect="$3" ttl="$4" policy="$5"
\tlocal refresh="$6"

\t[ -x "$DPD_CTL" ] || return 0
\t"$DPD_CTL" set mode "$mode" 2>/dev/null
\t"$DPD_CTL" set redirect "$redirect" 2>/dev/null
\t"$DPD_CTL" set ttl "$ttl" 2>/dev/null
\t[ -n "$refresh" ] && "$DPD_CTL" set refresh "$refresh" 2>/dev/null
\t[ -n "$policy" ] && "$DPD_CTL" set policy "$policy" 2>/dev/null
\t"$DPD_CTL" set enable "$enabled" 2>/dev/null
\treturn 0
}

# Drop every cached egress decision in one store. Called when something that a
# cached entry depends on changed (link state, address, route, neighbour, WAN
# table). Without it the hit path would have to re-validate dpd_wans and
# dpd_iface for every packet -- which is exactly what ABI 9 removed.
dpd_bump_epoch() {
\t[ -x "$DPD_CTL" ] || return 0
\t"$DPD_CTL" bump >/dev/null 2>&1
\treturn 0
}

# The map value layout is part of the pinned-map ABI. A package upgrade that
# changes it makes libbpf refuse to reuse /sys/fs/bpf/dpd_*, and `tc filter add`
# then fails with a pin error that says nothing about the real cause. Compare the
# ABI the object was built with (installed by the package) with the one the
# pinned map still has, and drop the pins when they differ.
dpd_pins_compat() {
\tlocal want cur

\t[ -r /usr/lib/dpd/abi ] || return 0
\twant="$(cat /usr/lib/dpd/abi 2>/dev/null)"
\t[ -n "$want" ] || return 0
\tcur="$("$DPD_CTL" abi 2>/dev/null)"
\t[ -n "$cur" ] || return 0
\t[ "$cur" = "$want" ] && return 0

\tdpd_log "ABI changed ($cur -> $want): dropping stale pinned maps"
\trm -f /sys/fs/bpf/dpd_cfg /sys/fs/bpf/dpd_stats /sys/fs/bpf/dpd_flows \\
\t\t/sys/fs/bpf/dpd_iface /sys/fs/bpf/dpd_vlans /sys/fs/bpf/dpd_wans 2>/dev/null
\treturn 0
}
'''
assert old in s
s = s.replace(old, new)
io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("dpd-fastpath.sh patched")
