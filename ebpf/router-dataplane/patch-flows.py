import io
p = r"C:\路由设计\work\gh\src\mydist\router-dataplane\src\dpdctl.c"
s = io.open(p, encoding="utf-8").read()

old = '''\t\t\tprintf("%-10s fam=%u proto=%u egress=%-10s age=%llums "
\t\t\t       "dmac=%02x:%02x:%02x:%02x:%02x:%02x "
\t\t\t       "smac=%02x:%02x:%02x:%02x:%02x:%02x%s\\n",
\t\t\t       ifname(k.ifindex), k.family, k.proto,
\t\t\t       ifname(v.egress_ifindex),
\t\t\t       (unsigned long long)age_ms,
\t\t\t       v.dmac[0], v.dmac[1], v.dmac[2],
\t\t\t       v.dmac[3], v.dmac[4], v.dmac[5],
\t\t\t       v.smac[0], v.smac[1], v.smac[2],
\t\t\t       v.smac[3], v.smac[4], v.smac[5],
\t\t\t       (v.flags & DPD_FLOW_F_NO_NEIGH) ? " no-neigh" : "");'''
new = '''\t\t\tprintf("%-10s fam=%u proto=%u egress=%-10s wan=%u epoch=%u "
\t\t\t       "cls=%s age=%llums "
\t\t\t       "dmac=%02x:%02x:%02x:%02x:%02x:%02x "
\t\t\t       "smac=%02x:%02x:%02x:%02x:%02x:%02x%s\\n",
\t\t\t       ifname(k.ifindex), k.family, k.proto,
\t\t\t       ifname(v.egress_ifindex),
\t\t\t       (unsigned)(v.wan & 0xff),
\t\t\t       (unsigned)((v.wan & DPD_FLOW_EPOCH_MASK) >> 8),
\t\t\t       (v.flags & DPD_FLOW_F_L2) ? "l2" :
\t\t\t       (v.flags & DPD_FLOW_F_DEV) ? "dev" : "neigh",
\t\t\t       (unsigned long long)age_ms,
\t\t\t       v.dmac[0], v.dmac[1], v.dmac[2],
\t\t\t       v.dmac[3], v.dmac[4], v.dmac[5],
\t\t\t       v.smac[0], v.smac[1], v.smac[2],
\t\t\t       v.smac[3], v.smac[4], v.smac[5],
\t\t\t       (v.flags & DPD_FLOW_F_NO_NEIGH) ? " no-neigh" : "");'''
assert old in s
s = s.replace(old, new)
io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("flows print patched")
