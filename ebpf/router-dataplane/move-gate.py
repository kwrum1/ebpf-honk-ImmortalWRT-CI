import io
p = r"C:\路由设计\work\gh\src\mydist\router-dataplane\src\dpd_fastpath.bpf.c"
s = io.open(p, encoding="utf-8").read()

gate = '''	/* Every gate below needs no route: family, :53, DHCP, non-unicast and
	 * the VLAN policy all read the flow key or the config. Running them
	 * before bpf_fib_lookup() is what keeps DNS/broadcast/v6 traffic from
	 * paying for an acceleration it can never get. */
	if (!dpd_may_accelerate(cfg, vlan_id, tagged, &fkey, st))
		return TC_ACT_UNSPEC;

'''
assert gate in s
s = s.replace(gate, "", 1)

anchor = '''	/* ---- FIB lookup, shared by every mode ---- */
'''
assert anchor in s
s = s.replace(anchor, gate + anchor, 1)

io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("gate moved after the hit path")
