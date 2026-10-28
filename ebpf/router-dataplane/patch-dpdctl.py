import io
p = r"C:\路由设计\work\gh\src\mydist\router-dataplane\src\dpdctl.c"
s = io.open(p, encoding="utf-8").read()

s = s.replace("/* Move the flow-cache generation. Every entry rememberc the epoch it was",
              "/* Move the flow-cache generation. Every entry remembers the epoch it was")

old_usage = '''\t\t"  set ttl <ms>\\n"
\t\t"  set policy <allow-all|vlans-only>\\n"'''
new_usage = '''\t\t"  set ttl <ms>\\n"
\t\t"  set refresh <ms>        0 = touch the flow timestamp on every packet\\n"
\t\t"  set policy <allow-all|vlans-only>\\n"
\t\t"  bump                    move the flow-cache epoch (drop all cached\\n"
\t\t"                          egress decisions without a map walk)\\n"
\t\t"  abi                     print the ABI of the loaded object (0 = none)\\n"'''
assert old_usage in s
s = s.replace(old_usage, new_usage)

old_main = '''\tif (!strcmp(argv[1], "stats"))
\t\treturn cmd_stats();'''
new_main = '''\tif (!strcmp(argv[1], "stats"))
\t\treturn cmd_stats();
\tif (!strcmp(argv[1], "bump"))
\t\treturn cmd_bump();
\tif (!strcmp(argv[1], "abi"))
\t\treturn cmd_abi();'''
assert old_main in s
s = s.replace(old_main, new_main)

# set: ttl/refresh/epoch handling
old_set = '''\t} else if (!strcmp(argv[0], "ttl")) {
\t\tcfg.flow_ttl_ms = strtoul(argv[1], NULL, 0);'''
new_set = '''\t} else if (!strcmp(argv[0], "ttl")) {
\t\tcfg.flow_ttl_ms = strtoul(argv[1], NULL, 0);
\t} else if (!strcmp(argv[0], "refresh")) {
\t\tcfg.flow_refresh_ms = strtoul(argv[1], NULL, 0);
\t} else if (!strcmp(argv[0], "epoch")) {
\t\tcfg.epoch = strtoul(argv[1], NULL, 0) & 0xff;'''
assert old_set in s
s = s.replace(old_set, new_set)

s = s.replace('''\t\t"usage: dpdctl set "
\t\t\t"<mode M | enable E | redirect R | ttl MS | policy P>\\n");''',
              '''\t\t"usage: dpdctl set "
\t\t\t"<mode M | enable E | redirect R | ttl MS | refresh MS | "
\t\t\t"epoch N | policy P>\\n");''')

# show: print epoch + refresh
old_show = '''\tprintf("policy       %s (%u)\\n", policy_name(cfg.policy), cfg.policy);'''
new_show = '''\tprintf("policy       %s (%u)\\n", policy_name(cfg.policy), cfg.policy);
\tprintf("epoch        %u\\n", cfg.epoch);
\tprintf("flow_refresh %u ms%s\\n", cfg.flow_refresh_ms,
\t       cfg.flow_refresh_ms ? "" : " (every packet)");'''
assert old_show in s
s = s.replace(old_show, new_show)

io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("dpdctl patched")
