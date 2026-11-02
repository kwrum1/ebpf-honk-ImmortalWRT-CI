"""Add one eBPF row to LuCI's System status card, right after CPU usage.

The homepage is luci-mod-status's view/status/index.js, which requires every
file in view/status/include/. We do NOT add a new section and we do NOT replace
the card: this edits the existing 10_system.js so the datapath shows up as one
more line next to Load Average / CPU usage, the way vendor PPE/NSS builds do.

Idempotent (marker comment). Fails loudly when the anchors move, so an upstream
change shows up in CI instead of silently dropping the row.

Usage: patch-luci-status.py <build-tree-root>
"""
import io
import sys

MARK = "/* ebpf-status-row */"

HELPER = """
%s
/* One compact line for the status card: mode + accelerated packets, or the
 * gate code when the datapath is not taking packets over. Reads the snapshot
 * the gate watchdog writes (no ubus/exec from the status page). */
function ebpf_status(raw) {
	try {
		var st = JSON.parse(raw);
		if (!st || !st.attached)
			return '\\u672a\\u6302\\u8f7d';
		var cfg = st.cfg || {}, s = st.stats || {}, g = st.gate || {};
		var mode = cfg.mode || '?';
		if (mode != 'stateful' && mode != 'stateless')
			return mode + (g.code && g.code != 'ok' ? ' (' + g.code + ')' : '');
		var hit = Number(s.flow_hit) || 0;
		return mode + ' \\u00b7 ' + hit.toLocaleString() + ' \\u5305';
	}
	catch (e) { return '\\u2014'; }
}

""" % MARK

LOAD_OLD = "\t\t\tuci.load('system')\n\t\t]);"
LOAD_NEW = ("\t\t\tuci.load('system'),\n"
            "\t\t\tL.resolveDefault(fs.read('/var/run/ebpf/status.json'), '')\n"
            "\t\t]);")

FIELDS_OLD = "\t\t\t_('CPU usage (%)'),    cpuusage.cpuusage\n"
FIELDS_NEW = ("\t\t\t_('CPU usage (%)'),    cpuusage.cpuusage,\n"
              "\t\t\t_('eBPF \\u52a0\\u901f'),   ebpf_status(data[8])\n")


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    path = (root.rstrip("/") +
            "/feeds/luci/modules/luci-mod-status/htdocs/luci-static/"
            "resources/view/status/include/10_system.js")
    try:
        src = io.open(path, encoding="utf-8").read()
    except FileNotFoundError:
        print("patch-luci-status: %s not found" % path, file=sys.stderr)
        return 1

    if MARK in src:
        print("patch-luci-status: already applied")
        return 0

    for anchor, name in ((LOAD_OLD, "load()"), (FIELDS_OLD, "fields")):
        if anchor not in src:
            print("patch-luci-status: anchor for %s not found in %s"
                  % (name, path), file=sys.stderr)
            return 1

    src = src.replace(LOAD_OLD, LOAD_NEW, 1)
    src = src.replace(FIELDS_OLD, FIELDS_NEW, 1)
    # helper goes after the require block, before baseclass.extend
    marker = "return baseclass.extend({"
    if marker not in src:
        print("patch-luci-status: baseclass anchor missing", file=sys.stderr)
        return 1
    src = src.replace(marker, HELPER + marker, 1)

    io.open(path, "w", encoding="utf-8").write(src)
    print("patch-luci-status: added the eBPF row to %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
