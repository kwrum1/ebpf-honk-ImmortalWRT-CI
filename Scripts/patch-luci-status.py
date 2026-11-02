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
/* One line for the status card, next to CPU usage, with both numbers laid out
 * horizontally and split by address family: active flows, and the share of
 * traffic the fastpath took over (bytes, not packets: a packet ratio
 * overstates the few large segments of a bulk flow). Each share is a share of
 * that family's own traffic, so a v6-heavy or v4-heavy box does not look
 * wrong. Reads the snapshot the gate watchdog writes, so the status page needs
 * no exec rights. */
var _ebpf_raw = null, _ebpf_val = null;

function ebpf_status(raw) {
	if (raw === _ebpf_raw && _ebpf_val)
		return _ebpf_val;

	var out = '\\u2014';
	try {
		var st = JSON.parse(raw), s = st.stats || {}, f = (st.maps || {}).flows || {};
		var n4 = Number(f.v4) || 0, n6 = Number(f.v6) || 0;
		var b4 = Number(s.bytes_v4) || 0, b6 = Number(s.bytes_v6) || 0;
		var h4 = Number(s.bytes_hit_v4) || 0, h6 = Number(s.bytes_hit_v6) || 0;

		function pct(hit, all) {
			return all > 0 ? (hit * 100 / all).toFixed(1) + '%%' : '0.0%%';
		}
		function pair(v4, v6) {
			return '[v4: ' + v4 + ' | v6: ' + v6 + ']';
		}

		out = '\\u52a0\\u901f\\u6d41\\uff1a' + pair(n4.toLocaleString(), n6.toLocaleString())
			+ '  |  \\u52a0\\u901f\\u5360\\u6bd4\\uff1a'
			+ pair(pct(h4, b4), pct(h6, b6));
	}
	catch (e) { /* datapath not loaded yet: keep the placeholder */ }

	_ebpf_raw = raw;
	_ebpf_val = out;
	return out;
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
