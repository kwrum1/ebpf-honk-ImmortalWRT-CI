"""Add one eBPF row to LuCI's System status card, right after CPU usage.

The homepage is luci-mod-status's view/status/index.js, which requires every
file in view/status/include/. We do NOT add a new section and we do NOT replace
the card: this edits the existing 10_system.js so the datapath shows up as one
more line next to Load Average / CPU usage, the way vendor PPE/NSS builds do.

The row is a single cell spanning both columns. Its value carries three groups
(engine, flows, takeover share) and must not wrap, which the normal 33%/67%
label/value split cannot guarantee; the right padding keeps the text off the
card edge.

Idempotent (marker comment). Fails loudly when the anchors move, so an upstream
change shows up in CI instead of silently dropping the row.

Usage: patch-luci-status.py <build-tree-root>
"""
import io
import sys

MARK = "/* ebpf-status-row */"

HELPER = """
%s
/* One line for the status card, next to CPU usage, with the engine and both
 * numbers laid out horizontally: the engine mode (stateful/stateless/observe),
 * active flows, and the share of traffic the fastpath took over (bytes, not
 * packets: a packet ratio overstates the few large segments of a bulk flow).
 * The two counters are split by address family and each share is a share of
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
		var mode = (st.cfg || {}).mode || '?';
		var n4 = Number(f.v4) || 0, n6 = Number(f.v6) || 0;
		var b4 = Number(s.bytes_v4) || 0, b6 = Number(s.bytes_v6) || 0;
		var h4 = Number(s.bytes_hit_v4) || 0, h6 = Number(s.bytes_hit_v6) || 0;

		function pct(hit, all) {
			return all > 0 ? (hit * 100 / all).toFixed(1) + '%%' : '0.0%%';
		}
		function pair(v4, v6) {
			return '[v4: ' + v4 + ' | v6: ' + v6 + ']';
		}

		out = '\\u52a0\\u901f\\u5f15\\u64ce\\uff1a' + mode
			+ '  |  \\u52a0\\u901f\\u6d41\\uff1a'
			+ pair(n4.toLocaleString(), n6.toLocaleString())
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

# The row loop that turns the flat fields array into 33%/67% table rows.
ROWS_OLD = (
    "\t\tfor (var i = 0; i < fields.length; i += 2) {\n"
    "\t\t\ttable.appendChild(E('tr', { 'class': 'tr' }, [\n"
    "\t\t\t\tE('td', { 'class': 'td left', 'width': '33%' }, [ fields[i] ]),\n"
    "\t\t\t\tE('td', { 'class': 'td left' }, [ (fields[i + 1] != null) ? fields[i + 1] : '?' ])\n"
    "\t\t\t]));\n"
    "\t\t}\n"
)

# Full-width row: white-space:nowrap keeps the three groups on one line, the
# right padding reserves the space the user asked for, and colspan=2 gives it
# the whole card instead of 67% of it.
ROWS_ADD = (
    "\n"
    "\t\t/* ebpf-status-row: one full-width line under CPU usage. The value\n"
    "\t\t * has three groups and must not wrap, so it cannot use the 33/67\n"
    "\t\t * label/value columns above. */\n"
    "\t\ttable.appendChild(E('tr', { 'class': 'tr' }, [\n"
    "\t\t\tE('td', { 'class': 'td left', 'colspan': '2',\n"
    "\t\t\t          'style': 'white-space:nowrap;padding-right:24px' }, [\n"
    "\t\t\t\tE('span', { 'style': 'margin-right:12px' }, [ _('eBPF \\u52a0\\u901f') ]),\n"
    "\t\t\t\tebpf_status(data[8])\n"
    "\t\t\t])\n"
    "\t\t]));\n"
)


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

    for anchor, name in ((LOAD_OLD, "load()"), (ROWS_OLD, "row loop")):
        if anchor not in src:
            print("patch-luci-status: anchor for %s not found in %s"
                  % (name, path), file=sys.stderr)
            return 1

    src = src.replace(LOAD_OLD, LOAD_NEW, 1)
    src = src.replace(ROWS_OLD, ROWS_OLD + ROWS_ADD, 1)

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
