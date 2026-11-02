"""Add the eBPF acceleration line to the Vantage dashboard's System tile.

The theme is cloned from upstream at build time, so this is applied by
Handles.sh when the image theme is vantage. It edits the view once and is
idempotent (marker comment).

Layout: one compact line in the same tile and the same label/value style as
"Storage", under it and above the firmware line:

    eBPF   stateful · v4 1,204 (86.7%) · v6 80 (45.0%)

Only the content comes from /var/run/ebpf/status.json; if the datapath is not
present (non-eBPF images) the line shows a dash, which is still honest.

Usage: patch-vantage-overview.py <package dir containing luci-app-vantage>
"""
import io
import sys

MARK = "/* ebpf-accel-tile */"

EL_OLD = "\t\tel.fw = E('div', { 'class': 'vt-fw' });\n"
EL_NEW = (EL_OLD +
          "\t\t%s\n"
          "\t\tel.ebpfVal = E('span', { 'class': 'vt-tn' });\n" % MARK)

TILE_OLD = "\t\t\tel.fw\n\t\t]));\n"
TILE_NEW = ("\t\t\tE('div', { 'class': 'vt-sys-store' }, [\n"
            "\t\t\t\tE('span', { 'class': 'vt-label' }, [ 'eBPF' ]),\n"
            "\t\t\t\tel.ebpfVal\n"
            "\t\t\t]),\n"
            "\t\t\tel.fw\n\t\t]));\n")

PAINT_OLD = ("\t\tpatch(el.fw, [\n"
             "\t\t\tE('span', {}, [ d.firmware || '' ]),\n"
             "\t\t\td.kernel ? E('span', { 'class': 'vt-hint' }, [ _('Kernel %s').format(d.kernel) ]) : ''\n"
             "\t\t]);\n\t},\n")
PAINT_NEW = ("\t\tpatch(el.fw, [\n"
             "\t\t\tE('span', {}, [ d.firmware || '' ]),\n"
             "\t\t\td.kernel ? E('span', { 'class': 'vt-hint' }, [ _('Kernel %s').format(d.kernel) ]) : ''\n"
             "\t\t]);\n"
             "\n"
             "\t\t/* eBPF acceleration: one compact line, same style as Storage */\n"
             "\t\tL.resolveDefault(callRead('/var/run/ebpf/status.json'), '').then(function(raw) {\n"
             "\t\t\tvar st = null;\n"
             "\t\t\ttry { st = JSON.parse(raw); } catch (e) {}\n"
             "\t\t\tif (!st || !st.stats) {\n"
             "\t\t\t\tel.ebpfVal.textContent = fmt.DASH;\n"
             "\t\t\t\treturn;\n"
             "\t\t\t}\n"
             "\t\t\tvar f = (st.maps || {}).flows || {}, s = st.stats;\n"
             "\t\t\tfunction pct(hit, all) {\n"
             "\t\t\t\treturn all > 0 ? (hit * 100 / all).toFixed(1) + '%%' : '0.0%%';\n"
             "\t\t\t}\n"
             "\t\t\tel.ebpfVal.textContent = ((st.cfg || {}).mode || '?')\n"
             "\t\t\t\t+ ' \\u00b7 v4 ' + (Number(f.v4) || 0).toLocaleString()\n"
             "\t\t\t\t+ ' (' + pct(Number(s.bytes_hit_v4) || 0, Number(s.bytes_v4) || 0) + ')'\n"
             "\t\t\t\t+ ' \\u00b7 v6 ' + (Number(f.v6) || 0).toLocaleString()\n"
             "\t\t\t\t+ ' (' + pct(Number(s.bytes_hit_v6) || 0, Number(s.bytes_v6) || 0) + ')';\n"
             "\t\t});\n"
             "\t},\n")


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    path = (root.rstrip("/") +
            "/luci-app-vantage/htdocs/luci-static/resources/view/vantage/overview.js")
    try:
        src = io.open(path, encoding="utf-8").read()
    except FileNotFoundError:
        print("patch-vantage-overview: %s not found" % path, file=sys.stderr)
        return 1

    if MARK in src:
        print("patch-vantage-overview: already applied")
        return 0

    for anchor, name in ((EL_OLD, "el.fw"), (TILE_OLD, "tile tail"),
                         (PAINT_OLD, "paintSystem tail")):
        if anchor not in src:
            print("patch-vantage-overview: anchor for %s not found in %s"
                  % (name, path), file=sys.stderr)
            return 1

    src = src.replace(EL_OLD, EL_NEW, 1)
    src = src.replace(TILE_OLD, TILE_NEW, 1)
    src = src.replace(PAINT_OLD, PAINT_NEW, 1)

    io.open(path, "w", encoding="utf-8").write(src)
    print("patch-vantage-overview: added the eBPF line to %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
