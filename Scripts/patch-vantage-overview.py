"""Put the eBPF acceleration into the Vantage dashboard's health row.

The theme's landing page ("Everything looks healthy") renders one chip per
health check (CPU, memory, storage, Wi-Fi, ...). This adds one more chip in
exactly that style, fed by /var/run/ebpf/status.json:

    eBPF       v4 86.7% · v6 45.0%
               stateful · 1,204 / 80 流

The theme is cloned from upstream at build time, so Handles.sh applies this.
Idempotent (marker comment).

Usage: patch-vantage-overview.py <package dir containing luci-app-vantage>
"""
import io
import sys

MARK = "/* ebpf-health-chip */"

SIG_OLD = ("\t\tvar sig = JSON.stringify(this.st.health.map(function(c) { return [ c.level, c.title, c.value, c.reason, c.detail, c.client, c.page ]; }));\n")
SIG_NEW = ("\t\tvar sig = JSON.stringify(this.st.health.map(function(c) { return [ c.level, c.title, c.value, c.reason, c.detail, c.client, c.page ]; }))\n"
           "\t\t\t+ (this.ebpf ? JSON.stringify([ this.ebpf.cfg, this.ebpf.maps && this.ebpf.maps.flows,\n"
           "\t\t\t\tthis.ebpf.stats && this.ebpf.stats.bytes_v4, this.ebpf.stats && this.ebpf.stats.bytes_hit_v4,\n"
           "\t\t\t\tthis.ebpf.stats && this.ebpf.stats.bytes_v6, this.ebpf.stats && this.ebpf.stats.bytes_hit_v6 ]) : '');\n")

CHIP_OLD = ("\t\t}));\n"
            "\t},\n"
            "\n"
            "\t/* ------------------------------------------------------------- hero */\n")
CHIP_NEW = ("\t\t}));\n"
            "\n"
            "\t\t%s\n"
            "\t\tif (this.ebpf) {\n"
            "\t\t\tvar e = this.ebpf, es = e.stats || {}, ef = (e.maps || {}).flows || {};\n"
            "\t\t\tvar mode = (e.cfg || {}).mode || '?';\n"
            "\t\t\tvar accel = !!e.attached && (mode === 'stateful' || mode === 'stateless');\n"
            "\t\t\tvar level = !e.attached ? 'warn' : (accel ? 'ok' : 'info');\n"
            "\t\t\tvar ic = level === 'ok' ? 'check' : level === 'warn' ? 'warn' : 'info';\n"
            "\t\t\tfunction pct(hit, all) {\n"
            "\t\t\t\treturn all > 0 ? (hit * 100 / all).toFixed(1) + '%%' : '0.0%%';\n"
            "\t\t\t}\n"
            "\t\t\tvar value = e.attached\n"
            "\t\t\t\t? 'v4 ' + pct(Number(es.bytes_hit_v4) || 0, Number(es.bytes_v4) || 0)\n"
            "\t\t\t\t  + ' \\u00b7 v6 ' + pct(Number(es.bytes_hit_v6) || 0, Number(es.bytes_v6) || 0)\n"
            "\t\t\t\t: '\\u672a\\u6302\\u8f7d';\n"
            "\t\t\tvar reason = e.attached\n"
            "\t\t\t\t? mode + ' \\u00b7 ' + (Number(ef.v4) || 0).toLocaleString()\n"
            "\t\t\t\t  + ' / ' + (Number(ef.v6) || 0).toLocaleString() + ' \\u6d41'\n"
            "\t\t\t\t: '\\u6570\\u636e\\u9762\\u672a\\u52a0\\u8f7d';\n"
            "\t\t\tthis.el.health.appendChild(E('div', { 'class': 'vt-chip vt-chip-' + level, 'role': 'listitem',\n"
            "\t\t\t\t'title': 'eBPF ' + mode + ' \\u00b7 v4 ' + (Number(ef.v4) || 0).toLocaleString()\n"
            "\t\t\t\t\t+ ' (\\u5360\\u6bd4 ' + pct(Number(es.bytes_hit_v4) || 0, Number(es.bytes_v4) || 0) + ')'\n"
            "\t\t\t\t\t+ ' \\u00b7 v6 ' + (Number(ef.v6) || 0).toLocaleString()\n"
            "\t\t\t\t\t+ ' (\\u5360\\u6bd4 ' + pct(Number(es.bytes_hit_v6) || 0, Number(es.bytes_v6) || 0) + ')' }, [\n"
            "\t\t\t\tE('span', { 'class': 'vt-chip-ico' }, [ icon(ic) ]),\n"
            "\t\t\t\tE('span', { 'class': 'vt-chip-main' }, [\n"
            "\t\t\t\t\tE('span', { 'class': 'vt-chip-top' }, [\n"
            "\t\t\t\t\t\tE('span', { 'class': 'vt-chip-title' }, [ 'eBPF' ]),\n"
            "\t\t\t\t\t\tE('span', { 'class': 'vt-chip-value' }, [ value ])\n"
            "\t\t\t\t\t]),\n"
            "\t\t\t\t\tE('span', { 'class': 'vt-chip-reason' }, [ reason ])\n"
            "\t\t\t\t])\n"
            "\t\t\t]));\n"
            "\t\t}\n"
            "\t},\n"
            "\n"
            "\t/* ------------------------------------------------------------- hero */\n") % MARK

FETCH_OLD = ("\t\tpatch(el.fw, [\n"
             "\t\t\tE('span', {}, [ d.firmware || '' ]),\n"
             "\t\t\td.kernel ? E('span', { 'class': 'vt-hint' }, [ _('Kernel %s').format(d.kernel) ]) : ''\n"
             "\t\t]);\n\t},\n")
FETCH_NEW = ("\t\tpatch(el.fw, [\n"
             "\t\t\tE('span', {}, [ d.firmware || '' ]),\n"
             "\t\t\td.kernel ? E('span', { 'class': 'vt-hint' }, [ _('Kernel %s').format(d.kernel) ]) : ''\n"
             "\t\t]);\n"
             "\n"
             "\t\t/* feed the health row's eBPF chip (same file the status page uses) */\n"
             "\t\tvar self = this;\n"
             "\t\tL.resolveDefault(callRead('/var/run/ebpf/status.json'), '').then(function(raw) {\n"
             "\t\t\tvar st = null;\n"
             "\t\t\ttry { st = JSON.parse(raw); } catch (e) {}\n"
             "\t\t\tself.ebpf = st || { attached: false };\n"
             "\t\t\tself.paintHealth();\n"
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

    for anchor, name in ((SIG_OLD, "health signature"), (CHIP_OLD, "health tail"),
                         (FETCH_OLD, "paintSystem tail")):
        if anchor not in src:
            print("patch-vantage-overview: anchor for %s not found in %s"
                  % (name, path), file=sys.stderr)
            return 1

    src = src.replace(SIG_OLD, SIG_NEW, 1)
    src = src.replace(CHIP_OLD, CHIP_NEW, 1)
    src = src.replace(FETCH_OLD, FETCH_NEW, 1)

    io.open(path, "w", encoding="utf-8").write(src)
    print("patch-vantage-overview: added the eBPF health chip to %s" % path)

    # 1) drop the theme's own firewall overview page: the firewall menu belongs
    #    to the eBPF port-control page here, and a leftover child paints a
    #    "1" badge next to it.
    menu = (root.rstrip("/") + "/luci-app-vantage/root/usr/share/luci/"
            "menu.d/luci-app-vantage.json")
    try:
        import json
        d = json.load(io.open(menu, encoding="utf-8"))
        if d.pop("admin/network/firewall/overview", None) is not None:
            io.open(menu, "w", encoding="utf-8", newline="\n").write(
                json.dumps(d, ensure_ascii=False, indent="\t") + "\n")
            print("patch-vantage-overview: dropped admin/network/firewall/overview")
    except FileNotFoundError:
        pass

    # 2) five health chips on one row for wired boxes (the theme's grid is 4)
    css = (root.rstrip("/") + "/luci-app-vantage/htdocs/luci-static/"
           "resources/vantage/app.css")
    try:
        css_src = io.open(css, encoding="utf-8").read()
        rule = ("\n@container vt (min-width: 1100px) { .vt-app.vt-wired .vt-health "
                "{ grid-template-columns: repeat(5, minmax(0, 1fr)); } }\n")
        if "repeat(5, minmax(0, 1fr))" not in css_src:
            io.open(css, "a", encoding="utf-8", newline="\n").write(rule)
            print("patch-vantage-overview: five-column health row for wired")
    except FileNotFoundError:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
