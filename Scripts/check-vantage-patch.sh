#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# check-vantage-patch.sh - the Vantage dashboard patch must produce valid JS.
#
# Handles.sh runs Scripts/patch-vantage-overview.py against the theme cloned at
# build time. If the injected JavaScript were malformed the build would still be
# green (it is a text patch, not a compile) and the page would only break at
# runtime in the browser. This extracts the injected block and syntax-checks it
# with node.
#
# usage: sh Scripts/check-vantage-patch.sh
# exit: 0 ok, 1 malformed, 77 skipped (no node)

set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd) || exit 1
PY=$ROOT/Scripts/patch-vantage-overview.py

if [ ! -f "$PY" ]; then
	echo "check-vantage-patch: $PY not found" >&2
	exit 1
fi

if ! command -v node >/dev/null 2>&1; then
	echo "check-vantage-patch: node not available, skipping"
	exit 77
fi

exec python3 - "$PY" <<'PY'
import importlib.util
import io
import subprocess
import sys

spec = importlib.util.spec_from_file_location("pv", sys.argv[1])
pv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pv)

chip = pv.CHIP_NEW
s = chip.index("}));") + len("}));")
e = chip.index("\t},", s)
block = chip[s:e]

harness = ("'use strict';\n"
           "function E(t,a,k){return {tag:t,attrs:a,kids:k};}\n"
           "function icon(n){return n;}\n"
           "var self = { el: { health: { appendChild: function(){} } },\n"
           "  ebpf: null, paint: function() {\n" + block + "\n} };\n")
path = "/tmp/dpd-vantage-injected.js"
io.open(path, "w", encoding="utf-8").write(harness)

r = subprocess.run(["node", "--check", path], capture_output=True, text=True)
if r.returncode != 0:
    sys.stderr.write("FAIL: injected Vantage JS does not parse:\n")
    sys.stderr.write(r.stderr[:900] + "\n")
    sys.exit(1)
print("ok:   the injected Vantage chip block parses")

# The block must actually carry the hardware counters, or the dashboard change
# silently did nothing.
for key in ("ppe", "yielded_total", "sw_active"):
    if key not in block:
        sys.stderr.write("FAIL: injected block lacks '%s'\n" % key)
        sys.exit(1)
print("ok:   it reads maps.ppe / yielded_total / sw_active")
sys.exit(0)
PY