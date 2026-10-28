#!/bin/sh
# SPDX-License-Identifier: MIT
#
# upstream-check.sh - does the upstream tree still look like the one our
# build-time edits assume?
#
# The firmware is built from VIKINGYFY/immortalwrt, unmodified. Everything this
# repo changes is applied by Scripts/Handles.sh / Settings.sh at build time and
# is guarded by a pattern (a line we expect to find). When upstream renames or
# removes that line, the sed silently stops matching and the image is built with
# upstream's default instead of ours -- no error, just a different firmware.
#
# This script is the tripwire. Run it against a fresh clone:
#
#   upstream-check.sh /path/to/immortalwrt
#
# Exit 0 = every anchor found, 1 = something to fix, 2 = bad usage.

set -u
TREE="${1:-}"
[ -n "$TREE" ] || { echo "usage: $0 <upstream tree>" >&2; exit 2; }
[ -d "$TREE" ] || { echo "no such tree: $TREE" >&2; exit 2; }

fails=0
ok()   { printf '  %-58s %s\n' "$1" "ok"; }
bad()  { printf '  %-58s %s\n' "$1" "MISSING"; fails=$((fails + 1)); }
have() { grep -qE "$2" "$TREE/$1" 2>/dev/null; }

echo "== anchors used by Scripts/Handles.sh =="

# X86 GPU/DRM trim: these three patterns are the ones the sed rewrites.
if have target/linux/x86/Makefile 'DEFAULT_PACKAGES.*video-support'; then
	ok "x86 Makefile: video-support in DEFAULT_PACKAGES"
else
	bad "x86 Makefile: video-support in DEFAULT_PACKAGES"
fi
if have target/linux/x86/Makefile 'i915-firmware-dmc'; then
	ok "x86 Makefile: i915-firmware-dmc"
else
	bad "x86 Makefile: i915-firmware-dmc"
fi
found_mk=0
for mk in "$TREE"/target/linux/x86/image/*.mk; do
	[ -f "$mk" ] || continue
	grep -q 'kmod-drm-i915' "$mk" && found_mk=1
done
[ "$found_mk" = 1 ] && ok "x86 image/*.mk: kmod-drm-i915" || bad "x86 image/*.mk: kmod-drm-i915"

# firewall4: the line we flip on the eBPF targets. Its *value* differs by
# branch on purpose: owrt ships 1 (kernel flowtable is the acceleration path),
# main ships 0 (those images accelerate with qca-nss/ECM, not with the nft
# flowtable). What must never disappear is the line itself, because that is what
# Handles.sh flips for X86/ROCKCHIP and what the IPQ guard reports.
F4=package/network/config/firewall4/patches/002-default-enable-fullcone.patch
if have "$F4" '^\+[[:space:]]*option[[:space:]]+flow_offloading[[:space:]]+[01]'; then
	val=$(grep -oE 'option[[:space:]]+flow_offloading[[:space:]]+[01]' "$TREE/$F4" 2>/dev/null | head -1 | awk '{print $NF}')
	ok "firewall4 patch: flow_offloading $val"
else
	bad "firewall4 patch: flow_offloading (line absent)"
fi
if have "$F4" '^\+[[:space:]]*option[[:space:]]+flow_offloading_hw[[:space:]]+[01]'; then
	val=$(grep -oE 'option[[:space:]]+flow_offloading_hw[[:space:]]+[01]' "$TREE/$F4" 2>/dev/null | head -1 | awk '{print $NF}')
	ok "firewall4 patch: flow_offloading_hw $val"
else
	bad "firewall4 patch: flow_offloading_hw (line absent)"
fi

# target.mk: kmod-nft-offload removal + odhcpd handover.
have include/target.mk '^[[:space:]]*kmod-nft-offload' \
	&& ok "include/target.mk: kmod-nft-offload" \
	|| bad "include/target.mk: kmod-nft-offload"
have include/target.mk '^[[:space:]]*odhcpd-ipv6only' \
	&& ok "include/target.mk: odhcpd-ipv6only" \
	|| bad "include/target.mk: odhcpd-ipv6only"

# dnsmasq/odhcpd handover.
have package/network/services/dnsmasq/files/dhcp.conf '^config[[:space:]]+dhcp[[:space:]]+lan$' \
	&& ok "dnsmasq dhcp.conf: config dhcp lan" \
	|| bad "dnsmasq dhcp.conf: config dhcp lan"
have package/network/services/odhcpd/files/odhcpd.defaults 'dhcp\.odhcpd\.maindhcp=' \
	&& ok "odhcpd.defaults: maindhcp" \
	|| bad "odhcpd.defaults: maindhcp"

echo
if [ "$fails" = 0 ]; then
	echo "RESULT: upstream still matches every build-time anchor"
	exit 0
fi
echo "RESULT: $fails anchor(s) missing -- Scripts/Handles.sh needs updating before the next build"
exit 1
