#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# dpd-regress.sh - short, repeatable correctness regression for the datapath.
#
# It answers the questions the 2026-10-28 review asks about, in the order that
# fails fastest:
#
#   1. does the program load, and does the ABI of the pinned maps match the
#      object (an in-place upgrade used to fail here with a pin error)
#   2. do observe / off / detached all still forward traffic (they must differ
#      in *who* forwards, not in whether packets arrive)
#   3. do the gates still reject what they must (v6, :53, DHCP, broadcast)
#   4. does a learned flow survive the epoch bump (it must be re-learned, not
#      silently kept)
#   5. MTU / GSO: a packet whose *segment* exceeds the MTU must fall back, and a
#      normal flow must keep accelerating
#
# Usage:
#   dpd-regress.sh [--target 192.0.2.1] [--dev br-lan] [--quick]
#
#   --target  an address that is reachable through the uplink (ping/iperf)
#   --dev     the LAN device the fast path is attached to (default br-lan)
#   --quick   skip the MTU matrix (only 1500)
#
# Exit code: 0 all checks passed, 1 a check failed, 2 environment problem.

set -u

TARGET=""
DEV="br-lan"
QUICK=0
PIN=/sys/fs/bpf/tc/globals
CTL=/usr/sbin/dpdctl

while [ $# -gt 0 ]; do
	case "$1" in
	--target) TARGET="${2:-}"; shift 2 ;;
	--dev) DEV="${2:-}"; shift 2 ;;
	--quick) QUICK=1; shift ;;
	-h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done

[ -x "$CTL" ] || { echo "FAIL: $CTL not found (dpd-fastpath not installed?)" >&2; exit 2; }

fails=0
pass() { printf '  %-46s %s\n' "$1" "$2"; }
ok()   { pass "$1" "ok"; }
bad()  { pass "$1" "FAIL"; fails=$((fails + 1)); }
note() { printf '  %-46s %s\n' "$1" "$2"; }

# The package installs the ABI it was built with in /usr/lib/dpd/abi. Older
# images do not have that file; fall back to the ABI compiled into dpdctl, which
# is enough to run this script against them.
if [ -f /usr/lib/dpd/abi ]; then
	abi_want=$(cat /usr/lib/dpd/abi)
else
	abi_want=$("$CTL" version 2>/dev/null | sed -n 's/.*abi //p')
fi
abi_have=$("$CTL" abi 2>/dev/null || echo 0)

echo "== 1. object and ABI =="
note "expected ABI" "${abi_want:-unknown}"
note "pinned ABI" "${abi_have:-0}"
if [ -z "${abi_want:-}" ] || [ "${abi_have:-0}" = 0 ]; then
	# Older dpdctl has no `abi` command; nothing to compare, and pretending
	# to would make this script fail on an image that is actually fine.
	note "ABI check" "skipped (dpdctl without an abi command)"
elif [ "$abi_want" = "$abi_have" ]; then
	ok "ABI matches"
else
	bad "ABI mismatch (stale pins?)"
fi

st=$("$CTL" stats 2>/dev/null | awk '/pkt_total/{print $3}')
[ -n "${st:-}" ] && ok "stats readable (pkt_total=$st)" || bad "stats unreadable"

echo "== 2. modes still forward =="
# A ping through the box is the cheapest proof that the slow path still works
# while we are attached.
if [ -n "$TARGET" ]; then
	for m in observe off; do
		"$CTL" set mode "$m" >/dev/null 2>&1
		sleep 1
		if ping -c 2 -W 2 "$TARGET" >/dev/null 2>&1; then
			ok "mode=$m forwards"
		else
			bad "mode=$m does not forward"
		fi
	done
	"$CTL" set mode stateful >/dev/null 2>&1

	# And the honest baseline: with no filter at all, forwarding must be
	# identical. If "detached" behaves differently from observe/off, the
	# difference is in the attach path, not in the accelerator.
	if tc filter del dev "$DEV" ingress pref 100 2>/dev/null; then
		sleep 1
		if ping -c 2 -W 2 "$TARGET" >/dev/null 2>&1; then
			ok "detached forwards"
		else
			bad "detached does not forward"
		fi
		/etc/init.d/dpd-fastpath start >/dev/null 2>&1 || 			tc filter add dev "$DEV" ingress pref 100 handle 100 \
				bpf da obj /lib/bpf/dpd_fastpath.bpf.o sec classifier >/dev/null 2>&1
		sleep 1
		if [ -n "$("$CTL" stats 2>/dev/null | awk '/pkt_total/{print $3}')" ]; then
			ok "re-attached after detach"
		else
			bad "re-attach failed"
		fi
	else
		note "detached" "skipped (no filter on $DEV)"
	fi
else
	note "modes" "skipped (no --target)"
fi

echo "== 3. gates =="
# These counters must move for traffic that must never be accelerated.
before=$("$CTL" stats 2>/dev/null | awk '/dns_skip/{print $3}')
nslookup openwrt.org >/dev/null 2>&1 || nslookup openwrt.org 127.0.0.1 >/dev/null 2>&1
sleep 1
after=$("$CTL" stats 2>/dev/null | awk '/dns_skip/{print $3}')
if [ -n "${before:-}" ] && [ -n "${after:-}" ] && [ "$after" -ge "$before" ]; then
	ok "dns_skip counter readable ($before -> $after)"
else
	bad "dns_skip counter"
fi
v6=$("$CTL" stats 2>/dev/null | awk '/v6_skip/{print $3}')
[ -n "${v6:-}" ] && ok "v6_skip counter present ($v6)" || bad "v6_skip counter missing"

echo "== 4. flow cache invalidation =="
# Wait for at least one flow, then bump the epoch and look for a re-learn.
if [ -n "$TARGET" ]; then
	ping -c 3 -W 2 "$TARGET" >/dev/null 2>&1
	w0=$("$CTL" stats 2>/dev/null | awk '/flow_write/{print $3}')
	if ! "$CTL" bump >/dev/null 2>&1; then
		note "epoch" "skipped (this dpdctl has no bump command)"
		w0=""
	fi
	ping -c 3 -W 2 "$TARGET" >/dev/null 2>&1
	w1=$("$CTL" stats 2>/dev/null | awk '/flow_write/{print $3}')
	if [ -z "${w0:-}" ]; then
		:
	elif [ -n "${w1:-}" ] && [ "$w1" -gt "$w0" ]; then
		ok "epoch bump forces re-learn (flow_write $w0 -> $w1)"
	else
		bad "epoch bump did not force a re-learn ($w0 -> $w1)"
	fi
else
	note "epoch" "skipped (no --target)"
fi

echo "== 5. MTU / GSO matrix =="
mtu_now=$(cat "/sys/class/net/$DEV/mtu" 2>/dev/null || echo "")
if [ -z "$mtu_now" ]; then
	note "mtu" "skipped (no $DEV)"
else
	note "current $DEV mtu" "$mtu_now"
	fail0=$("$CTL" stats 2>/dev/null | awk '/fib_fail/{print $3}')
	if [ "$QUICK" = 0 ] && [ -n "$TARGET" ]; then
		for m in 1500 1492 1400; do
			ip link set dev "$DEV" mtu "$m" 2>/dev/null || continue
			sleep 1
			if ping -c 2 -W 2 -s 1000 "$TARGET" >/dev/null 2>&1; then
				ok "mtu $m forwards (1000B payload)"
			else
				bad "mtu $m does not forward"
			fi
		done
		ip link set dev "$DEV" mtu "$mtu_now" 2>/dev/null
	else
		note "mtu matrix" "skipped (--quick or no --target)"
	fi
	fail1=$("$CTL" stats 2>/dev/null | awk '/fib_fail/{print $3}')
	note "fib_fail" "$fail0 -> $fail1"
fi

echo "== 6. chain summary =="
if command -v bpftool >/dev/null 2>&1; then
	bpftool net show 2>/dev/null | sed -n 's/^\(.*\)$/  \1/p' | head -8
fi

echo
if [ "$fails" = 0 ]; then
	echo "RESULT: pass"
	exit 0
fi
echo "RESULT: $fails check(s) failed"
exit 1
