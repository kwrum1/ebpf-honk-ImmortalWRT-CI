#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# router-qos.sh - shared helpers for the CAKE QoS.
#
# Sourced by:
#   /etc/init.d/router-qos
#   /etc/hotplug.d/iface/92-router-qos
#
# Why there is no classifier program here
# ---------------------------------------
# The old shape of this was HTB plus a cascade of `tc filter` classifiers, one
# per class, and every new class meant another filter. CAKE replaces all of it
# with a single qdisc that does its own per-flow fairness, its own ack
# filtering and its own DSCP->tin mapping. So the whole QoS is one qdisc:
#
#   tc qdisc replace dev <wan> root cake bandwidth <upload>kbit ...
#
# That is the "single TC program + CAKE" from the plan, taken literally.
#
# Why the download direction is not shaped here
# ---------------------------------------------
# The plan called for a second CAKE on an IFB, fed by a mirror filter in the
# WAN's ingress hook, so both directions would be shaped. That was measured on
# the host with a veth pair and it does not work (build/ifb-probe.sh):
#
#   mirror + pass, cake on the IFB   ping 3/3, IFB saw 4 pkt
#   redirect,      cake on the IFB   ping 3/3, IFB saw 10 pkt
#
# `mirror` copies the packet, so the *original* still goes on to the LAN
# untouched; the IFB only ever shapes the copy. The ping still succeeds, so
# nothing looks broken, but the download is not actually shaped. Only
# `redirect` really shapes, and redirect steals the packet out of the chain.
#
# That matters because on this WAN device the ingress cls_bpf chain is the whole
# datapath:
#
#   einat    TCX links (the kernel runs tcx_run() before tc_run())
#   pref 90  router-acl
#   pref 100 dpd
#
# A redirect would terminate the chain and starve router-acl and dpd. Putting
# the redirect last would keep them running, but an IFB re-injects the packet
# with its own interface as the source, and fw4 matches zones by `iifname` -- so
# the re-injected download would no longer look like it came from the WAN zone
# and fw4 forward would drop it.
#
# So: upload only. On a home link the upload really is the queue this box owns
# -- the downstream is queued at the ISP's end, which is exactly why tuning it
# means pretending the link is slower than it is. Shaping the direction the
# router actually controls is the honest half, and it is the half that needs no
# IFB, no extra filter and no interference with the eBPF datapath.
#
# Interaction with the other TC users on the WAN device
# ---------------------------------------------------
# A root qdisc and a clsact qdisc are independent: clsact lives at handle
# ffff: and carries the ingress and egress filter chains, while root is the
# device's normal transmit queue. Replacing root does not touch the filters, so
# router-acl (pref 90) and dpd (pref 100) keep working with CAKE installed.
# This is verified in build/qemu-qos.sh.
#
# clsact vs ingress qdisc: the reverse is not true -- a plain `ingress` qdisc
# only carries the ingress hook, so router-acl could not attach its egress
# program later. router-acl creates clsact, so nothing here needs to.

rq_log() {
	logger -t router-qos "$*" 2>/dev/null || true
}

rq_resolve_dev() {
	local want="$1" dev=""

	[ -n "$want" ] || return 1
	[ -e "/sys/class/net/$want" ] && { echo "$want"; return 0; }
	. /lib/functions/network.sh
	network_get_device dev "$want" 2>/dev/null
	[ -n "$dev" ] && { echo "$dev"; return 0; }
	return 1
}

rq_cake_opts() {
	local bw="$1" overhead="$2" mpu="$3" diffserv="$4" wash="$5" nat="$6"
	local opts="bandwidth ${bw}kbit"

	[ "${overhead:-0}" != "0" ] && opts="$opts overhead $overhead"
	[ "${mpu:-0}" != "0" ] && opts="$opts mpu $mpu"
	case "$diffserv" in
	''|none)	;;
	*)		opts="$opts $diffserv" ;;
	esac
	[ "$wash" = "1" ] && opts="$opts wash"
	[ "$nat" = "1" ] && opts="$opts nat"
	printf '%s' "$opts"
}

rq_apply() {
	local dev="$1" opts="$2"

	[ -e "/sys/class/net/$dev" ] || return 1
	if ! tc qdisc replace dev "$dev" root cake $opts 2>/dev/null; then
		rq_log "apply: cake on $dev failed ($opts)"
		return 1
	fi
	rq_log "apply: cake on $dev ($opts)"
	return 0
}

rq_clear() {
	local dev="$1"

	[ -n "$dev" ] || return 0
	[ -e "/sys/class/net/$dev" ] || return 0
	# `qdisc del root` puts the device back on its default (noqueue for a
	# virtual device, the driver default otherwise). It does not touch the
	# clsact qdisc, so the ingress/egress filter chains are unaffected.
	tc qdisc del dev "$dev" root 2>/dev/null
}

rq_enabled_qdisc() {
	local dev="$1"

	[ -e "/sys/class/net/$dev" ] || return 1
	tc qdisc show dev "$dev" 2>/dev/null | grep -qE '(^| )cake( |$)'
}

rq_status() {
	local dev="$1"

	echo "--- root qdisc on $dev ---"
	if [ -z "$dev" ]; then
		echo "  (WAN device not resolved)"
		return 0
	fi
	tc -s qdisc show dev "$dev" 2>/dev/null || echo "  (tc failed)"
	echo "--- clsact filters on $dev (owned by router-acl / dpd, not us) ---"
	tc filter show dev "$dev" ingress 2>/dev/null | grep -E '^filter' || true
	tc filter show dev "$dev" egress 2>/dev/null | grep -E '^filter' || true
}
