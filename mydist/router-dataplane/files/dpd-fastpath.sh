#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# dpd-fastpath.sh - shared helpers for the dpd TC ingress fastpath.
#
# Sourced by:
#   /etc/init.d/dpd-fastpath
#   /etc/hotplug.d/iface/90-dpd-fastpath
#
# Contract with einat (see src/dpd_common.h):
#   * einat attaches with a bpf_link on the external iface's TC hooks (TCX
#     ingress + egress). That is NOT a pref-1 cls_bpf filter -- measured, see
#     工作计划.md §13.16 and again in QEMU 2026-10-17: `bpftool net show`
#     reports `eth1(3) tcx/ingress ingress_rev_snat` + `tcx/egress egress_snat`.
#     The kernel runs TCX before the classic cls_bpf chain, so einat always sees
#     a packet first.
#   * Acceleration is *gated* on einat being attached: taking a flow over skips
#     netfilter, so the reply of an accelerated flow is only accepted because
#     einat (conntrack-free NAT) makes its init inject a blanket WAN->LAN accept
#     into fw4. No einat, no acceleration -- see dpd_gate_mode().
#   * we attach as a classic filter at pref 100 and must never take pref 1: a
#     pref-1 filter would sit in front of nothing useful and could reorder
#     against honk's steering.
#   * honk owns TCX on br-lan, its bridge slaves and the WAN. TCX runs before
#     every classic filter, so honk's proxy decision is always taken first and
#     we structurally see only the flows honk declined. That is why a transparent
#     proxy and this accelerator can coexist -- dpd must never become a TCX
#     program, or it would jump in front of honk.
#   * a qdisc is never replaced: honk may have created clsact already, and
#     einat may have created a plain ingress qdisc. clsact and ingress cannot
#     coexist on one device, so we only ever add one if neither is present.
#
# Debugging note from the first hardware bring-up: this file used to swallow
# every error, so a failed attach was indistinguishable from a successful one
# (the init script logged "started" in both cases while no BPF map existed).
# Every failure path now goes through dpd_log().

DPD_OBJ=/lib/bpf/dpd_fastpath.bpf.o
DPD_SEC=classifier
DPD_PREF=100
DPD_CTL=/usr/sbin/dpdctl

dpd_log() {
	logger -t dpd-fastpath "$*" 2>/dev/null || true
}

# libbpf pins our maps by name, so /sys/fs/bpf has to be a bpffs. Nothing in
# the base system guarantees it exists this early, and when it is missing
# `tc filter add` fails with a "failed to pin map" error that does not name the
# real cause.
dpd_bpffs_ensure() {
	mount 2>/dev/null | grep -qE ' on /sys/fs/bpf type bpf' && return 0
	mkdir -p /sys/fs/bpf
	mount -t bpf bpf /sys/fs/bpf 2>/dev/null && return 0
	return 1
}

# ensure a hook exists on $1 without disturbing whatever is already there
dpd_qdisc_ready() {
	local dev="$1"

	tc qdisc show dev "$dev" 2>/dev/null | grep -qE '(^| )(clsact|ingress)( |$)' && return 0
	tc qdisc add dev "$dev" clsact 2>/dev/null && return 0
	tc qdisc add dev "$dev" ingress 2>/dev/null && return 0
	return 1
}

# Teach the BPF side this iface's L2 capabilities (NOARP/POINTOPOINT), which is
# what lets redirect=auto pick bpf_redirect() for ppp and bpf_redirect_neigh()
# for ethernet.
#
# This MUST run after the program is loaded: dpdctl talks to the pinned map
# dpd_iface, which does not exist until the first successful attach. Running it
# before the filter add silently did nothing, so the iface table stayed empty
# and auto had no input at all.
dpd_teach_iface() {
	local dev="$1"

	[ -x "$DPD_CTL" ] || return 1
	[ -e "/sys/class/net/$dev" ] || return 1
	"$DPD_CTL" ifaces "$dev" >/dev/null 2>&1
}

# attach the program to $1 at DPD_PREF. Idempotent.
dpd_attach_if() {
	local dev="$1"

	[ -n "$dev" ] || return 1
	[ -e "/sys/class/net/$dev" ] || { dpd_log "no such device: $dev"; return 1; }
	[ -f "$DPD_OBJ" ] || { dpd_log "missing $DPD_OBJ"; return 1; }
	dpd_bpffs_ensure || dpd_log "warning: /sys/fs/bpf is not a bpffs"
	dpd_qdisc_ready "$dev" || { dpd_log "cannot create a tc hook on $dev"; return 1; }

	# replace, do not stack
	tc filter del dev "$dev" ingress pref "$DPD_PREF" 2>/dev/null
	if ! tc filter add dev "$dev" ingress pref "$DPD_PREF" handle "$DPD_PREF" \
		bpf da obj "$DPD_OBJ" sec "$DPD_SEC"; then
		dpd_log "tc filter add failed on $dev (program not loaded)"
		return 1
	fi

	# the program is loaded now, so the pin exists and the flags can land
	dpd_teach_iface "$dev"
	return 0
}

dpd_detach_if() {
	local dev="$1"

	[ -e "/sys/class/net/$dev" ] || return 0
	tc filter del dev "$dev" ingress pref "$DPD_PREF" 2>/dev/null
	return 0
}

# is the program on $1 right now?
dpd_is_attached() {
	tc filter show dev "$1" ingress pref "$DPD_PREF" 2>/dev/null | grep -q bpf
}

# last-resort device lookup: ask netifd over ubus and match the interface name.
# network_get_device() needs the interface to be up and ubus to know about it,
# which is exactly what is false when the init script runs at boot.
dpd_find_device() {
	local want="$1" iface dev

	for iface in $(ubus list 'network.interface.*' 2>/dev/null); do
		case "$iface" in
		*."$want") ;;
		*) continue ;;
		esac
		dev="$(ubus -S call "$iface" status 2>/dev/null |
			jsonfilter -e '@.l3_device' 2>/dev/null)"
		if [ -n "$dev" ] && [ -e "/sys/class/net/$dev" ]; then
			echo "$dev"
			return 0
		fi
	done
	return 1
}

# resolve a uci netifd logical name to a device name (empty if not up yet).
# Interfaces like pppoe-wan only appear once the link is up, hence the hotplug.
dpd_resolve_logical() {
	local logical="$1" dev=""

	. /lib/functions/network.sh
	network_get_device dev "$logical" 2>/dev/null
	[ -n "$dev" ] || dev="$(dpd_find_device "$logical")"
	printf '%s' "$dev"
}

# resolve a uci netifd logical name to a device, then attach.
dpd_attach_logical() {
	local dev

	dev="$(dpd_resolve_logical "$1")"
	if [ -z "$dev" ]; then
		dpd_log "iface '$1' has no device yet; hotplug will retry on ifup"
		return 1
	fi
	dpd_attach_if "$dev"
}

# ------------------------------------------------------------------ gates
#
# Everything below decides whether the accelerator is *allowed* to take packets
# over. Each gate is a separate, cheap probe, and each one that says no
# downgrades the effective mode to observe and says why in the log. The datapath
# then cannot accelerate even if the uci config asked for it.
#
# These live in the shared lib, not in the init script, on purpose: the iface
# hotplug sources this file and calls dpd_gate_mode() too. They were in the init
# once, and the hotplug then called a function that did not exist in its
# namespace -- every ifup would have quietly skipped the gates.

# publish the uci selection into the BPF config map. Safe to call when no
# program is loaded yet: dpdctl then just fails and we retry after attaching.
dpd_push_uci() {
	local enabled="$1" mode="$2" redirect="$3" ttl="$4" policy="$5"

	[ -x "$DPD_CTL" ] || return 0
	"$DPD_CTL" set mode "$mode" 2>/dev/null
	"$DPD_CTL" set redirect "$redirect" 2>/dev/null
	"$DPD_CTL" set ttl "$ttl" 2>/dev/null
	[ -n "$policy" ] && "$DPD_CTL" set policy "$policy" 2>/dev/null
	"$DPD_CTL" set enable "$enabled" 2>/dev/null
	return 0
}

# publish the vlan allow-list from uci into dpd_vlans, then the policy.
#
# The list is rebuilt from uci on every start, so the map always matches the
# configuration file instead of accumulating entries nobody can see.
dpd_push_vlans() {
	local policy="$1" vlans="$2" v

	[ -x "$DPD_CTL" ] || return 0
	"$DPD_CTL" vlan flush >/dev/null 2>&1
	for v in $vlans; do
		case "$v" in
		'' | *[!0-9]*) dpd_log "ignoring non-numeric vlan id '$v'"; continue ;;
		esac
		"$DPD_CTL" vlan add "$v" >/dev/null 2>&1
	done
	[ -n "$policy" ] && "$DPD_CTL" set policy "$policy" 2>/dev/null
	return 0
}

# The acceleration gate. $1 = the mode uci asked for. Echoes the mode that may
# actually be used.
#
# Rationale (full version in src/dpd_common.h): taking a flow over skips
# netfilter, so the return path of an accelerated flow exists only because einat
# is the NAT and injects a blanket WAN->LAN accept into fw4. Without a
# confirmed-attached einat the honest thing is to watch and not accelerate -- an
# accelerator that silently eats replies is worse than no accelerator.
dpd_gate_mode() {
	local mode="$1" why="" r

	if dpd_mode_wants_accel "$mode"; then
		# Acceleration is a *forwarding* optimisation: it redirects LAN->WAN
		# flows out of the uplink. With no uplink at all (WAN down, no cable,
		# no lease yet) there is nothing to accelerate, and the program must
		# not touch the LAN: with einat able to report "attached" on an
		# uplink that has no address or route, the gate would otherwise let
		# it run. Measured on the lab VM (single-NIC, no WAN), stateless mode
		# made every TCP/UDP connection *to the router* time out while ICMP
		# still answered -- i.e. the box became unmanageable.
		if ! dpd_has_uplink; then
			why="no uplink (no WAN device or no default route), so there is no forwarding path to accelerate and hooking the LAN would only steal traffic addressed to the router itself"
		fi
		dpd_einat_attached
		r=$?
		case "$r" in
		1) why="${why:-einat is not attached, so the reply of an accelerated flow would be dropped by fw4 (no conntrack state, no NAT)}" ;;
		2) why="${why:-cannot tell whether einat is attached (no bpftool); refusing to accelerate blind}" ;;
		esac
		if [ -z "$why" ] && dpd_honk_owns; then
			why="honk's TCX programs own every device this program hooks, so the classic chain is never reached -- the proxy is the datapath, and claiming a fastpath the counters cannot back would be a lie"
		fi
	fi
	if [ -n "$why" ]; then
		dpd_log "gate: mode '$mode' downgraded to 'observe': $why"
		echo observe
		return 0
	fi
	echo "$mode"
}

# Is there a real uplink to accelerate towards? A device that exists, is not
# administratively/link down, and has a default route. pppoe-wan only appears
# once the session is up, so this is naturally false until then and the gate is
# re-evaluated on every ifup/hotplug.
dpd_has_uplink() {
	local dev state
	# network_get_device lives in /lib/functions/network.sh, not in
	# /lib/functions.sh; without this the lookup exits 127 and the gate永远
	# believes there is no uplink (measured 2026-10-19: the WAN was up with a
	# default route and dpd still logged "no uplink"). Sourcing twice is safe.
	. /lib/functions/network.sh 2>/dev/null
	network_get_device dev wan 2>/dev/null || dev=""
	[ -n "$dev" ] || return 1
	[ -e "/sys/class/net/$dev" ] || return 1
	state=$(cat "/sys/class/net/$dev/operstate" 2>/dev/null)
	case "$state" in
	down | lowerlayerdown | notpresent) return 1 ;;
	esac
	ip route show default 2>/dev/null | grep -q . || return 1
	return 0
}

# Re-evaluate the gates from uci and publish the result.
#
# Single source of truth for "what is the datapath allowed to do right now".
# Called by the init script at start and by /usr/libexec/dpd-gate-refresh (which
# einat invokes when the NAT comes or goes, and which an operator can run by
# hand). Echoes the effective mode.
dpd_gate_refresh_uci() {
	local enabled mode redirect ttl policy vlans emode

	config_load dpd_fastpath
	config_get_bool enabled global enabled 1
	config_get mode global mode off
	config_get redirect global redirect auto
	config_get ttl global flow_ttl_ms 5000
	config_get policy global policy 'allow_all'
	config_get vlans global vlans ''

	emode="$(dpd_gate_mode "$mode")"
	dpd_push_uci "$enabled" "$emode" "$redirect" "$ttl" "$policy"
	dpd_push_vlans "$policy" "$vlans"
	# The attachment invariant survives mode changes: a filter that was only a
	# counter while observing starts *accelerating* the moment einat attaches,
	# and the decision to attach is per event. An image upgraded in place can
	# also carry the older behaviour, which attached the uplink for telemetry.
	dpd_reconcile_uplink
	printf '%s' "$emode"
}

# Enforce "the uplink is never attached" (see the note in 90-dpd-fastpath).
#
# Called from the init script at start and from every gate refresh, so a stale
# attachment cannot outlive a mode change. Teaching its L2 flags is safe and
# necessary: redirect=auto needs them to pick the right emit path for the device
# every LAN->WAN flow leaves through.
dpd_reconcile_uplink() {
	local w d n=0

	for w in wan wan6 wan_6; do
		d="$(dpd_resolve_logical "$w")"
		[ -n "$d" ] || continue
		if dpd_is_attached "$d"; then
			dpd_detach_if "$d"
			dpd_log "invariant: detached $d (the uplink is never attached)"
			n=$((n + 1))
		fi
		dpd_teach_iface "$d"
	done
	[ "$n" = 0 ] || dpd_log "invariant: removed $n stale uplink attachment(s)"
	return 0
}

# Wait (bounded) for a device that does not exist yet, then attach it.
#
# The hotplug can fire while netifd is still creating the device -- measured
# 2026-10-18 with a pppoe WAN: `ifup wan -> pppoe-wan` arrived when
# /sys/class/net/pppoe-wan was not there yet, and netifd does not promise
# another event once it appears. Re-evaluate the gates first, so a device that
# turns out to be the uplink is taught and never attached.
dpd_wait_for_dev() {
	local dev="$1" iv="${DPD_WAIT_INTERVAL:-3}" tries="${DPD_WAIT_TRIES:-20}" i=0 emode

	while [ "$i" -lt "$tries" ]; do
		sleep "$iv"
		i=$((i + 1))
		[ -e "/sys/class/net/$dev" ] || continue
		if dpd_is_wan_device "$dev"; then
			dpd_teach_iface "$dev"
			dpd_log "late: $dev is the uplink; L2 flags taught, not attached"
			return 0
		fi
		emode="$(dpd_gate_refresh_uci)"
		dpd_attach_if "$dev" && dpd_log "late attach: $dev came up after $((i * iv))s (effective mode ${emode:-?})"
		return 0
	done
	dpd_log "gave up waiting for $dev (${tries}x${iv}s)"
	return 1
}

# Which modes take packets over?
dpd_mode_wants_accel() {
	case "$1" in
	stateless | stateful | neigh-probe) return 0 ;;
	*) return 1 ;;
	esac
}

# Is einat attached as this box's NAT right now?
#
# Match einat's *program names*, not "any TCX on the WAN": honk also owns TCX
# there (wan_ingress_l2), so a generic probe would answer "yes" on a box where
# nobody is doing NAT at all.
#   0 attached    1 not attached    2 cannot tell (no bpftool)
dpd_einat_attached() {
	command -v bpftool >/dev/null 2>&1 || return 2
	bpftool net show 2>/dev/null \
		| grep -qE 'tcx/(ingress|egress)[[:space:]]+(ingress_rev_snat|egress_snat)'
}

# Do honk's TCX programs own the datapath on the devices this program hooks?
#
# honk attaches TCX on br-lan, eth0, eth1 and dae0 -- every device we are on --
# and its programs return a verdict for every packet they see. Source fact,
# linux-6.18.55 net/core/dev.c:
#
#	if (tcx_needed) { sch_ret = tcx_run(...);
#			  if (sch_ret != TC_ACT_UNSPEC) goto ingress_verdict; }
#	sch_ret = tc_run(...);
#
# One non-UNSPEC verdict from any TCX program therefore skips the ENTIRE classic
# chain, and this program is a classic filter. Measured 2026-10-18 (coexist
# harness, QEMU x86_64): with honk running, a LAN->WAN flow that provably
# traversed br-lan moved pkt_total by 0, on every device that was tried.
#
# Matching honk's *program names* and not "any TCX" keeps the answer honest:
# einat's TCX on the uplink returns UNSPEC for packets it does not claim, so it
# does not hide us, and a box with no proxy must not be downgraded.
dpd_honk_owns() {
	command -v bpftool >/dev/null 2>&1 || return 1
	bpftool net show 2>/dev/null | grep -qE \
		'tcx/(ingress|egress)[[:space:]]+(lan_ingress_l2|lan_egress_l2|wan_ingress_l2|wan_egress_l2|dae0_ingress)'
}

# Is $1 the uplink device? Taking a packet over on the WAN would skip
# router-acl's nft guard and the input path for router-destined packets, so
# acceleration is LAN-side only.
dpd_is_wan_device() {
	local dev="$1" wdev=""

	[ -n "$dev" ] || return 1
	for wdev in wan wan6 wan_6; do
		local d
		d="$(dpd_resolve_logical "$wdev")"
		[ -n "$d" ] && [ "$d" = "$dev" ] && return 0
	done
	return 1
}

# Nothing foreign may sit *after* us in the classic chain on $1.
#
# The TCX-beats-classic rule is what guarantees the interception layer runs
# first, and it is a property of TCX, not of our pref. So the only way we could
# steal a packet the proxy wanted is if a *classic* bpf filter landed at a pref
# above ours. There is none today (router-acl owns 90 and is a policy layer we
# are happy to sit behind), and if one ever appears we stop accelerating rather
# than guess which of the two is the interception layer.
# Returns 0 = safe, 1 = something foreign is after us.
dpd_chain_guard() {
	local dev="$1" p bad=0

	for p in $(tc filter show dev "$dev" ingress 2>/dev/null |
		sed -n 's/.*pref \([0-9]*\) bpf.*/\1/p'); do
		[ "$p" -gt "$DPD_PREF" ] 2>/dev/null || continue
		bad=1
		dpd_log "chain guard: bpf filter at pref $p sits after ours (pref $DPD_PREF) on $dev"
	done
	[ "$bad" = 0 ]
}

# one compact line of evidence for the log: who owns which hook right now, as
# `bpftool net show` prints it, e.g.
#   br-lan(5) tcx/ingress lan_ingress_l2 | br-lan(5) tcx/egress lan_egress_l2 | ...
dpd_chain_summary() {
	command -v bpftool >/dev/null 2>&1 || { echo "bpftool not installed"; return 0; }

	bpftool net show 2>/dev/null | awk '
		/^tc:/ { intc = 1; next }
		/^[a-z_]+:/ { intc = 0 }
		intc && NF >= 3 { printf "%s %s %s | ", $1, $2, $3 }'
}

# TCX programs attached to an interface, as "tcx/ingress:prog tcx/egress:prog".
#
# Why this is worth reporting rather than silently ignoring: TCX runs BEFORE
# every classic filter. sch_handle_ingress()/sch_handle_egress() call tcx_run()
# and only then tc_run(), so anything a TCX program takes is gone before the
# classic chain -- and returning TC_ACT_REDIRECT ends the chain outright. The
# interception layer (honk/dae) attaches exactly such programs (lan_ingress_l2 /
# lan_egress_l2) to the LAN interface, so once honk is up our classic filter
# stops being entered and pkt_total freezes.
#
# Measured 2026-10-17 in QEMU: with honk attached, a LAN client that dpd had
# been accelerating (neigh_ok +13, eth1_tx +1040 in the same run) produced
# pkt_total 144401 -> 144401 across three flows while the traffic itself worked
# perfectly through honk. That is not a fault and not a detach: it is honk doing
# the datapath (it forwards direct flows and tproxies proxied ones in-kernel),
# with dpd kept behind it and taking over the moment a packet is passed through.
#
# This is deliberately a *note* and not a gate: einat can tell us when it comes
# and goes (its init calls /usr/libexec/dpd-gate-refresh), honk has no such hook
# -- a gate could only ever be evaluated once and would strand dpd in observe
# after honk stopped. Reporting the fact, without acting on it, is the honest
# version. `dpdctl stats` still shows whether we are seeing traffic at all.
dpd_tcx_on() {
	command -v bpftool >/dev/null 2>&1 || return 0

	bpftool net show 2>/dev/null | awk -v d="$1" '
		/^tc:/ { intc = 1; next }
		/^[a-z_]+:/ { intc = 0 }
		intc && $2 ~ /^tcx\// {
			split($1, a, "(")
			if (a[1] == d) printf "%s:%s ", $2, $3
		}'
}

dpd_status() {
	local any=0 dev tcx

	for dev in /sys/class/net/*; do
		dev="${dev##*/}"
		if dpd_is_attached "$dev"; then
			echo "  $dev: attached (pref $DPD_PREF)"
			tcx=$(dpd_tcx_on "$dev")
			if [ -n "$tcx" ]; then
				echo "    TCX ahead of us: $tcx"
				echo "    -> they run before any classic filter and a redirect ends the"
				echo "       chain, so packets they take never reach dpd. A flat"
				echo "       pkt_total with these present is expected: the proxy owns"
				echo "       the datapath and we take over whatever it passes through."
			else
				echo "    no TCX ahead: everything this interface receives reaches us"
			fi
			any=1
		fi
	done
	[ "$any" = 1 ] || echo "  no interface has the program attached"
	echo "--- who owns the TC hooks right now ---"
	dpd_chain_summary
	echo "--- gates ---"
	dpd_mode_wants_accel "$(dpd_effective_mode_late)" && {
		echo "  einat attached: $(dpd_einat_attached; case $? in 0) echo yes;; 1) echo NO;; *) echo unknown;; esac)"
	} || echo "  mode does not accelerate"
	echo "--- dpd_cfg ---"
	[ -x "$DPD_CTL" ] && "$DPD_CTL" show
	echo "--- counters ---"
	[ -x "$DPD_CTL" ] && "$DPD_CTL" stats
}

# what the datapath is *actually* set to (the effective, gated mode)
dpd_effective_mode_late() {
	local m=""

	if [ -x "$DPD_CTL" ]; then
		m=$("$DPD_CTL" show 2>/dev/null | sed -n 's/^mode *//p' | awk '{print $1}')
	fi
	printf '%s' "$m"
}
