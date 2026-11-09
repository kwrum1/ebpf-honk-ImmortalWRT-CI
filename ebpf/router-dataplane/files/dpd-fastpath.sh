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
DPD_SEC_L2=classifier/l2
DPD_SEC_L3=classifier/l3
DPD_PREF=100
DPD_CTL=/usr/sbin/dpdctl

# Published state, kept next to each other so a status page, `logread` and CI
# all read the same thing. gate    : 4 lines (requested/effective/code/reason)
#                           gate.json: the same, for LuCI/scripts
#                           status.json: `dpdctl status -j` snapshot (watchdog)
DPD_RUN_DIR=/var/run/ebpf
DPD_GATE_TEXT=$DPD_RUN_DIR/gate
DPD_GATE_JSON=$DPD_RUN_DIR/gate.json
DPD_STATUS_JSON=$DPD_RUN_DIR/status.json

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
	local dev="$1" gw=""

	[ -x "$DPD_CTL" ] || return 1
	[ -e "/sys/class/net/$dev" ] || return 1
	"$DPD_CTL" ifaces "$dev" >/dev/null 2>&1
	# A ppp/tun egress has no neighbour table, so the neigh emit needs an
	# explicit nexthop: with params==NULL bpf_redirect_neigh() redoes
	# ip_route_output_flow() per packet with flowi4_iif=0, and on this box's
	# policy routing that lookup is -ENETUNREACH, i.e. every accelerated
	# packet is silently freed (see struct dpd_iface_val in dpd_common.h).
	# Re-taught on every ifup/ifupdate, so a PPPoE redial picks up the new
	# peer address.
	gw="$(ip -4 route show default dev "$dev" 2>/dev/null |
		sed -n 's/.* via \([0-9][0-9.]*\).*/\1/p' | head -n 1)"
	[ -n "$gw" ] && "$DPD_CTL" gw "$dev" "$gw" >/dev/null 2>&1
	return 0
}

# Low-level attach to one device. No bridge recursion.
dpd_attach_one() {
	local dev="$1"

	[ -n "$dev" ] || return 1
	[ -e "/sys/class/net/$dev" ] || { dpd_log "no such device: $dev"; return 1; }
	[ -f "$DPD_OBJ" ] || { dpd_log "missing $DPD_OBJ"; return 1; }
	dpd_bpffs_ensure || dpd_log "warning: /sys/fs/bpf is not a bpffs"
	dpd_qdisc_ready "$dev" || { dpd_log "cannot create a tc hook on $dev"; return 1; }

	# L3 devices (ppp/tun) get the variant that starts at the IP header;
	# Ethernet/bridge/VLAN get the L2 parser. IFF_POINTOPOINT=0x10,
	# IFF_NOARP=0x80. This replaces the per-packet dpd_iface lookup.
	local sec flags
	flags=$(cat "/sys/class/net/$dev/flags" 2>/dev/null) || flags=0
	if [ $((flags & 0x90)) -ne 0 ]; then sec=$DPD_SEC_L3; else sec=$DPD_SEC_L2; fi

	# replace, do not stack
	tc filter del dev "$dev" ingress pref "$DPD_PREF" 2>/dev/null
	if ! tc filter add dev "$dev" ingress pref "$DPD_PREF" handle "$DPD_PREF" \
		bpf da obj "$DPD_OBJ" sec "$sec"; then
		dpd_log "tc filter add failed on $dev (program not loaded)"
		return 1
	fi

	# the program is loaded now, so the pin exists and the flags can land
	dpd_teach_iface "$dev"
	return 0
}

# Attach to a device and, when it is a bridge master, to every bridge port.
# A tc ingress filter on the bridge master does not see frames forwarded
# between its ports: LAN clients enter on eth0, and without a filter there the
# fast path never sees LAN->WAN traffic at all. Measured on the ESXi lab
# 2026-11-08: pkt/hit stayed flat on br-lan until the filter was also attached
# to eth0.
dpd_attach_if() {
	local dev="$1" p

	dpd_attach_one "$dev" || return 1
	if [ -d "/sys/class/net/$dev/brif" ]; then
		for p in /sys/class/net/"$dev"/brif/*; do
			[ -e "$p" ] || continue
			p=${p##*/}
			[ "$p" = "$dev" ] && continue
			dpd_attach_one "$p" || dpd_log "bridge port $p attach failed"
		done
	fi
	return 0
}

dpd_detach_if() {
	local dev="$1" p

	[ -e "/sys/class/net/$dev" ] || return 0
	tc filter del dev "$dev" ingress pref "$DPD_PREF" 2>/dev/null
	if [ -d "/sys/class/net/$dev/brif" ]; then
		for p in /sys/class/net/"$dev"/brif/*; do
			[ -e "$p" ] || continue
			p=${p##*/}
			[ "$p" = "$dev" ] && continue
			tc filter del dev "$p" ingress pref "$DPD_PREF" 2>/dev/null
		done
	fi
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
	local refresh="$6" ipv6="$7" mss="$8" accel="$9" ttl_tcp="${10}"
	local ttl_udp="${11}" ttl_udp1="${12}"

	[ -x "$DPD_CTL" ] || return 0
	"$DPD_CTL" set mode "$mode" 2>/dev/null
	# ABI 16: an accelerating gate guarantees einat is attached on the
	# uplinks (dpd_gate_mode() refuses to accelerate otherwise), so the
	# forward half may be taken over once a mirrored binding exists and
	# einat's TCX egress does the SNAT. Any other effective mode leaves the
	# uplink half to the stack, which is the only safe choice when fw4's
	# masquerade owns NAT.
	case "$mode" in
	stateful | stateless)
		"$DPD_CTL" set nat 1 2>/dev/null ;;
	*)
		"$DPD_CTL" set nat 0 2>/dev/null ;;
	esac
	"$DPD_CTL" set redirect "$redirect" 2>/dev/null
	"$DPD_CTL" set ttl "$ttl" 2>/dev/null
	# ABI 17 Flow Manager knobs. The script only publishes; the values come
	# from UCI so an operator can A/B without rebuilding.
	[ -n "$accel" ] && "$DPD_CTL" set accel "$accel" 2>/dev/null
	[ -n "$ttl_tcp" ] && "$DPD_CTL" set tcp_ttl "$ttl_tcp" 2>/dev/null
	[ -n "$ttl_udp" ] && "$DPD_CTL" set udp_ttl "$ttl_udp" 2>/dev/null
	[ -n "$ttl_udp1" ] && "$DPD_CTL" set udp_unidir_ttl "$ttl_udp1" 2>/dev/null
	[ -n "$refresh" ] && "$DPD_CTL" set refresh "$refresh" 2>/dev/null
	[ -n "$ipv6" ] && "$DPD_CTL" set ipv6 "$ipv6" 2>/dev/null
	[ -n "$mss" ] && "$DPD_CTL" set mss "$mss" 2>/dev/null
	[ -n "$policy" ] && "$DPD_CTL" set policy "$policy" 2>/dev/null
	"$DPD_CTL" set enable "$enabled" 2>/dev/null
	return 0
}

# Drop every cached egress decision in one store. Called when something that a
# cached entry depends on changed (link state, address, route, neighbour, WAN
# table). Without it the hit path would have to re-validate dpd_wans and
# dpd_iface for every packet -- which is exactly what ABI 9 removed.
dpd_bump_epoch() {
	[ -x "$DPD_CTL" ] || return 0
	"$DPD_CTL" bump >/dev/null 2>&1
	return 0
}

# The map value layout is part of the pinned-map ABI. A package upgrade that
# changes it makes libbpf refuse to reuse /sys/fs/bpf/dpd_*, and `tc filter add`
# then fails with a pin error that says nothing about the real cause. Compare the
# ABI the object was built with (installed by the package) with the one the
# pinned map still has, and drop the pins when they differ.
dpd_pins_compat() {
	local want cur

	[ -r /usr/lib/dpd/abi ] || return 0
	want="$(cat /usr/lib/dpd/abi 2>/dev/null)"
	[ -n "$want" ] || return 0
	cur="$("$DPD_CTL" abi 2>/dev/null)"
	[ -n "$cur" ] || return 0
	[ "$cur" = "$want" ] && return 0

	dpd_log "ABI changed ($cur -> $want): dropping stale pinned maps"
	# ABI 12 merged the counters into dpd_cfg's per-CPU value; older images
	# may still have a dpd_stats pin, so remove it too if present.
	rm -f /sys/fs/bpf/dpd_cfg /sys/fs/bpf/dpd_stats /sys/fs/bpf/dpd_flows \
		/sys/fs/bpf/dpd_iface /sys/fs/bpf/dpd_vlans \
		/sys/fs/bpf/dpd_mtu /sys/fs/bpf/dpd_wans 2>/dev/null
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

# The acceleration gate. $1 = the mode uci asked for, $2 = enabled (0/1).
# Echoes the mode that may actually be used and publishes the decision.
#
# Rationale (full version in src/dpd_common.h): taking a flow over skips
# netfilter, so the return path of an accelerated flow exists only because einat
# is the NAT and injects a blanket WAN->LAN accept into fw4. Without a
# confirmed-attached einat the honest thing is to watch and not accelerate -- an
# accelerator that silently eats replies is worse than no accelerator.
#
# Why the decision is *published* and not only logged: the log tells you what
# happened but not what is true now, and it is buried among a boot's worth of
# other lines. /var/run/ebpf/gate.json is the answer to "why is nothing
# accelerated?" that LuCI, `dpdctl status` and CI read. The shell globals
# (DPD_GATE_CODE etc.) are best-effort: callers run this in $( ), where they do
# not propagate -- the files are the interface.
dpd_gate_code=ok
dpd_gate_reason="accelerating"
dpd_gate_req=""
dpd_gate_eff=""

dpd_gate_publish() {
	local req="$1" eff="$2" code="$3" reason="$4"
	local uplink=0 ein=0 ein_up=0 honk=0 honk_p1=0 r

	dpd_has_uplink && uplink=1
	dpd_einat_attached
	r=$?
	[ "$r" = 0 ] && ein=1
	dpd_einat_on_uplink
	r=$?
	[ "$r" = 0 ] && ein_up=1
	dpd_honk_owns && honk=1
	dpd_honk_passes_direct && honk_p1=1

	mkdir -p "$DPD_RUN_DIR" 2>/dev/null
	# 4-line text form first: a reader that only knows shell (or a human on
	# the serial console) must not need a JSON parser.
	printf '%s\n%s\n%s\n%s\n' "$req" "$eff" "$code" "$reason" \
		> "$DPD_GATE_TEXT.tmp" 2>/dev/null &&
		mv -f "$DPD_GATE_TEXT.tmp" "$DPD_GATE_TEXT" 2>/dev/null

	# JSON form for LuCI. The reason is one ASCII line by construction, but
	# quote/escape it anyway: a future reason with a quote must not produce
	# invalid JSON that the page then has to guess about.
	local rj
	rj=$(printf '%s' "$reason" | sed 's/\\/\\\\/g; s/"/\\"/g')
	{
		printf '{\n'
		printf '  "requested": "%s",\n' "$req"
		printf '  "effective": "%s",\n' "$eff"
		printf '  "code": "%s",\n' "$code"
		printf '  "reason": "%s",\n' "$rj"
		printf '  "at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
		printf '  "uptime_s": %s,\n' "$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)"
		printf '  "checks": { "uplink": %s, "einat": %s, ' \
			"$([ "$uplink" = 1 ] && echo true || echo false)" \
			"$([ "$ein" = 1 ] && echo true || echo false)"
		printf '"einat_on_uplink": %s, "honk": %s, "honk_p1": %s }\n' \
			"$([ "$ein_up" = 1 ] && echo true || echo false)" \
			"$([ "$honk" = 1 ] && echo true || echo false)" \
			"$([ "$honk_p1" = 1 ] && echo true || echo false)"
		printf '}\n'
	} > "$DPD_GATE_JSON.tmp" 2>/dev/null &&
		mv -f "$DPD_GATE_JSON.tmp" "$DPD_GATE_JSON" 2>/dev/null

	dpd_gate_code=$code
	dpd_gate_reason=$reason
	dpd_gate_req=$req
	dpd_gate_eff=$eff
}

# Snapshot the counters for the status page. Written from the gate refresh and
# from every watchdog tick, so a page without exec rights still reads fresh
# numbers; when the page can exec dpdctl it ignores this file.
dpd_status_publish() {
	[ -x "$DPD_CTL" ] || return 0
	mkdir -p "$DPD_RUN_DIR" 2>/dev/null
	"$DPD_CTL" status -j > "$DPD_STATUS_JSON.tmp" 2>/dev/null &&
		mv -f "$DPD_STATUS_JSON.tmp" "$DPD_STATUS_JSON" 2>/dev/null
	return 0
}

dpd_gate_mode() {
	local mode="$1" enabled="${2:-1}" why="" code="ok" r

	if [ "$enabled" != "1" ]; then
		code=uci-disabled
		why="acceleration is disabled in uci (dpd_fastpath.global.enabled=0)"
	elif [ "$mode" = "off" ]; then
		code=mode-off
		why="configured mode is 'off': the program still counts, but takes nothing over"
	elif [ "$mode" = "observe" ]; then
		code=mode-observe
		why="configured mode is 'observe': telemetry only, by operator request"
	elif dpd_mode_wants_accel "$mode"; then
		# Acceleration is a *forwarding* optimisation: it redirects LAN->WAN
		# flows out of the uplink. With no uplink at all (WAN down, no cable,
		# no lease yet) there is nothing to accelerate, and the program must
		# not touch the LAN: with einat able to report "attached" on an
		# uplink that has no address or route, the gate would otherwise let
		# it run. Measured on the lab VM (single-NIC, no WAN), stateless mode
		# made every TCP/UDP connection *to the router* time out while ICMP
		# still answered -- i.e. the box became unmanageable.
		if ! dpd_has_uplink; then
			code=no-uplink
			why="no uplink (no WAN device or no default route), so there is no forwarding path to accelerate and hooking the LAN would only steal traffic addressed to the router itself"
		fi
		if [ "$code" = "ok" ]; then
			dpd_einat_attached
			r=$?
			case "$r" in
			1) code=no-einat
			   why="einat is not attached, so the reply of an accelerated flow would be dropped by fw4 (no conntrack state, no NAT)" ;;
			2) code=einat-unknown
			   why="cannot tell whether einat is attached (no bpftool); refusing to accelerate blind" ;;
			esac
		fi
		# and it must be on the uplink we actually steer into, not just
		# somewhere on the box
		if [ "$code" = "ok" ]; then
			dpd_einat_on_uplink
			r=$?
			case "$r" in
			1) code=einat-not-on-uplink
			   why="einat is not attached on at least one uplink, so flows steered there would have untracked replies" ;;
			2) code=einat-uplink-unknown
			   why="cannot confirm einat on the uplinks (no bpftool or no uplink device)" ;;
			esac
		fi
		if [ "$code" = "ok" ] && dpd_honk_owns && ! dpd_honk_passes_direct; then
			code=honk-unpatched
			why="honk owns the LAN TCX and its direct exit is terminal (unpatched core), so the classic chain never runs -- the proxy is the datapath, and claiming a fastpath the counters cannot back would be a lie"
		fi
	else
		code=mode-unknown
		why="configured mode '$mode' is not one this datapath accelerates with"
	fi

	if [ "$code" = "ok" ]; then
		dpd_gate_publish "$mode" "$mode" ok "accelerating (mode $mode)"
		echo "$mode"
		return 0
	fi
	dpd_log "gate: mode '$mode' downgraded to 'observe' [$code]: $why"
	dpd_gate_publish "$mode" observe "$code" "$why"
	echo observe
	return 0
}

# Is there a real uplink to accelerate towards? A device that exists, is not
# administratively/link down, and has a default route. pppoe-wan only appears
# once the session is up, so this is naturally false until then and the gate is
# re-evaluated on every ifup/hotplug.
#
# Every uplink counts, not just `wan`: with multi-WAN, `ifdown wan` leaves wan2
# up and carrying the default route, but a `network_get_device dev wan` probe
# answers "no uplink" and the gate then downgrades to observe -- measured on the
# bench during the failover test, which silently turned acceleration off for the
# surviving link. dpd_uplink_devs() is the same list the downlink reconciler
# uses, so both agree on what an uplink is.
dpd_has_uplink() {
	local dev state

	. /lib/functions/network.sh 2>/dev/null

	for dev in $(dpd_uplink_devs); do
		[ -e "/sys/class/net/$dev" ] || continue
		state=$(cat "/sys/class/net/$dev/operstate" 2>/dev/null)
		case "$state" in
		down | lowerlayerdown | notpresent) continue ;;
		esac
		ip route show default 2>/dev/null | grep -q . && return 0
	done
	return 1
}

# Re-evaluate the gates from uci and publish the result.
#
# Single source of truth for "what is the datapath allowed to do right now".
# Called by the init script at start and by /usr/libexec/dpd-gate-refresh (which
# einat invokes when the NAT comes or goes, and which an operator can run by
# hand). Echoes the effective mode.
dpd_gate_refresh_uci() {
	local enabled mode redirect ttl policy vlans refresh ipv6 mss emode
	local accel tcp_ttl udp_ttl udp_unidir_ttl flow_counters class_enable

	config_load dpd_fastpath
	config_get_bool enabled global enabled 1
	config_get mode global mode off
	config_get redirect global redirect auto
	config_get ttl global flow_ttl_ms 5000
	config_get refresh global flow_refresh_ms 250
	config_get ipv6 global ipv6 0
	config_get mss global mss_clamp 1
	config_get policy global policy 'allow_all'
	config_get vlans global vlans ''
	config_get accel global accel_after_pkts 32
	config_get tcp_ttl global tcp_ttl_ms 300000
	config_get udp_ttl global udp_ttl_ms 120000
	config_get udp_unidir_ttl global udp_unidir_ttl_ms 30000
	config_get_bool flow_counters global flow_counters 1
	config_get_bool class_enable global class_enable 1

	emode="$(dpd_gate_mode "$mode" "$enabled")"
	dpd_push_uci "$enabled" "$emode" "$redirect" "$ttl" "$policy" "$refresh" \
		"$ipv6" "$mss" "$accel" "$tcp_ttl" "$udp_ttl" "$udp_unidir_ttl"
	"$DPD_CTL" set counters "$flow_counters" 2>/dev/null
	"$DPD_CTL" set class "$class_enable" 2>/dev/null
	dpd_push_vlans "$policy" "$vlans"
	# The attachment invariant survives mode changes: a filter that was only a
	# counter while observing starts *accelerating* the moment einat attaches,
	# and the decision to attach is per event. An image upgraded in place can
	# also carry the older behaviour, which attached the uplink for telemetry.
	dpd_reconcile_uplink
	dpd_status_publish
	printf '%s' "$emode"
}

# Enforce "the uplink is never attached" unless `option downlink '1'`.
#
# Called from the init script at start and from every gate refresh, so a stale
# attachment cannot outlive a mode change. Teaching its L2 flags is safe and
# necessary: redirect=auto needs them to pick the right emit path for the device
# every LAN->WAN flow leaves through.
#
# With downlink=1 the uplink *is* attached, on purpose: that is the return
# direction (WAN->LAN) accelerator. It is opt-in because it hooks the device
# whose inbound policy belongs to router-acl and fw4 (see the note below), and
# because it is only safe in stateful mode: the first packet of every flow still
# traverses netfilter and builds conntrack/NAT state, and only then does the
# program start taking the rest of that flow over. Measured on the lab bench
# (2026-10-27, 2 vCPU x86_64, -P4 iperf3 download): 2.72 -> 3.44 Gbit/s, router
# CPU 61% -> 65% (total), and the L2 emit path another +16% on top of that.
# Every device that carries a default route for this box: the primary WAN names
# plus, when multi-WAN is on, each uplink ebpf-mwan balances over. A plain
# `for w in wan wan6` loop silently skipped wan2/wan3 -- measured on the bench:
# only eth2 got the downlink hook and eth3 never did, so the second uplink's
# return direction walked netfilter while the first one was accelerated.
dpd_uplink_devs() {
	local w d

	for w in wan wan6 wan_6; do
		d="$(dpd_resolve_logical "$w")"
		[ -n "$d" ] && echo "$d"
	done

	# Only when the balancer is on: otherwise ebpf_mwan's sections may be
	# leftover experiments and must not get a hook.
	[ "$(uci -q get ebpf_mwan.global.enabled 2>/dev/null)" = "1" ] || return 0
	for w in $(uci -q show ebpf_mwan 2>/dev/null |
		sed -n 's/^ebpf_mwan\.\([^.=]*\)\.interface=.*/\1/p'); do
		[ "$(uci -q get "ebpf_mwan.$w.enabled" 2>/dev/null)" = "0" ] && continue
		d="$(dpd_resolve_logical "$w")"
		[ -n "$d" ] && echo "$d"
	done
}

dpd_reconcile_uplink() {
	local w d n=0 downlink=0 mode=""

	config_load dpd_fastpath
	config_get_bool downlink global downlink 1
	config_get mode global mode off
	dpd_downlink_wanted "$mode" "$downlink" || downlink=0

	for d in $(dpd_uplink_devs | awk '!seen[$0]++'); do
		if [ "$downlink" = 1 ]; then
			# attached on purpose; the chain guard decides whether the
			# policy layer is behind us on that device too
			dpd_attach_if "$d" || continue
			dpd_chain_guard "$d" || dpd_log "chain guard: a bpf filter sits after us on uplink $d"
			n=$((n + 1))
			continue
		fi
		if dpd_is_attached "$d"; then
			dpd_detach_if "$d"
			dpd_log "invariant: detached $d (the uplink is never attached)"
			n=$((n + 1))
		fi
		dpd_teach_iface "$d"
	done
	if [ "$downlink" = 1 ]; then
		dpd_log "downlink=1: uplink ingress accelerated for learned flows ($n device(s))"
	elif [ "$n" -gt 0 ]; then
		dpd_log "invariant: removed $n stale uplink attachment(s)"
	fi
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
			# With downlink=1 the uplink *is* wanted; the decision (and
			# the mode=stateful condition) lives in one place.
			dpd_reconcile_uplink
			if dpd_is_attached "$dev"; then
				dpd_log "late: $dev is the uplink; L2 flags taught, attached for downlink"
			else
				dpd_log "late: $dev is the uplink; L2 flags taught, not attached"
			fi
			return 0
		fi
		emode="$(dpd_gate_refresh_uci)"
		dpd_attach_if "$dev" && dpd_log "late attach: $dev came up after $((i * iv))s (effective mode ${emode:-?})"
		return 0
	done
	dpd_log "gave up waiting for $dev (${tries}x${iv}s)"
	return 1
}

# Is the return direction allowed to be accelerated?
#
# Two conditions, and neither is negotiable:
#   * `option downlink '1'`, and
#   * `option mode 'stateful'`.
#
# In stateless mode the *first* WAN->LAN packet of a flow would be taken over as
# well, i.e. the return direction would never create a conntrack entry at all
# and no fw4 forward rule would ever see the flow -- not even its first packet.
# That is not a trade this box gets to make, so downlink is silently (but
# loudly logged) ignored outside stateful mode.
dpd_downlink_wanted() {
	local mode="$1" downlink="$2"

	[ "$downlink" = 1 ] || return 1
	case "$mode" in
	stateful) return 0 ;;
	esac
	dpd_log "downlink=1 ignored: the return direction is only accelerated with mode=stateful (configured mode is '$mode')"
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

# Is einat's NAT attached on the uplink device(s) the accelerated flows leave
# through? dpd_einat_attached() answers "is some einat program attached
# anywhere"; this answers "on the device that matters". A box with einat on a
# second WAN but not on the one dpd steers into would accept the fast path
# locally and then have its replies dropped on the way back.
#
# 0 = einat present on every uplink, 1 = missing on at least one,
# 2 = cannot tell (no bpftool / no uplinks).
dpd_einat_on_uplink() {
	local d n=0

	command -v bpftool >/dev/null 2>&1 || return 2
	for d in $(dpd_uplink_devs); do
		[ -n "$d" ] || continue
		n=$((n + 1))
		if ! bpftool net show 2>/dev/null | grep -E "^${d}\(" | grep -q 'ingress_rev_snat'; then
			dpd_log "gate: uplink $d has no einat ingress_rev_snat"
			return 1
		fi
	done
	[ "$n" -gt 0 ] || return 2
	return 0
}

# Do honk's TCX programs own the datapath on the devices this program hooks?
#
# honk attaches TCX on br-lan and its bridge slaves (and dae0); its programs
# return a verdict for every packet they see. Source fact, linux-6.18.55
# net/core/dev.c:
#
#	if (tcx_needed) { sch_ret = tcx_run(...);
#			  if (sch_ret != TC_ACT_UNSPEC) goto ingress_verdict; }
#	sch_ret = tc_run(...);
#
# One non-UNSPEC verdict from any TCX program therefore skips the ENTIRE classic
# chain, and this program is a classic filter. Measured 2026-10-18 (coexist
# harness, QEMU x86_64): with the stock honk core, a LAN->WAN flow that provably
# traversed br-lan moved pkt_total by 0.
#
# The p1 core is different on purpose: its direct exits return TC_ACT_UNSPEC
# (see ci/patches/honk-direct-unspec.py in the honk package), so direct flows do
# reach this filter while proxy/block verdicts stay terminal. The gate asks
# dpd_honk_passes_direct() (the marker) before trusting that.
#
# Matching honk's *program names* and not "any TCX" keeps the answer honest:
# einat's TCX on the uplink returns UNSPEC for packets it does not claim, so it
# does not hide us, and a box with no proxy must not be downgraded.
dpd_honk_owns() {
	command -v bpftool >/dev/null 2>&1 || return 1
	bpftool net show 2>/dev/null | grep -qE \
		'tcx/(ingress|egress)[[:space:]]+(lan_ingress_l2|lan_egress_l2|wan_ingress_l2|wan_egress_l2|dae0_ingress)'
}

# Does the running honk core hand direct-classified flows back to the classic
# chain? The patched core (honk package p1, ci/patches/honk-direct-unspec.py)
# installs this marker and returns TC_ACT_UNSPEC for direct flows, so the only
# packets reaching dpd are the ones we are allowed to accelerate. Proxy and
# block verdicts stay terminal and never reach us.
#
# Without the marker, honk's direct exit is TC_ACT_OK and the classic chain is
# skipped entirely. Accelerating the WAN return half in that state is not safe:
# the flow table is learned on the LAN (which honk swallows), and a forced
# stateful run was measured to break a TCP connection on the first reverse test.
dpd_honk_passes_direct() {
	[ -f /usr/share/honk/direct-unspec ]
}

# Is $1 the uplink device? Taking a packet over on the WAN would skip
# router-acl's nft guard and the input path for router-destined packets, so
# acceleration is LAN-side only.
dpd_is_wan_device() {
	local dev="$1" d

	[ -n "$dev" ] || return 1
	for d in $(dpd_uplink_devs); do
		[ "$d" = "$dev" ] && return 0
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
	echo "--- gate (published by the last evaluation) ---"
	if [ -r "$DPD_GATE_TEXT" ]; then
		printf '  requested   %s\n' "$(sed -n '1p' "$DPD_GATE_TEXT")"
		printf '  effective   %s\n' "$(sed -n '2p' "$DPD_GATE_TEXT")"
		printf '  code        %s\n' "$(sed -n '3p' "$DPD_GATE_TEXT")"
		printf '  reason      %s\n' "$(sed -n '4p' "$DPD_GATE_TEXT")"
	else
		echo "  not published yet (run /usr/libexec/dpd-gate-refresh)"
	fi
	echo "--- dpd_cfg ---"
	[ -x "$DPD_CTL" ] && "$DPD_CTL" show
	echo "--- counters ---"
	[ -x "$DPD_CTL" ] && "$DPD_CTL" stats
	dpd_status_publish
}

# what the datapath is *actually* set to (the effective, gated mode)
dpd_effective_mode_late() {
	local m=""

	if [ -x "$DPD_CTL" ]; then
		m=$("$DPD_CTL" show 2>/dev/null | sed -n 's/^mode *//p' | awk '{print $1}')
	fi
	printf '%s' "$m"
}
