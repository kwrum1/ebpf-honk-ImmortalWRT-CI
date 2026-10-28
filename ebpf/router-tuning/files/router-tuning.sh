#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# ebpf router-tuning - the engine.
#
# Sourced by /etc/init.d/router-tuning and by /etc/hotplug.d/iface/93-router-tuning.
# There is no dispatcher here on purpose: the init owns the commands.
#
# Ownership rules, and why every branch below is written defensively:
#
#   * CAKE owns the WAN root qdisc (router-qos). We never touch a device that
#     already has a root qdisc we did not install, and we never write the WAN's
#     root qdisc at all.
#   * The upstream `packet_steering` service (S25, enabled in this image) owns
#     rps_cpus and the NAPI/IRQ affinity split. We only fill in when it is
#     provably off, or when every rps_cpus is still zero.
#   * honk sets rp_filter / accept_local / ip_forward / rmem_max / wmem_max
#     itself (measured: `strings honk-core`). Those are only ever *raised*.
#   * /etc/config/{network,dhcp,firewall} are never written. Everything this
#     file needs to know it reads (ubus is read-only here, uci is read-only).
#
# Every action goes through rt_wr()/rt_cmd(), so `router-tuning report` is the
# same code path with RT_DRYRUN=1 - the report cannot lie about what apply does.

RT_SYSCTL=/etc/sysctl.d/29-router-tuning.conf
RT_STATE=/etc/router-tuning.state
RT_TAG=router-tuning

rt_log() { logger -t "$RT_TAG" "$@"; }

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

rt_note() {
	# rt_note <item> <value> <status>
	printf '  %-26s %-30s %s\n' "$1" "$2" "$3"
}

rt_save() {
	# rt_save <kind> <key> <value>  -- first value seen wins, so a second apply
	# never overwrites the real original with one of our own values.
	local kind="$1" key="$2" val="$3"
	[ "$RT_DRYRUN" = 1 ] && return 0
	grep -qF "$kind|$key|" "$RT_STATE" 2>/dev/null && return 0
	printf '%s|%s|%s\n' "$kind" "$key" "$val" >>"$RT_STATE"
}

rt_wr() {
	# rt_wr <path> <value> <item>
	if [ "$RT_DRYRUN" = 1 ]; then
		rt_note "$3" "$2" would-set
		return 0
	fi
	if [ -e "$1" ] && printf '%s\n' "$2" >"$1" 2>/dev/null; then
		rt_note "$3" "$2" ok
		return 0
	fi
	rt_note "$3" "$2" FAILED
	return 1
}

rt_cmd() {
	# rt_cmd <item> <cmd...>
	local item="$1"
	shift
	if [ "$RT_DRYRUN" = 1 ]; then
		rt_note "$item" "$*" would-run
		return 0
	fi
	if "$@" >/dev/null 2>&1; then
		rt_note "$item" "$*" ok
		return 0
	fi
	rt_note "$item" "$*" FAILED
	return 1
}

rt_hexmask() {
	# rt_hexmask <cpu id...> -> a CPU mask in the /sys form (hex, no 0x)
	local id mask=0
	for id in "$@"; do
		mask=$((mask | (1 << id)))
	done
	printf '%x' "$mask"
}

rt_int() { case "$1" in '' | *[!0-9]*) return 1 ;; *) return 0 ;; esac; }

# ---------------------------------------------------------------------------
# environment detection
# ---------------------------------------------------------------------------

rt_cpu_ids() {
	local rng a b i
	for rng in $(sed 's/,/ /g' /sys/devices/system/cpu/online 2>/dev/null); do
		case "$rng" in
		*-*)
			a=${rng%-*}
			b=${rng#*-}
			i=$a
			while [ "$i" -le "$b" ]; do
				echo "$i"
				i=$((i + 1))
			done
			;;
		'') ;;
		*) echo "$rng" ;;
		esac
	done
}

rt_ncpu() { rt_cpu_ids | wc -l; }

rt_mem_mb() { awk '/^MemTotal:/{print int($2 / 1024); exit}' /proc/meminfo 2>/dev/null; }

rt_is_virt() {
	# virtio present and no real DMI board string is the signal we care about:
	# inside a guest the ring sizes and IRQ affinity belong to the host.
	local p
	for p in /sys/class/dmi/id/product_name /sys/class/dmi/id/sys_vendor; do
		[ -r "$p" ] || continue
		case "$(cat "$p" 2>/dev/null)" in
		*KVM* | *QEMU* | *VirtualBox* | *VMware* | *Bochs* | *"Standard PC"*) return 0 ;;
		esac
	done
	[ -e /proc/xen ] && return 0
	return 1
}

rt_tier() {
	# rt_tier <profile> -> the tier name. `auto` derives one from RAM.
	local profile="$1" mem
	mem=$(rt_mem_mb)
	case "$profile" in
	conservative | standard | aggressive) echo "$profile"; return 0 ;;
	esac
	if rt_int "$mem" && [ "$mem" -le 300 ]; then
		echo conservative
	elif rt_int "$mem" && [ "$mem" -le 1200 ]; then
		echo standard
	else
		echo aggressive
	fi
}

# The physical ports worth tuning: have a `device` link, are not a bridge port,
# not a virtual pair of ours, not the loopback.
rt_ifaces() {
	local d n
	for d in /sys/class/net/*; do
		[ -e "$d/device" ] || continue
		[ -e "$d/brport" ] && continue
		n=$(basename "$d")
		case "$n" in
		lo | br-* | veth* | netkit* | dae0 | dae0peer | ifb*) continue ;;
		esac
		echo "$n"
	done
}

rt_logical_dev() {
	# rt_logical_dev <netifd iface> -> its l3_device, or nothing.
	local want="$1" s
	s=$(ubus call "network.interface.$want" status 2>/dev/null)
	[ -n "$s" ] || return 1
	printf '%s' "$s" | grep -o '"l3_device":[[:space:]]*"[^"]*"' | head -1 |
		sed 's/.*"l3_device":[[:space:]]*"\([^"]*\)".*/\1/'
}

rt_wan_dev() {
	local d
	d=$(rt_logical_dev wan) || d=""
	[ -n "$d" ] || d="$WAN_DEV"
	[ -n "$d" ] || d=eth1
	printf '%s' "$d"
}

# ---------------------------------------------------------------------------
# sysctl
# ---------------------------------------------------------------------------

rt_sysctl_conf() {
	# rt_sysctl_conf <tier> -- the /etc/sysctl.d body.
	# Values scale with RAM so a 128 MB IPQ is not handed a 16 MB socket cap.
	local tier="$1"
	local rmem wmem tcp_r tcp_w backlog budget somaxconn udpmin
	case "$tier" in
	conservative)
		rmem=4194304; wmem=4194304
		tcp_r='4096 65536 2097152'; tcp_w='4096 65536 2097152'
		backlog=2048; budget=300; somaxconn=1024; udpmin=16384
		;;
	aggressive)
		rmem=16777216; wmem=16777216
		tcp_r='4096 262144 16777216'; tcp_w='4096 262144 16777216'
		backlog=8192; budget=900; somaxconn=8192; udpmin=65536
		;;
	*)
		rmem=8388608; wmem=8388608
		tcp_r='4096 131072 8388608'; tcp_w='4096 131072 8388608'
		backlog=4096; budget=600; somaxconn=4096; udpmin=32768
		;;
	esac

	cat <<-EOF
		# ebpf router-tuning (tier: $tier). Generated - edit
		# /etc/config/router_tuning, not this file.
		#
		# Applied by /etc/init.d/sysctl (START=11), i.e. before network (20)
		# creates any device. That ordering is the reason default_qdisc is
		# here and not in the service.
	EOF

	# Only advertise fq when the module is actually available; a default_qdisc
	# the kernel cannot load leaves every new device with no qdisc at all.
	if rt_fq_available; then
		cat <<-EOF

			# BBR's preferred pacing qdisc. Only emitted when sch_fq loads.
			net.core.default_qdisc=fq
		EOF
	else
		rt_log 'sch_fq is not available; default_qdisc left at fq_codel'
	fi

	cat <<-EOF

		# Honk also raises rmem_max/wmem_max; sysctl only ever raises, never
		# lowers, so ordering between the two does not matter.
		net.core.rmem_max=$rmem
		net.core.wmem_max=$wmem
		net.core.netdev_max_backlog=$backlog
		net.core.netdev_budget=$budget
		net.core.somaxconn=$somaxconn

		net.ipv4.tcp_rmem=$tcp_r
		net.ipv4.tcp_wmem=$tcp_w
		net.ipv4.udp_rmem_min=$udpmin
		net.ipv4.udp_wmem_min=$udpmin

		# Do not reset cwnd after an idle period: this box carries a proxy and
		# long-lived connections that go quiet between requests.
		net.ipv4.tcp_slow_start_after_idle=0
		# PMTU blackhole repair. The accelerated path skips fw4's mtu_fix
		# clamp, so the client side needs a way to crawl back down.
		net.ipv4.tcp_mtu_probing=1
		net.ipv4.tcp_notsent_lowat=131072
		net.ipv4.tcp_fastopen=3
		net.ipv4.tcp_tw_reuse=1
		net.ipv4.tcp_fin_timeout=30
		# Wider ephemeral range = more concurrent full-cone NAT flows
		# available to einat.
		net.ipv4.ip_local_port_range=10240 65535
	EOF

	if rt_bbr_available; then
		cat <<-EOF

			# BBR, when kmod-tcp-bbr is installed. kmod-tcp-bbr's own
			# /etc/sysctl.d/12-tcp-bbr.conf does this too; both are
			# idempotent and this one is not installed without the module.
			net.ipv4.tcp_congestion_control=bbr
		EOF
	fi
}

rt_gen_sysctl() {
	# rt_gen_sysctl <tier> -- regenerate the file only when it would change.
	local tier="$1" tmp
	tmp=$(mktemp -p /tmp rt-sysctl.XXXXXX) || return 1
	rt_sysctl_conf "$tier" >"$tmp"
	if [ "$RT_DRYRUN" = 1 ]; then
		rt_note "$RT_SYSCTL" "tier=$tier" would-write
		rm -f "$tmp"
		return 0
	fi
	if cmp -s "$tmp" "$RT_SYSCTL" 2>/dev/null; then
		rt_note "$RT_SYSCTL" "tier=$tier" unchanged
		rm -f "$tmp"
		return 0
	fi
	if mv "$tmp" "$RT_SYSCTL"; then
		chmod 0644 "$RT_SYSCTL"
		rt_note "$RT_SYSCTL" "tier=$tier" written
	else
		rm -f "$tmp"
		rt_note "$RT_SYSCTL" "tier=$tier" FAILED
		return 1
	fi
}

rt_sysctl_set() {
	# rt_sysctl_set <key> <value> [raise]
	# `raise` keeps the larger numeric value (or the larger last field of a
	# three-field value like tcp_rmem), so we never undo honk's own settings.
	local key="$1" want="$2" mode="$3" path cur last_want last_cur
	path="/proc/sys/$(printf '%s' "$key" | tr . /)"
	if [ ! -e "$path" ]; then
		rt_note "$key" "$want" 'skipped (absent)'
		return 0
	fi
	cur=$(cat "$path" 2>/dev/null)
	[ "$cur" = "$want" ] && { rt_note "$key" "$want" 'already'; return 0; }
	if [ "$mode" = raise ]; then
		last_want=$(printf '%s' "$want" | awk '{print $NF}')
		last_cur=$(printf '%s' "$cur" | awk '{print $NF}')
		if rt_int "$last_cur" && rt_int "$last_want" && [ "$last_cur" -gt "$last_want" ]; then
			rt_note "$key" "$cur" 'kept (larger)'
			return 0
		fi
	fi
	rt_save sysctl "$key" "$cur"
	rt_wr "$path" "$want" "$key"
}

# ---------------------------------------------------------------------------
# module / qdisc / congestion control
# ---------------------------------------------------------------------------

rt_mod_loaded() { [ -d "/sys/module/$1" ]; }

rt_try_modprobe() {
	[ "$RT_DRYRUN" = 1 ] && return 0
	rt_mod_loaded "$1" && return 0
	modprobe "$1" 2>/dev/null && return 0
	return 1
}

rt_fq_available() { rt_mod_loaded sch_fq || rt_try_modprobe sch_fq; }

rt_bbr_available() {
	rt_mod_loaded tcp_bbr || rt_try_modprobe tcp_bbr || {
		[ "$RT_DRYRUN" = 1 ] && grep -q bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null
	}
}

rt_apply_cc() {
	local cc avail
	avail=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null)
	cc=$(cat /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null)
	case " $avail " in
	*' bbr '*) ;;
	*) rt_note tcp_congestion_control "have=$cc" 'skipped (no bbr)'; return 0 ;;
	esac
	[ "$cc" = bbr ] && { rt_note tcp_congestion_control bbr already; return 0; }
	rt_sysctl_set net.ipv4.tcp_congestion_control bbr
}

rt_apply_default_qdisc() {
	local cur
	cur=$(cat /proc/sys/net/core/default_qdisc 2>/dev/null)
	if ! rt_fq_available; then
		rt_note net.core.default_qdisc "$cur" 'skipped (no sch_fq)'
		return 0
	fi
	[ "$cur" = fq ] && { rt_note net.core.default_qdisc fq already; return 0; }
	rt_save sysctl net.core.default_qdisc "$cur"
	rt_wr /proc/sys/net/core/default_qdisc fq net.core.default_qdisc
}

# ---------------------------------------------------------------------------
# per-interface
# ---------------------------------------------------------------------------

rt_ring_parse() {
	# rt_ring_parse <dev> -> "cur_rx cur_tx max_rx max_tx", fields may be empty.
	# ethtool -g prints two blocks; only the second one is what we are running.
	ethtool -g "$1" 2>/dev/null | awk '
		/^Pre-set maximums:/          { sect = "max"; next }
		/^Current hardware settings:/ { sect = "cur"; next }
		/^RX:/ { if (sect == "max") maxrx = $2; else if (sect == "cur") currx = $2 }
		/^TX:/ { if (sect == "max") maxtx = $2; else if (sect == "cur") curtx = $2 }
		END    { print currx, curtx, maxrx, maxtx }'
}

rt_iface_rings() {
	local dev="$1" v cur_rx cur_tx max_rx max_tx
	v=$(rt_ring_parse "$dev")
	cur_rx=$(printf '%s' "$v" | awk '{print $1}')
	cur_tx=$(printf '%s' "$v" | awk '{print $2}')
	max_rx=$(printf '%s' "$v" | awk '{print $3}')
	max_tx=$(printf '%s' "$v" | awk '{print $4}')
	rt_int "$max_rx" || { rt_note "$dev rings" - 'skipped (no ethtool -g)'; return 0; }
	rt_int "$max_tx" || max_tx=$max_rx
	if rt_int "$cur_rx" && [ "$cur_rx" -ge "$max_rx" ]; then
		rt_note "$dev rings" "rx=$cur_rx tx=$cur_tx" already
		return 0
	fi
	rt_save ring "$dev" "rx=$cur_rx tx=$cur_tx"
	rt_cmd "$dev rings" ethtool -G "$dev" rx "$max_rx" tx "$max_tx"
}

rt_iface_offloads() {
	local dev="$1"
	ethtool -k "$dev" >/dev/null 2>&1 || {
		rt_note "$dev offloads" - 'skipped (no ethtool -k)'
		return 0
	}
	# Only ever turn things ON, and only those that help a forwarding box.
	# LRO is deliberately left alone: coalescing receives into >MTU segments
	# upsets the forwarding path.
	ethtool -k "$dev" 2>/dev/null | grep -qE '^generic-receive-offload: off' &&
		rt_cmd "$dev gro" ethtool -K "$dev" gro on
	ethtool -k "$dev" 2>/dev/null | grep -qE '^generic-segmentation-offload: off' &&
		rt_cmd "$dev gso" ethtool -K "$dev" gso on
	ethtool -k "$dev" 2>/dev/null | grep -qE '^tcp-segmentation-offload: off' &&
		rt_cmd "$dev tso" ethtool -K "$dev" tso on
	ethtool -k "$dev" 2>/dev/null | grep -qE '^large-receive-offload: on' &&
		rt_note "$dev lro" on 'left alone (forwarding)'
	return 0
}

rt_iface_coalesce() {
	local dev="$1" cur adaptive
	rt_is_virt && { rt_note "$dev coalesce" - 'skipped (guest)'; return 0; }
	cur=$(ethtool -c "$dev" 2>/dev/null) || {
		rt_note "$dev coalesce" - 'skipped (no ethtool -c)'
		return 0
	}
	adaptive=$(printf '%s' "$cur" | awk '/adaptive-rx/{print $2; exit}')
	[ "$adaptive" = on ] && { rt_note "$dev coalesce" adaptive 'left alone (driver adaptive)'; return 0; }
	case "$RT_TIER" in
	conservative)
		rt_note "$dev coalesce" - 'skipped (conservative tier)'
		return 0
		;;
	esac
	printf '%s' "$cur" | grep -qE 'rx-usecs' || {
		rt_note "$dev coalesce" - 'skipped (no rx-usecs)'
		return 0
	}
	# Mode decides the trade-off (see router_tuning.config). tx-usecs is set
	# too when the driver exposes it; a NIC that only knows rx-usecs simply
	# gets the rx half.
	local want
	case "$RT_MODE" in
	throughput)	want=32 ;;
	latency)	want=0 ;;
	*)		want=16 ;;
	esac
	if printf '%s' "$cur" | grep -qE 'tx-usecs'; then
		rt_cmd "$dev coalesce" ethtool -C "$dev" rx-usecs "$want" tx-usecs "$want"
	else
		rt_cmd "$dev coalesce" ethtool -C "$dev" rx-usecs "$want"
	fi
}

rt_iface_txqlen() {
	local dev="$1" cur want
	case "$RT_MODE" in
	throughput)	want=5000 ;;
	latency)	want=500 ;;
	*)		want=2000 ;;
	esac
	cur=$(ip -o link show dev "$dev" 2>/dev/null | sed -n 's/.*qlen \([0-9]*\).*/\1/p' | head -1)
	rt_int "$cur" || return 0
	[ "$cur" -ge "$want" ] && { rt_note "$dev txqueuelen" "$cur" already; return 0; }
	rt_save txqlen "$dev" "$cur"
	rt_cmd "$dev txqueuelen" ip link set dev "$dev" txqueuelen "$want"
}

rt_iface_xps() {
	# Upstream packet_steering writes rps_cpus and the IRQ affinity, but it
	# does not touch xps_cpus. With more than one TX queue, pinning each queue
	# to its own CPU round-robin is the part nobody else does.
	local dev="$1" txq i idx id ncpu ids mask
	ids=$(rt_cpu_ids | tr '\n' ' ')
	ncpu=$(rt_ncpu)
	rt_int "$ncpu" && [ "$ncpu" -gt 0 ] || return 0
	txq=$(ls -d /sys/class/net/"$dev"/queues/tx-* 2>/dev/null | wc -l)
	rt_int "$txq" || return 0
	[ "$txq" -gt 1 ] || { rt_note "$dev xps" "txq=$txq" 'skipped (single queue)'; return 0; }
	i=0
	while [ "$i" -lt "$txq" ]; do
		idx=$((i % ncpu))
		id=$(printf '%s\n' $ids | awk -v n="$idx" 'NR == n + 1 { print; exit }')
		if [ -n "$id" ]; then
			mask=$(rt_hexmask "$id")
			rt_wr "/sys/class/net/$dev/queues/tx-$i/xps_cpus" "$mask" "$dev xps tx-$i"
		fi
		i=$((i + 1))
	done
}

rt_iface_rps_fallback() {
	# Only when the upstream service is provably absent AND every rps_cpus is
	# still zero. Otherwise this is someone else's job.
	local dev="$1" q mask all=1
	[ -e /etc/rc.d/S25packet_steering ] && {
		rt_note "$dev rps" - 'upstream packet_steering owns it'
		return 0
	}
	for q in /sys/class/net/"$dev"/queues/rx-*/rps_cpus; do
		[ -e "$q" ] || continue
		[ "$(cat "$q" 2>/dev/null)" != 0 ] && all=0
	done
	[ "$all" = 1 ] || { rt_note "$dev rps" - 'already steered'; return 0; }
	mask=$(rt_hexmask $(rt_cpu_ids))
	for q in /sys/class/net/"$dev"/queues/rx-*/rps_cpus; do
		[ -e "$q" ] || continue
		rt_wr "$q" "$mask" "$dev $(basename "$(dirname "$q")") rps"
	done
}

rt_iface_apply() {
	local dev="$1"
	[ -n "$dev" ] || return 0
	[ -e /sys/class/net/"$dev" ] || return 0
	rt_note "$dev" - '---'
	[ "$RT_NIC" = 1 ] && rt_iface_rings "$dev"
	[ "$RT_NIC" = 1 ] && rt_iface_offloads "$dev"
	[ "$RT_NIC" = 1 ] && rt_iface_coalesce "$dev"
	[ "$RT_NIC" = 1 ] && rt_iface_txqlen "$dev"
	[ "$RT_XPS" = 1 ] && rt_iface_xps "$dev"
	[ "$RT_RPS_FALLBACK" = 1 ] && rt_iface_rps_fallback "$dev"
	return 0
}

# ---------------------------------------------------------------------------
# cpu
# ---------------------------------------------------------------------------

rt_apply_governor() {
	local pol avail
	[ "$RT_GOVERNOR" = 1 ] || return 0
	for pol in /sys/devices/system/cpu/cpufreq/policy*; do
		[ -d "$pol" ] || continue
		avail=$(cat "$pol/scaling_available_governors" 2>/dev/null)
		case " $avail " in
		*' performance '*) ;;
		*)
			rt_note "$(basename "$pol") governor" "have=$avail" 'skipped'
			continue
			;;
		esac
		[ "$(cat "$pol/scaling_governor" 2>/dev/null)" = performance ] && {
			rt_note "$(basename "$pol") governor" performance already
			continue
		}
		rt_save governor "$pol/scaling_governor" "$(cat "$pol/scaling_governor" 2>/dev/null)"
		rt_wr "$pol/scaling_governor" performance "$(basename "$pol") governor"
	done
	return 0
}

# ---------------------------------------------------------------------------
# entry points
# ---------------------------------------------------------------------------

rt_apply_all() {
	local dev
	[ "$RT_FQ" = 1 ] && rt_apply_default_qdisc
	[ "$RT_BBR" = 1 ] && rt_apply_cc
	[ "$RT_SYSCTL" = 1 ] && {
		rt_sysctl_set net.core.netdev_max_backlog "$RT_BACKLOG" raise
		rt_sysctl_set net.core.netdev_budget "$RT_BUDGET"
		rt_sysctl_set net.core.somaxconn "$RT_SOMAXCONN"
		rt_sysctl_set net.core.rmem_max "$RT_RMEM" raise
		rt_sysctl_set net.core.wmem_max "$RT_WMEM" raise
		rt_sysctl_set net.ipv4.tcp_rmem "$RT_TCP_R" raise
		rt_sysctl_set net.ipv4.tcp_wmem "$RT_TCP_W" raise
		rt_sysctl_set net.ipv4.tcp_slow_start_after_idle 0
		rt_sysctl_set net.ipv4.tcp_mtu_probing 1
		rt_sysctl_set net.ipv4.tcp_notsent_lowat 131072
		rt_sysctl_set net.ipv4.tcp_fastopen 3
		rt_sysctl_set net.ipv4.tcp_tw_reuse 1
		rt_sysctl_set net.ipv4.ip_local_port_range '10240 65535'
		rt_sysctl_set net.ipv4.udp_rmem_min "$RT_UDPMIN"
		rt_sysctl_set net.ipv4.udp_wmem_min "$RT_UDPMIN"
	}
	for dev in $RT_IFACES; do
		rt_iface_apply "$dev"
	done
	rt_apply_governor
	return 0
}

rt_tier_values() {
	# Fill the RT_* knobs for the resolved tier, so apply and the generated
	# file can never disagree.
	case "$RT_TIER" in
	conservative)
		RT_RMEM=4194304; RT_WMEM=4194304
		RT_TCP_R='4096 65536 2097152'; RT_TCP_W='4096 65536 2097152'
		RT_BACKLOG=2048; RT_BUDGET=300; RT_SOMAXCONN=1024; RT_UDPMIN=16384
		;;
	aggressive)
		RT_RMEM=16777216; RT_WMEM=16777216
		RT_TCP_R='4096 262144 16777216'; RT_TCP_W='4096 262144 16777216'
		RT_BACKLOG=8192; RT_BUDGET=900; RT_SOMAXCONN=8192; RT_UDPMIN=65536
		;;
	*)
		RT_RMEM=8388608; RT_WMEM=8388608
		RT_TCP_R='4096 131072 8388608'; RT_TCP_W='4096 131072 8388608'
		RT_BACKLOG=4096; RT_BUDGET=600; RT_SOMAXCONN=4096; RT_UDPMIN=32768
		;;
	esac
}

rt_config() {
	config_load router_tuning
	config_get_bool RT_ENABLED global enabled 0
	config_get RT_PROFILE global profile auto
	config_get_bool RT_SYSCTL global sysctl 1
	config_get_bool RT_BBR global bbr 1
	config_get_bool RT_FQ global fq 1
	config_get_bool RT_NIC global nic 1
	config_get_bool RT_XPS global xps 1
	config_get_bool RT_RPS_FALLBACK global rps_fallback 1
	config_get_bool RT_GOVERNOR global governor 1
	config_get RT_LIST global interfaces ''
	config_get RT_MODE global mode balanced
	case "$RT_MODE" in
	throughput|balanced|latency) ;;
	*) RT_MODE=balanced ;;
	esac
	RT_TIER=$(rt_tier "$RT_PROFILE")
	rt_tier_values
	if [ -n "$RT_LIST" ]; then
		RT_IFACES="$RT_LIST"
	else
		RT_IFACES=$(rt_ifaces)
	fi
}

rt_restore() {
	local kind key val
	[ -f "$RT_STATE" ] || { rt_note state - 'nothing recorded'; return 0; }
	RT_DRYRUN=${RT_DRYRUN:-0}
	while IFS='|' read -r kind key val; do
		case "$kind" in
		sysctl)
			rt_wr "/proc/sys/$(printf '%s' "$key" | tr . /)" "$val" "restore $key"
			;;
		governor) rt_wr "$key" "$val" "restore governor" ;;
		txqlen) rt_cmd "restore txqlen $key" ip link set dev "$key" txqueuelen "$val" ;;
		ring)
			# val is "rx=N tx=M"
			rt_cmd "restore ring $key" ethtool -G "$key" \
				rx "$(printf '%s' "$val" | sed -n 's/.*rx=\([0-9]*\).*/\1/p')" \
				tx "$(printf '%s' "$val" | sed -n 's/.*tx=\([0-9]*\).*/\1/p')"
			;;
		esac
	done <"$RT_STATE"
	if [ "$RT_DRYRUN" != 1 ]; then
		mv "$RT_STATE" "$RT_STATE.restored" 2>/dev/null
		rt_note state - 'restored (old values kept in .restored)'
	fi
}
