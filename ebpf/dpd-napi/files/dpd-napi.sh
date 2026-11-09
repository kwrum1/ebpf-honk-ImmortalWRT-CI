#!/bin/sh
# Apply DPD NAPI/queue settings, with a low-latency default and an adaptive
# throughput profile.
#
#   mode low          always low latency: gro_flush/defer = 0, budget 300,
#                     dev_weight 64, no RPS/XPS
#   mode throughput   always the UCI values below
#   mode adaptive     start low, switch to throughput after 3 consecutive
#                     10 s samples above 60% CPU, back to low after 6 samples
#                     below 25% (hysteresis; never flaps on a single spike)
#
# The per-NAPI values go through netdev generic netlink (kernel >= 6.10) and
# the legacy per-device sysfs files; the globals go through /proc/sys.
# The profile is published in /var/run/dpd/napi.json.
. /lib/functions.sh
. /usr/share/libubox/jshn.sh

OUT=/var/run/dpd
mkdir -p "$OUT"

config_load dpd_napi
config_get_bool enabled main enabled 0
[ "$enabled" = 1 ] || exit 0
config_get mode main mode adaptive
config_get netdev_budget main netdev_budget 600
config_get netdev_budget_usecs main netdev_budget_usecs 4000
config_get dev_weight main dev_weight 64
config_get gro_flush_timeout main gro_flush_timeout 0
config_get napi_defer_hard_irqs main napi_defer_hard_irqs 0
config_get irq_suspend_timeout main irq_suspend_timeout ''
config_get threaded main threaded ''
config_get_bool netdev_genl main netdev_genl 1
config_get rps_cpus main rps_cpus ''
config_get xps_cpus main xps_cpus ''
config_get irq_cpus main irq_cpus ''
config_get_bool irq_spread main irq_spread 1
config_get busy_poll main busy_poll 0
config_get busy_read main busy_read 0
config_get qdisc_mode main qdisc_mode keep
config_get qdisc_cake_args main qdisc_cake_args ''

# Low-latency profile: fixed, deliberately conservative.
LOW_GRO=0
LOW_DEFER=0
LOW_BUDGET=300
LOW_BUDGET_US=2000
LOW_WEIGHT=64

# Adaptive thresholds (percent of all CPUs, 10 s window).
HIGH_PCT=60
LOW_PCT=25
HIGH_SAMPLES=3
LOW_SAMPLES=6

NETDEV=/usr/sbin/dpd-napi-netdev
genl=0
if [ "$netdev_genl" = 1 ] && [ -x "$NETDEV" ] &&
   "$NETDEV" list >/dev/null 2>&1; then
	genl=1
fi

profile=low
busy=0
switches=0
devices=""

write_sysctl() {
	[ -w "$1" ] || return 0
	printf '%s\n' "$2" > "$1" 2>/dev/null || return 0
}

write_json() {
	json_init
	json_add_boolean enabled 1
	json_add_string mode "$mode"
	json_add_string profile "$profile"
	json_add_int cpu_busy "$busy"
	json_add_int switches "$switches"
	json_add_int netdev_budget "$cur_budget"
	json_add_int netdev_budget_usecs "$cur_budget_us"
	json_add_int dev_weight "$cur_weight"
	json_add_int gro_flush_timeout "$cur_gro"
	json_add_int napi_defer_hard_irqs "$cur_defer"
	json_add_boolean netdev_genl "$genl"
	json_add_string rps_cpus "$cur_rps"
	json_add_string xps_cpus "$cur_xps"
	json_add_string devices "$devices"
	json_add_boolean irq_spread "$irq_spread"
	json_add_string busy_poll "$busy_poll"
	json_add_string busy_read "$busy_read"
	json_dump > "$OUT/napi.json.tmp" && mv "$OUT/napi.json.tmp" "$OUT/napi.json"
}

apply_profile() {
	local p="$1" d name q

	if [ "$p" = low ]; then
		cur_gro=$LOW_GRO
		cur_defer=$LOW_DEFER
		cur_budget=$LOW_BUDGET
		cur_budget_us=$LOW_BUDGET_US
		cur_weight=$LOW_WEIGHT
		cur_rps=0
		cur_xps=0
	else
		cur_gro=$gro_flush_timeout
		cur_defer=$napi_defer_hard_irqs
		cur_budget=$netdev_budget
		cur_budget_us=$netdev_budget_usecs
		cur_weight=$dev_weight
		cur_rps=${rps_cpus:-0}
		cur_xps=${xps_cpus:-0}
	fi

	write_sysctl /proc/sys/net/core/netdev_budget "$cur_budget"
	write_sysctl /proc/sys/net/core/netdev_budget_usecs "$cur_budget_us"
	write_sysctl /proc/sys/net/core/dev_weight "$cur_weight"

	# Report what the kernel actually accepted. Some kernels reject low
	# values of netdev_budget_usecs (EINVAL, e.g. a 20000 us floor), and
	# publishing the requested value would hide that.
	[ -r /proc/sys/net/core/netdev_budget_usecs ] &&
		cur_budget_us=$(cat /proc/sys/net/core/netdev_budget_usecs 2>/dev/null ||
			echo "$cur_budget_us")

	devices=""
	for d in /sys/class/net/*; do
		[ -d "$d/queues" ] || continue
		name=${d##*/}
		[ "$name" = lo ] && continue
		devices="$devices $name"

		[ -w "$d/gro_flush_timeout" ] &&
			printf '%s\n' "$cur_gro" > "$d/gro_flush_timeout" 2>/dev/null
		[ -w "$d/napi_defer_hard_irqs" ] &&
			printf '%s\n' "$cur_defer" > "$d/napi_defer_hard_irqs" 2>/dev/null

		if [ "$genl" = 1 ]; then
			set -- gro_flush_timeout "$cur_gro" \
				defer_hard_irqs "$cur_defer"
			[ -n "$irq_suspend_timeout" ] &&
				set -- "$@" irq_suspend_timeout "$irq_suspend_timeout"
			[ -n "$threaded" ] && set -- "$@" threaded "$threaded"
			"$NETDEV" set "$name" "$@" 2>/dev/null
		fi

		for q in "$d"/queues/rx-*/rps_cpus; do
			[ -w "$q" ] && printf '%s\n' "$cur_rps" > "$q" 2>/dev/null
		done
		for q in "$d"/queues/tx-*/xps_cpus; do
			[ -w "$q" ] && printf '%s\n' "$cur_xps" > "$q" 2>/dev/null
		done
	done
	profile=$p
	write_json
}

# One-shot helpers (qdisc/irq/GRO state); no-op unless configured.
apply_helpers() {
	local devargs=

	[ -n "$devices" ] || return 0
	for d in $devices; do devargs="$devargs --dev $d"; done
	# Socket busy-poll: only sockets that ask for it (SO_BUSY_POLL) are
	# affected; forwarded packets do not use it. Default 0.
	write_sysctl /proc/sys/net/core/busy_poll "$busy_poll"
	write_sysctl /proc/sys/net/core/busy_read "$busy_read"
	if [ -n "$irq_cpus" ] && [ -x /usr/sbin/dpd-napi-irq ]; then
		spread_arg=
		[ "$irq_spread" = 1 ] && spread_arg=--spread
		# shellcheck disable=SC2086
		/usr/sbin/dpd-napi-irq --cpus "$irq_cpus" $spread_arg \
			--json "$OUT/irq.json" $devargs ||
			logger -t dpd-napi "irq affinity failed (irq_cpus=$irq_cpus)"
	fi
	if [ -x /usr/sbin/dpd-napi-gro ]; then
		# shellcheck disable=SC2086
		/usr/sbin/dpd-napi-gro --json "$OUT/gro.json" $devargs ||
			logger -t dpd-napi "gro state dump failed"
	fi
	if [ -x /usr/sbin/dpd-napi-qdisc ]; then
		if [ "$qdisc_mode" = keep ]; then
			/usr/sbin/dpd-napi-qdisc --mode "$qdisc_mode" \
				--cake-args "$qdisc_cake_args" \
				--json "$OUT/qdisc.json" >/dev/null 2>&1 || true
		else
			/usr/sbin/dpd-napi-qdisc --mode "$qdisc_mode" \
				--cake-args "$qdisc_cake_args" \
				--json "$OUT/qdisc.json" ||
				logger -t dpd-napi "qdisc mode '$qdisc_mode' not applied (see $OUT/qdisc.json)"
		fi
	fi
}

# Read /proc/stat's aggregate line as "<total> <idle+iowait>".
read_cpu() {
	awk '/^cpu / { t = 0; for (i = 2; i <= NF; i++) t += $i; print t, $5 + $6; exit }' /proc/stat
}

case "$mode" in
low)
	apply_profile low
	apply_helpers
	while :; do sleep 3600; done
	;;
throughput)
	apply_profile throughput
	apply_helpers
	while :; do sleep 3600; done
	;;
adaptive)
	apply_profile low
	apply_helpers
	set -- $(read_cpu)
	prev_total=${1:-0}
	prev_idle=${2:-0}
	high=0
	lowcnt=0
	while :; do
		sleep 10
		set -- $(read_cpu)
		total=${1:-0}
		idle=${2:-0}
		dt=$((total - prev_total))
		di=$((idle - prev_idle))
		prev_total=$total
		prev_idle=$idle
		if [ "$dt" -gt 0 ]; then
			busy=$(( (dt - di) * 100 / dt ))
		else
			busy=0
		fi
		if [ "$profile" = low ]; then
			if [ "$busy" -ge "$HIGH_PCT" ]; then
				high=$((high + 1))
				[ "$high" -ge "$HIGH_SAMPLES" ] && {
					apply_profile throughput
					switches=$((switches + 1))
					logger -t dpd-napi "adaptive: CPU ${busy}% -> throughput"
					high=0
					lowcnt=0
				}
			else
				high=0
			fi
		else
			if [ "$busy" -le "$LOW_PCT" ]; then
				lowcnt=$((lowcnt + 1))
				[ "$lowcnt" -ge "$LOW_SAMPLES" ] && {
					apply_profile low
					switches=$((switches + 1))
					logger -t dpd-napi "adaptive: CPU ${busy}% -> low latency"
					lowcnt=0
					high=0
				}
			else
				lowcnt=0
			fi
		fi
		write_json
	done
	;;
*)
	logger -t dpd-napi "unknown mode '$mode', using low"
	apply_profile low
	apply_helpers
	while :; do sleep 3600; done
	;;
esac
