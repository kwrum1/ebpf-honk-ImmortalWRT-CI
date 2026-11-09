#!/bin/sh
# Apply DPD NAPI/queue settings.
#   - sysfs/sysctl for the device-wide knobs (netdev_budget, dev_weight,
#     RPS/XPS, and the legacy per-device gro_flush_timeout/defer_hard_irqs);
#   - netdev generic netlink for the real per-NAPI instances (kernel >= 6.10):
#     gro_flush_timeout, defer_hard_irqs, irq_suspend_timeout, threaded.
# The genl path is optional: without the helper or the family, the sysfs path
# still runs and napi.json says so.
. /lib/functions.sh
. /usr/share/libubox/jshn.sh

OUT=/var/run/dpd
mkdir -p "$OUT"

config_load dpd_napi
config_get_bool enabled main enabled 0
[ "$enabled" = 1 ] || exit 0

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

write_sysctl() {
	[ -w "$1" ] || return 0
	printf '%s\n' "$2" > "$1" 2>/dev/null || return 0
}

write_sysctl /proc/sys/net/core/netdev_budget "$netdev_budget"
write_sysctl /proc/sys/net/core/netdev_budget_usecs "$netdev_budget_usecs"
write_sysctl /proc/sys/net/core/dev_weight "$dev_weight"

NETDEV=/usr/sbin/dpd-napi-netdev
genl=0
if [ "$netdev_genl" = 1 ] && [ -x "$NETDEV" ]; then
	if "$NETDEV" list >/dev/null 2>&1; then
		genl=1
	else
		logger -t dpd-napi "netdev family unavailable, sysfs only"
	fi
fi

devices=""
for d in /sys/class/net/*; do
	[ -d "$d/queues" ] || continue
	name=${d##*/}
	[ "$name" = lo ] && continue
	devices="$devices $name"

	[ -w "$d/gro_flush_timeout" ] && printf '%s\n' "$gro_flush_timeout" > "$d/gro_flush_timeout" 2>/dev/null
	[ -w "$d/napi_defer_hard_irqs" ] && printf '%s\n' "$napi_defer_hard_irqs" > "$d/napi_defer_hard_irqs" 2>/dev/null

	if [ "$genl" = 1 ]; then
		set -- gro_flush_timeout "$gro_flush_timeout" \
			defer_hard_irqs "$napi_defer_hard_irqs"
		[ -n "$irq_suspend_timeout" ] && set -- "$@" irq_suspend_timeout "$irq_suspend_timeout"
		[ -n "$threaded" ] && set -- "$@" threaded "$threaded"
		"$NETDEV" set "$name" "$@" 2>/dev/null
	fi

	if [ -n "$rps_cpus" ]; then
		for q in "$d"/queues/rx-*/rps_cpus; do
			[ -w "$q" ] && printf '%s\n' "$rps_cpus" > "$q" 2>/dev/null
		done
	fi
	if [ -n "$xps_cpus" ]; then
		for q in "$d"/queues/tx-*/xps_cpus; do
			[ -w "$q" ] && printf '%s\n' "$xps_cpus" > "$q" 2>/dev/null
		done
	fi
done

json_init
json_add_boolean enabled "$enabled"
json_add_int netdev_budget "$netdev_budget"
json_add_int netdev_budget_usecs "$netdev_budget_usecs"
json_add_int dev_weight "$dev_weight"
json_add_int gro_flush_timeout "$gro_flush_timeout"
json_add_int napi_defer_hard_irqs "$napi_defer_hard_irqs"
json_add_string irq_suspend_timeout "$irq_suspend_timeout"
json_add_string threaded "$threaded"
json_add_boolean netdev_genl "$genl"
json_add_string rps_cpus "$rps_cpus"
json_add_string xps_cpus "$xps_cpus"
json_add_string devices "$devices"
json_dump > "$OUT/napi.json.tmp" && mv "$OUT/napi.json.tmp" "$OUT/napi.json"

while true; do sleep 3600; done
