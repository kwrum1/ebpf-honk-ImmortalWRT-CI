#!/bin/sh
# Apply DPD NAPI/queue settings. Standard sysfs/sysctl only.
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
config_get rps_cpus main rps_cpus ''
config_get xps_cpus main xps_cpus ''

write_sysctl() {
	[ -w "$1" ] || return 0
	printf '%s\n' "$2" > "$1" 2>/dev/null || return 0
}

write_sysctl /proc/sys/net/core/netdev_budget "$netdev_budget"
write_sysctl /proc/sys/net/core/netdev_budget_usecs "$netdev_budget_usecs"
write_sysctl /proc/sys/net/core/dev_weight "$dev_weight"

devices=""
for d in /sys/class/net/*; do
	[ -d "$d/queues" ] || continue
	name=${d##*/}
	[ "$name" = lo ] && continue
	devices="$devices $name"

	[ -w "$d/gro_flush_timeout" ] && printf '%s\n' "$gro_flush_timeout" > "$d/gro_flush_timeout" 2>/dev/null
	[ -w "$d/napi_defer_hard_irqs" ] && printf '%s\n' "$napi_defer_hard_irqs" > "$d/napi_defer_hard_irqs" 2>/dev/null

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
json_add_string rps_cpus "$rps_cpus"
json_add_string xps_cpus "$xps_cpus"
json_add_string devices "$devices"
json_dump > "$OUT/napi.json.tmp" && mv "$OUT/napi.json.tmp" "$OUT/napi.json"

while true; do sleep 3600; done
