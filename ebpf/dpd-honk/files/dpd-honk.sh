#!/bin/sh
# dpd-honk: control-plane bridge between honk and DPD-FW.
#
# It never starts/stops/reconfigures honk. Its only jobs are:
#   * publish honk's health for the DPD UI;
#   * bump the DPD flow-cache epoch when honk's config changes, so flows that
#     were classified before a proxy policy change are re-evaluated.
. /usr/share/libubox/jshn.sh
. /usr/libexec/dpd-fastpath.sh 2>/dev/null || true

OUT=/var/run/dpd
mkdir -p "$OUT"
last_mtime=0

honk_status() {
	local st running version
	st=$(ubus call honk status 2>/dev/null)
	if [ -n "$st" ]; then
		running=$(printf '%s' "$st" | jsonfilter -e '@.running' 2>/dev/null)
		version=$(printf '%s' "$st" | jsonfilter -e '@.core_version' 2>/dev/null)
	fi
	case "$running" in
		true|1) running=1 ;;
		false|0|'') running=0 ;;
	esac
	if [ "$running" != 1 ] && pidof honk-core >/dev/null 2>&1; then running=1; fi
	[ -n "$version" ] || version=$(/usr/bin/honk-core --version 2>/dev/null | head -n1)
	printf '%s\n%s\n' "$running" "$version"
}

while true; do
	status=$(honk_status)
	running=$(printf '%s' "$status" | sed -n '1p')
	version=$(printf '%s' "$status" | sed -n '2p')

	mtime=$(stat -c %Y /etc/honk/config.dae 2>/dev/null || echo 0)
	if [ "$last_mtime" != 0 ] && [ "$mtime" != "$last_mtime" ] && [ "$running" = 1 ]; then
		if command -v dpd_bump_epoch >/dev/null 2>&1; then
			dpd_bump_epoch
		else
			/usr/sbin/dpdctl bump >/dev/null 2>&1 || true
		fi
		logger -t dpd-honk "honk config changed; DPD epoch bumped"
	fi
	last_mtime=$mtime

	json_init
	json_add_boolean running "$running"
	json_add_string version "$version"
	json_add_int config_mtime "$mtime"
	json_dump > "$OUT/honk.json.tmp" && mv "$OUT/honk.json.tmp" "$OUT/honk.json"
	sleep 10
done
