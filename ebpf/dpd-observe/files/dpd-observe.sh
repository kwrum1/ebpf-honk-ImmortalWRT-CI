#!/bin/sh
# Compose the DPD status document once, for ubus/LuCI/scripts.
. /lib/functions.sh

# UCI switch. A disabled daemon stays alive but idle: procd would otherwise
# respawn an exited instance.
config_load dpd_observe
config_get_bool enabled main enabled 1
[ "$enabled" = 1 ] || { while true; do sleep 3600; done; }

OUT=/var/run/dpd
mkdir -p "$OUT"

while true; do
	at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

	dpd=$(/usr/sbin/dpdctl status -j 2>/dev/null)
	[ -n "$dpd" ] || dpd=null

	gate=$(cat /var/run/ebpf/gate.json 2>/dev/null)
	[ -n "$gate" ] || gate=null

	honk=$(cat "$OUT/honk.json" 2>/dev/null)
	[ -n "$honk" ] || honk=null

	napi=$(cat "$OUT/napi.json" 2>/dev/null)
	[ -n "$napi" ] || napi=null

	printf '{"at":"%s","dpd":%s,"gate":%s,"honk":%s,"napi":%s}\n' \
		"$at" "$dpd" "$gate" "$honk" "$napi" > "$OUT/observe.json.tmp" &&
		mv "$OUT/observe.json.tmp" "$OUT/observe.json"
	sleep 5
done
