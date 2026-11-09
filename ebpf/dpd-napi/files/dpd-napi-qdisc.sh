#!/bin/sh
# qdisc mode gate for DPD: keep / off / cake / hybrid.
#
#   dpd-napi-qdisc --mode off --lan br-lan --wan eth1
#   dpd-napi-qdisc --mode cake --wan eth1 --bandwidth 500mbit
#   dpd-napi-qdisc --mode hybrid --lan br-lan --wan eth1 \
#                  --cake-args "bandwidth 500mbit dual-srchost nat"
#   dpd-napi-qdisc --mode off --dev eth1 --dry-run
#
# Modes:
#   keep    change nothing (default; the daemon only records the state)
#   off     root noqueue, falling back to mq when the driver rejects noqueue
#   cake    root cake with --cake-args / --bandwidth
#   hybrid  LAN noqueue, WAN cake
#
# A root qdisc that this script does not manage (for example fq_codel left by
# SQM) is treated as foreign: without --force the script changes nothing and
# exits 1, so an existing policy is never silently replaced.
#
# UCI: option qdisc_mode 'keep'; option qdisc_cake_args ''.
# jshn.sh reads JSON_PREFIX before assigning it, so set -u breaks the
# JSON writer at runtime (measured on the target). Keep the default options.
PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
LC_ALL=C
export LC_ALL

OUT=/var/run/dpd
JSON=$OUT/qdisc.json
MODE=keep
MODE_GIVEN=0
LAN=
WAN=
DEVS=
CAKE_ARGS=
ARGS_GIVEN=0
BW=
FORCE=0
DRY=0

usage() {
	cat <<'EOF'
usage: dpd-napi-qdisc [--mode keep|off|cake|hybrid]
                      [--lan DEV] [--wan DEV] [--dev DEV]...
                      [--cake-args "ARGS"] [--bandwidth RATE]
                      [--force] [--dry-run] [--json FILE]

  --mode off     root noqueue (or mq when noqueue is unsupported)
  --mode cake    root cake; ARGS are passed to tc after "root cake"
  --mode hybrid  LAN noqueue + WAN cake
  --lan/--wan    devices to use; when omitted they are read from
                 network.lan/network.wan UCI (a PPPoE logical name such as
                 "wan" may need an explicit --wan pppoe-wan)
  --dev          extra device (repeatable); in off/cake mode it replaces the
                 UCI-derived targets
  --bandwidth    convenience for "bandwidth RATE", prepended to --cake-args
  --force        replace a foreign root qdisc (fq_codel, htb, ...)
  --dry-run      print the tc commands, change nothing
  --json FILE    summary path (default /var/run/dpd/qdisc.json)
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--mode)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		MODE=$2
		MODE_GIVEN=1
		shift 2
		;;
	--lan)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		LAN=$2
		shift 2
		;;
	--wan)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		WAN=$2
		shift 2
		;;
	--dev)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		DEVS="$DEVS $2"
		shift 2
		;;
	--cake-args)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		CAKE_ARGS=$2
		ARGS_GIVEN=1
		shift 2
		;;
	--bandwidth)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		BW=$2
		shift 2
		;;
	--force)
		FORCE=1
		shift
		;;
	--dry-run)
		DRY=1
		shift
		;;
	--json)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		JSON=$2
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	-*)
		usage >&2
		exit 2
		;;
	*)
		DEVS="$DEVS $1"
		shift
		;;
	esac
done

case "$MODE" in
keep | off | cake | hybrid) ;;
*)
	echo "dpd-napi-qdisc: bad mode '$MODE'" >&2
	exit 2
	;;
esac

# UCI fallbacks are only read when the matching flag was not supplied.
uci_get() {
	command -v uci >/dev/null 2>&1 || return 0
	uci -q get "$1" 2>/dev/null || true
}

if command -v uci >/dev/null 2>&1; then
	if [ "$MODE_GIVEN" = 0 ]; then
		m=$(uci_get dpd_napi.main.qdisc_mode)
		[ -n "$m" ] && MODE=$m
	fi
	if [ "$ARGS_GIVEN" = 0 ]; then
		a=$(uci_get dpd_napi.main.qdisc_cake_args)
		[ -n "$a" ] && CAKE_ARGS=$a
	fi
	[ -n "$LAN" ] || LAN=$(uci_get network.lan.device)
	[ -n "$LAN" ] || LAN=$(uci_get network.lan.ifname)
	[ -n "$WAN" ] || WAN=$(uci_get network.wan.device)
	[ -n "$WAN" ] || WAN=$(uci_get network.wan.ifname)
fi

# A logical name such as "wan" is not a netdev. Resolve the common PPPoE
# case through ubus, then fall back to pppoe-wan before giving up.
if [ -n "$WAN" ] && [ ! -d "/sys/class/net/$WAN" ]; then
	WAN=
fi
if [ -z "$WAN" ] && command -v ubus >/dev/null 2>&1 && command -v jsonfilter >/dev/null 2>&1; then
	WAN=$(ubus call network.interface.wan status 2>/dev/null |
		jsonfilter -e '@.l3_device' 2>/dev/null || true)
	[ -n "$WAN" ] && [ ! -d "/sys/class/net/$WAN" ] && WAN=
fi
if [ -z "$WAN" ] && [ -d /sys/class/net/pppoe-wan ]; then
	WAN=pppoe-wan
fi

case "$MODE" in
keep | off | cake | hybrid) ;;
*)
	echo "dpd-napi-qdisc: bad UCI qdisc_mode '$MODE'" >&2
	exit 2
	;;
esac

# A logical interface name ("wan") is not a netdev; let add_target drop it
# with a warning instead of silently doing nothing.
[ -n "$LAN" ] || LAN=br-lan

case "$JSON" in
*/*) mkdir -p "${JSON%/*}" 2>/dev/null || true ;;
esac
mkdir -p "$OUT" 2>/dev/null || true

# --bandwidth is sugar for the first cake argument.
if [ -n "$BW" ]; then
	case " $CAKE_ARGS " in
	*" bandwidth "*) ;;
	*) CAKE_ARGS="bandwidth $BW $CAKE_ARGS" ;;
	esac
fi
if [ "$MODE" = cake ] || [ "$MODE" = hybrid ]; then
	[ -n "$CAKE_ARGS" ] || echo "dpd-napi-qdisc: cake without bandwidth (unshaped)" >&2
fi

if ! command -v tc >/dev/null 2>&1; then
	echo "dpd-napi-qdisc: tc not found, nothing to do" >&2
	exit 0
fi

root_qdisc() {
	tc qdisc show dev "$1" 2>/dev/null | awk '
		$1 == "qdisc" {
			for (i = 2; i <= NF; i++)
				if ($i == "root") {
					print $2
					exit
				}
		}'
}

is_foreign() {
	case "$1" in
	'' | noqueue | mq | cake | pfifo_fast) return 1 ;;
	*) return 0 ;;
	esac
}

TARGETS=$OUT/.qdisc.targets.$$
RESULTS=$OUT/.qdisc.results.$$
ERRF=$OUT/.qdisc.err.$$
: >"$TARGETS"
: >"$RESULTS"
SEEN=

add_target() {
	# dev, role (off|cake|keep)
	[ -n "$1" ] || return 0
	if [ ! -d "/sys/class/net/$1" ]; then
		echo "dpd-napi-qdisc: skip '$1': not a netdev (use --wan pppoe-wan?)" >&2
		return 0
	fi
	case " $SEEN " in
	*" $1 "*) return 0 ;;
	esac
	SEEN="$SEEN $1"
	printf '%s|%s\n' "$1" "$2" >>"$TARGETS"
}

case "$MODE" in
keep)
	add_target "$LAN" keep
	add_target "$WAN" keep
	;;
off)
	if [ -n "$DEVS" ]; then
		for d in $DEVS; do add_target "$d" off; done
	else
		add_target "$LAN" off
		add_target "$WAN" off
	fi
	;;
cake)
	if [ -n "$DEVS" ]; then
		for d in $DEVS; do add_target "$d" cake; done
	else
		add_target "$WAN" cake
		[ -n "$WAN" ] || add_target "$LAN" cake
	fi
	;;
hybrid)
	if [ -n "$LAN" ] && [ "$LAN" = "$WAN" ]; then
		echo "dpd-napi-qdisc: hybrid needs distinct --lan and --wan" >&2
		exit 2
	fi
	add_target "$LAN" off
	add_target "$WAN" cake
	for d in $DEVS; do add_target "$d" cake; done
	;;
esac

if [ ! -s "$TARGETS" ]; then
	echo "dpd-napi-qdisc: no usable target device" >&2
	. /usr/share/libubox/jshn.sh
	json_init
	json_add_string mode "$MODE"
	json_add_boolean dry_run "$DRY"
	json_add_boolean force "$FORCE"
	json_add_string cake_args "$CAKE_ARGS"
	json_add_array devices
	json_close_array
	json_dump >"$JSON.tmp" && mv "$JSON.tmp" "$JSON"
	exit 1
fi

# Preflight: never half-configure hybrid when one side has a foreign qdisc.
PREFAIL=0
if [ "$MODE" != keep ] && [ "$FORCE" = 0 ]; then
	while IFS='|' read -r dev role; do
		q=$(root_qdisc "$dev")
		if is_foreign "$q"; then
			echo "dpd-napi-qdisc: refusing $dev: foreign root qdisc '$q' (use --force)" >&2
			printf '%s|%s|%s|%s|0|foreign root qdisc: %s\n' \
				"$dev" "$role" "$q" "refused" "$q" >>"$RESULTS"
			PREFAIL=1
		fi
	done <"$TARGETS"
fi

if [ "$PREFAIL" = 1 ]; then
	:
else
	while IFS='|' read -r dev role; do
		prev=$(root_qdisc "$dev")
		applied=0
		err=""
		case "$role" in
		keep)
			target=$prev
			applied=1
			;;
		off)
			target="noqueue-or-mq"
			if [ "$DRY" = 1 ]; then
				echo "would run: tc qdisc replace dev $dev root noqueue" >&2
			elif tc qdisc replace dev "$dev" root noqueue 2>"$ERRF"; then
				applied=1
			elif tc qdisc replace dev "$dev" root mq 2>>"$ERRF"; then
				applied=1
			else
				err=$(tr '\n|' '  ' <"$ERRF" 2>/dev/null || true)
			fi
			;;
		cake)
			target="cake $CAKE_ARGS"
			if [ "$DRY" = 1 ]; then
				echo "would run: tc qdisc replace dev $dev root cake $CAKE_ARGS" >&2
			elif tc qdisc replace dev "$dev" root cake $CAKE_ARGS 2>"$ERRF"; then
				applied=1
			else
				err=$(tr '\n|' '  ' <"$ERRF" 2>/dev/null || true)
			fi
			;;
		esac
		[ -n "$err" ] && echo "dpd-napi-qdisc: $dev: $err" >&2
		printf '%s|%s|%s|%s|%s|%s\n' \
			"$dev" "$role" "$prev" "$target" "$applied" "$err" >>"$RESULTS"
	done <"$TARGETS"
fi

. /usr/share/libubox/jshn.sh
FAILED=$PREFAIL
json_init
json_add_string mode "$MODE"
json_add_boolean dry_run "$DRY"
json_add_boolean force "$FORCE"
json_add_string cake_args "$CAKE_ARGS"
json_add_array devices
while IFS='|' read -r dev role prev target applied err; do
	if [ "$DRY" = 0 ] && [ "$applied" != 1 ]; then
		FAILED=1
	fi
	json_add_object
	json_add_string dev "$dev"
	json_add_string role "$role"
	json_add_string previous "$prev"
	json_add_string target "$target"
	json_add_boolean applied "$applied"
	json_add_string error "$err"
	json_close_object
done <"$RESULTS"
json_close_array
json_dump >"$JSON.tmp" && mv "$JSON.tmp" "$JSON"

rm -f "$TARGETS" "$RESULTS" "$ERRF"
exit "$FAILED"
