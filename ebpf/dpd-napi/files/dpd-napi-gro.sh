#!/bin/sh
# Per-device GRO / GSO / TSO / checksum A/B helper.
#
#   dpd-napi-gro --dev eth1 --gro off --gso keep --tso keep
#   dpd-napi-gro --dev eth1 --rx-checksum off --tx-checksum on
#   dpd-napi-gro --dev eth1 --feature sg=off --dry-run
#   dpd-napi-gro                       # record every physical NIC, change nothing
#
# Each feature accepts on|off|keep. "keep" is the default, so the daemon can
# call this script at boot purely to record the state in /var/run/dpd/gro.json.
# --dry-run prints the ethtool commands and still dumps the current features.
#
# The kernel value layout is untouched: this is the standard `ethtool -K`
# interface, and every requested change is attempted individually so one
# unsupported feature does not hide the others.
# jshn.sh reads JSON_PREFIX before assigning it, so set -u breaks the
# JSON writer at runtime (measured on the target). Keep the default options.
PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
LC_ALL=C
export LC_ALL

OUT=/var/run/dpd
JSON=$OUT/gro.json
DEVS=
ALL=0
DRY=0
GRO=keep
GSO=keep
TSO=keep
RXCHK=keep
TXCHK=keep
EXTRA=

usage() {
	cat <<'EOF'
usage: dpd-napi-gro [--dev DEV]... [--all]
                    [--gro on|off|keep] [--gso on|off|keep]
                    [--tso on|off|keep] [--rx-checksum on|off|keep]
                    [--tx-checksum on|off|keep]
                    [--feature NAME=on|off|keep]...
                    [--dry-run] [--json FILE]

  --dev DEV    netdev to handle; repeatable. Default: every device with a
               /sys/class/net/<dev>/device symlink (physical NICs).
  --all        also include virtual devices (bridges, veth, dummy).
  --dry-run    show commands, do not call ethtool -K.
  --feature    any extra ethtool feature name, e.g. sg, rxvlan, txvlan.
  --json FILE  summary path (default /var/run/dpd/gro.json).
EOF
}

bad_value() {
	echo "dpd-napi-gro: bad value '$1' for $2 (want on|off|keep)" >&2
	exit 2
}

check_val() {
	case "$2" in
	on | off | keep) ;;
	*) bad_value "$2" "$1" ;;
	esac
}

while [ $# -gt 0 ]; do
	case "$1" in
	--dev)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		DEVS="$DEVS $2"
		shift 2
		;;
	--all)
		ALL=1
		shift
		;;
	--gro)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		check_val gro "$2"
		GRO=$2
		shift 2
		;;
	--gso)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		check_val gso "$2"
		GSO=$2
		shift 2
		;;
	--tso)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		check_val tso "$2"
		TSO=$2
		shift 2
		;;
	--rx-checksum)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		check_val rx "$2"
		RXCHK=$2
		shift 2
		;;
	--tx-checksum)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		check_val tx "$2"
		TXCHK=$2
		shift 2
		;;
	--feature)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		name=${2%%=*}
		val=${2#*=}
		[ -n "$name" ] && [ "$name" != "$2" ] || {
			echo "dpd-napi-gro: --feature wants NAME=on|off|keep" >&2
			exit 2
		}
		check_val "$name" "$val"
		EXTRA="$EXTRA $name=$val"
		shift 2
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

if [ -z "$DEVS" ]; then
	for d in /sys/class/net/*; do
		[ -d "$d/queues" ] || continue
		name=${d##*/}
		[ "$name" = lo ] && continue
		if [ "$ALL" = 1 ] || [ -e "$d/device" ]; then
			DEVS="$DEVS $name"
		fi
	done
fi

case "$JSON" in
*/*) mkdir -p "${JSON%/*}" 2>/dev/null || true ;;
esac
mkdir -p "$OUT" 2>/dev/null || true

. /usr/share/libubox/jshn.sh

if ! command -v ethtool >/dev/null 2>&1; then
	json_init
	json_add_string error "ethtool not found"
	json_add_boolean dry_run "$DRY"
	json_add_array devices
	json_close_array
	json_dump >"$JSON.tmp" && mv "$JSON.tmp" "$JSON"
	echo "dpd-napi-gro: ethtool not found, nothing to do" >&2
	exit 0
fi

# ethtool -k prints "feature: on [fixed]"; strip the bracket note.
read_features() {
	ethtool -k "$1" 2>/dev/null | awk -F':[ \t]*' '
		NF >= 2 {
			k = $1
			v = $2
			# ethtool indents sub-features ("\ttx-checksum-ipv4");
			# keep the JSON keys free of that leading whitespace.
			sub(/^[ \t]+/, "", k)
			sub(/[ \t].*/, "", v)
			if (k != "" && v != "")
				print k "|" v
		}'
}

apply_one() {
	# dev, ethtool feature, value -> status word on stdout
	[ "$3" = keep ] && { echo keep; return 0; }
	if [ "$DRY" = 1 ]; then
		echo "would run: ethtool -K $1 $2 $3" >&2
		echo dry-run
		return 0
	fi
	if ethtool -K "$1" "$2" "$3" >/dev/null 2>&1; then
		echo ok
	else
		echo failed
		echo "dpd-napi-gro: ethtool -K $1 $2 $3 failed" >&2
		return 1
	fi
}

REQ="gro:$GRO gso:$GSO tso:$TSO rx:$RXCHK tx:$TXCHK"
for spec in $EXTRA; do
	name=${spec%%=*}
	val=${spec#*=}
	REQ="$REQ $name:$val"
done

FAILED=0
json_init
json_add_boolean dry_run "$DRY"
json_add_array devices
for dev in $DEVS; do
	[ -d "/sys/class/net/$dev" ] || {
		echo "dpd-napi-gro: no such netdev '$dev'" >&2
		continue
	}

	json_add_object
	json_add_string dev "$dev"

	json_add_object requested
	for spec in $REQ; do
		json_add_string "${spec%%:*}" "${spec#*:}"
	done
	json_close_object

	json_add_object applied
	for spec in $REQ; do
		name=${spec%%:*}
		val=${spec#*:}
		st=$(apply_one "$dev" "$name" "$val") || FAILED=1
		json_add_string "$name" "$st"
	done
	json_close_object

	json_add_object features
	FEAT=${TMPDIR:-/tmp}/dpd-gro.$$
	read_features "$dev" >"$FEAT"
	while IFS='|' read -r k v; do
		[ -n "$k" ] && json_add_string "$k" "$v"
	done <"$FEAT"
	rm -f "$FEAT"
	json_close_object

	json_close_object
	suffix=
	[ "$DRY" = 1 ] && suffix=" (dry-run)"
	echo "dpd-napi-gro: $dev state recorded$suffix" >&2
done
json_close_array
json_dump >"$JSON.tmp" && mv "$JSON.tmp" "$JSON"

exit "$FAILED"
