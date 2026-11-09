#!/bin/sh
# Bind the NAPI / MSI IRQs of one or more netdevs to a CPU list.
#
#   dpd-napi-irq --cpus 2-3 --dev eth0 --dev eth1
#   dpd-napi-irq --cpus 4
#   dpd-napi-irq --cpus 2-3 --dev eth1 --dry-run
#
# The IRQ list is taken, in this order, from:
#   1. /usr/sbin/dpd-napi-netdev list <dev>   (real NAPI instances, >= 6.10)
#   2. /sys/class/net/<dev>/device/msi_irqs   (the driver's MSI vectors)
#   3. /proc/interrupts descriptors containing "<dev>-" (legacy/INTx)
#
# The only side effect is writing /proc/irq/<irq>/smp_affinity_list. With
# --dry-run the current mask is only recorded. Re-running with the same CPU
# list is harmless.
#
# UCI option: irq_cpus '2-3'  (empty = disabled; the daemon does not call us).
# jshn.sh reads JSON_PREFIX before assigning it, so set -u breaks the
# JSON writer at runtime (measured on the target). Keep the default options.
PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
LC_ALL=C
export LC_ALL

OUT=/var/run/dpd
JSON=$OUT/irq.json
CPUS=
DEVS=
DRY=0
ALL=0
NETDEV=/usr/sbin/dpd-napi-netdev

usage() {
	cat <<'EOF'
usage: dpd-napi-irq [--cpus LIST] [--dev DEV]... [--all] [--dry-run]
                    [--json FILE]

  --cpus LIST   CPU list for /proc/irq/<irq>/smp_affinity_list
                (for example "2-3" or "4"). Defaults to UCI irq_cpus.
  --dev DEV     netdev to handle; repeatable. Default: every device that has
                a /sys/class/net/<dev>/device symlink (physical NICs).
  --all         also include devices without a device symlink (bridges, veth).
  --dry-run     read and report, do not write the affinity mask.
  --json FILE   summary path (default /var/run/dpd/irq.json).
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--cpus)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		CPUS=$2
		shift 2
		;;
	--dev)
		[ $# -ge 2 ] || { usage >&2; exit 2; }
		DEVS="$DEVS $2"
		shift 2
		;;
	--all)
		ALL=1
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

# Standalone use (and the daemon's explicit call) both fall back to UCI.
if [ -z "$CPUS" ] && command -v uci >/dev/null 2>&1; then
	CPUS=$(uci -q get dpd_napi.main.irq_cpus 2>/dev/null || true)
fi
if [ -z "$CPUS" ]; then
	echo "dpd-napi-irq: irq_cpus is empty, nothing to do" >&2
	exit 0
fi

# Accept only "N" or "N-M" chunks separated by commas.
if ! printf '%s\n' "$CPUS" | awk -F, '
	{
		for (i = 1; i <= NF; i++) {
			if ($i !~ /^[0-9]+(-[0-9]+)?$/)
				exit 1
			n = split($i, r, "-")
			if (n == 2 && r[1] + 0 > r[2] + 0)
				exit 1
		}
	}'; then
	echo "dpd-napi-irq: bad CPU list '$CPUS' (want e.g. 2-3 or 4)" >&2
	exit 2
fi

# Refuse a list that names CPUs the kernel does not have: the write would fail
# anyway, but a clear message is more useful than a partial application.
MAXCPU=$(awk -F'[,-]' 'NF { print $NF }' /sys/devices/system/cpu/online 2>/dev/null || true)
if [ -n "$MAXCPU" ] && [ "$MAXCPU" -gt 0 ] 2>/dev/null; then
	if ! printf '%s\n' "$CPUS" | awk -F, -v max="$MAXCPU" '
		{
			for (i = 1; i <= NF; i++) {
				n = split($i, r, "-")
				if (r[n] + 0 > max)
					exit 1
			}
		}'; then
		echo "dpd-napi-irq: CPU list '$CPUS' exceeds online max $MAXCPU" >&2
		exit 2
	fi
fi

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
if [ -z "$DEVS" ]; then
	echo "dpd-napi-irq: no netdev to handle" >&2
	exit 0
fi

napi_irqs() {
	[ -x "$NETDEV" ] || return 0
	"$NETDEV" list "$1" 2>/dev/null | awk '
		{
			for (i = 1; i <= NF; i++)
				if ($i ~ /^irq=/) {
					sub(/^irq=/, "", $i)
					if ($i + 0 > 0)
						print $i
				}
		}'
}

msi_irqs() {
	f="/sys/class/net/$1/device/msi_irqs"
	[ -r "$f" ] || return 0
	while IFS= read -r irq; do
		case "$irq" in
		'' | *[!0-9]*) continue ;;
		esac
		[ -d "/proc/irq/$irq" ] && printf '%s\n' "$irq"
	done <"$f"
}

proc_irqs() {
	dev=$1
	[ -r /proc/interrupts ] || return 0
	awk -v dev="$dev" '
		$1 ~ /^[0-9]+:$/ {
			# Require the device name at the start of a field so "eth1"
			# does not match "veth1-TxRx-0".
			found = 0
			for (i = 2; i <= NF; i++) {
				if ($i ~ /^[0-9]+$/)
					continue
				if ($i == dev || index($i, dev "-") == 1)
					found = 1
			}
			if (found) {
				irq = $1
				sub(":", "", irq)
				print irq
			}
		}' /proc/interrupts
}

# First source that produces data wins: the netdev family knows the real NAPI
# IRQs; msi_irqs and /proc/interrupts are fallbacks for older kernels/drivers.
collect_irqs() {
	irqs=$(napi_irqs "$1")
	[ -n "$irqs" ] || irqs=$(msi_irqs "$1")
	[ -n "$irqs" ] || irqs=$(proc_irqs "$1")
	printf '%s\n' "$irqs" | awk 'NF' | sort -n -u
}

# Pick the best description for the summary: the source that produced data.
irq_source() {
	dev=$1
	if [ -n "$(napi_irqs "$dev")" ]; then
		echo netdev
	elif [ -n "$(msi_irqs "$dev")" ]; then
		echo msi_irqs
	elif [ -n "$(proc_irqs "$dev")" ]; then
		echo interrupts
	else
		echo none
	fi
}

case "$JSON" in
*/*) mkdir -p "${JSON%/*}" 2>/dev/null || true ;;
esac

. /usr/share/libubox/jshn.sh

FAILED=0
json_init
json_add_string cpus "$CPUS"
json_add_boolean dry_run "$DRY"
json_add_array devices
for dev in $DEVS; do
	[ -d "/sys/class/net/$dev" ] || {
		echo "dpd-napi-irq: no such netdev '$dev'" >&2
		continue
	}
	src=$(irq_source "$dev")
	irqs=$(collect_irqs "$dev")

	json_add_object
	json_add_string dev "$dev"
	json_add_string source "$src"
	json_add_array irqs

	count=0
	for irq in $irqs; do
		[ -d "/proc/irq/$irq" ] || continue
		prev=$(cat "/proc/irq/$irq/smp_affinity_list" 2>/dev/null || true)
		ok=0
		err=""
		if [ "$DRY" = 1 ]; then
			echo "would bind irq $irq ($dev) to $CPUS" >&2
		elif printf '%s\n' "$CPUS" >"/proc/irq/$irq/smp_affinity_list" 2>/dev/null; then
			ok=1
		else
			err="write /proc/irq/$irq/smp_affinity_list failed"
			FAILED=1
			echo "dpd-napi-irq: $err" >&2
		fi

		json_add_object
		json_add_int irq "$irq"
		json_add_string previous "$prev"
		json_add_boolean applied "$ok"
		json_add_string error "$err"
		json_close_object
		count=$((count + 1))
	done

	json_close_array
	if [ "$count" = 0 ]; then
		json_add_string error "no IRQ found (driver without msi_irqs?)"
	fi
	json_close_object

	echo "dpd-napi-irq: $dev source=$src irqs=$count -> $CPUS" >&2
done
json_close_array
json_dump >"$JSON.tmp" && mv "$JSON.tmp" "$JSON"

exit "$FAILED"
