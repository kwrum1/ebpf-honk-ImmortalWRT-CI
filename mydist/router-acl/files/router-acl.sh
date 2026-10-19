#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# router-acl.sh - shared helpers for the router-acl WAN filter.
#
# Sourced by:
#   /etc/init.d/router-acl
#   /etc/hotplug.d/iface/91-router-acl
#
# Contract with einat and dpd (see src/acl_common.h):
#   * einat owns the TCX links and does the NAT. We neither do NAT nor read its
#     maps; the ACL learns by watching the WAN egress direction itself.
#   * dpd owns pref 100. We take pref 90 so a packet we drop never reaches the
#     fastpath.
#   * unlike dpd we need the *egress* hook too, so the device must have a
#     clsact qdisc. A plain `ingress` qdisc cannot carry an egress filter and
#     cannot be upgraded in place, so that case is reported instead of being
#     silently worked around.
#
# The BYPASS mode nft snippets are generated here, not shipped as static files:
# they embed the LAN device name and the mark value, and they must be removed
# again the moment the service stops. Leaving a `notrack` behind after the ACL
# is gone would break NAT, so removal is unconditional in stop_service().

ACL_OBJ_IN=/lib/bpf/acl_ingress.bpf.o
ACL_OBJ_OUT=/lib/bpf/acl_egress.bpf.o
ACL_SEC=classifier
ACL_PREF=90
ACL_CTL=/usr/sbin/aclctl
# must match ACL_MAX_LAN_V4 in src/acl_common.h
ACL_MAX_LAN_V4=4

# fw4 auto-include positions. chain-post/raw_prerouting runs after fw4's own
# notrack rules but still in the raw hook, i.e. before conntrack. chain-pre/
# forward runs before the first rule of the forward chain, which is what lets us
# accept a marked reply before fw4's policy drop.
ACL_NFT_RAW=/usr/share/nftables.d/chain-post/raw_prerouting/10-router-acl.nft
ACL_NFT_FWD=/usr/share/nftables.d/chain-pre/forward/10-router-acl.nft
ACL_NFT_STAMP=/tmp/.router-acl-nft

acl_log() {	logger -t router-acl "$*" 2>/dev/null || true
}

# The prefixes fullcone matches against. Read from the live interface rather
# than from uci: what matters is what the kernel actually routes locally.
acl_lan_prefixes() {
	local dev="$1" out=""

	[ -n "$dev" ] || return 0
	out="$(ip -4 -o addr show dev "$dev" scope global 2>/dev/null |
		awk '{print $4}' | head -"${ACL_MAX_LAN_V4:-4}")"
	printf '%s' "$out"
}

acl_bpffs_ensure() {
	mount 2>/dev/null | grep -qE ' on /sys/fs/bpf type bpf' && return 0
	mkdir -p /sys/fs/bpf
	mount -t bpf bpf /sys/fs/bpf 2>/dev/null && return 0
	return 1
}

# clsact is mandatory (egress hook). Never replace a qdisc that is already
# there: honk may own it and einat's TCX links do not need one at all.
acl_qdisc_ready() {
	local dev="$1"

	tc qdisc show dev "$dev" 2>/dev/null | grep -qE '(^| )clsact( |$)' && return 0
	if tc qdisc show dev "$dev" 2>/dev/null | grep -qE '(^| )ingress( |$)'; then
		acl_log "$dev has a plain ingress qdisc; cannot add egress filters"
		return 1
	fi
	tc qdisc add dev "$dev" clsact 2>/dev/null && return 0
	return 1
}

acl_attach_if() {
	local dev="$1"

	[ -n "$dev" ] || return 1
	[ -e "/sys/class/net/$dev" ] || { acl_log "no such device: $dev"; return 1; }
	[ -f "$ACL_OBJ_IN" ] || { acl_log "missing $ACL_OBJ_IN"; return 1; }
	[ -f "$ACL_OBJ_OUT" ] || { acl_log "missing $ACL_OBJ_OUT"; return 1; }
	acl_bpffs_ensure || acl_log "warning: /sys/fs/bpf is not a bpffs"
	acl_qdisc_ready "$dev" || return 1

	# replace, do not stack
	tc filter del dev "$dev" ingress pref "$ACL_PREF" 2>/dev/null
	if ! tc filter add dev "$dev" ingress pref "$ACL_PREF" handle "$ACL_PREF" \
		bpf da obj "$ACL_OBJ_IN" sec "$ACL_SEC"; then
		acl_log "tc filter add ingress failed on $dev"
		return 1
	fi
	tc filter del dev "$dev" egress pref "$ACL_PREF" 2>/dev/null
	if ! tc filter add dev "$dev" egress pref "$ACL_PREF" handle "$ACL_PREF" \
		bpf da obj "$ACL_OBJ_OUT" sec "$ACL_SEC"; then
		acl_log "tc filter add egress failed on $dev"
		tc filter del dev "$dev" ingress pref "$ACL_PREF" 2>/dev/null
		return 1
	fi
	return 0
}

acl_detach_if() {
	local dev="$1"

	[ -e "/sys/class/net/$dev" ] || return 0
	tc filter del dev "$dev" ingress pref "$ACL_PREF" 2>/dev/null
	tc filter del dev "$dev" egress pref "$ACL_PREF" 2>/dev/null
	return 0
}

acl_is_attached() {
	tc filter show dev "$1" ingress pref "$ACL_PREF" 2>/dev/null | grep -q bpf &&
		tc filter show dev "$1" egress pref "$ACL_PREF" 2>/dev/null | grep -q bpf
}

acl_find_device() {
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

# accept a netifd logical name or a bare device name
acl_resolve_dev() {
	local want="$1" dev=""

	[ -n "$want" ] || return 1
	[ -e "/sys/class/net/$want" ] && { echo "$want"; return 0; }
	. /lib/functions/network.sh
	network_get_device dev "$want" 2>/dev/null
	[ -n "$dev" ] || dev="$(acl_find_device "$want")"
	[ -n "$dev" ] && { echo "$dev"; return 0; }
	return 1
}

acl_attach_logical() {
	local logical="$1" dev

	dev="$(acl_resolve_dev "$logical")"
	if [ -z "$dev" ]; then
		acl_log "iface '$logical' has no device yet; hotplug will retry on ifup"
		return 1
	fi
	acl_attach_if "$dev"
}

# ------------------------------------------------------------------ nft side

# dports that fw4 has a DNAT port forward on, for one protocol. These must NOT be
# notracked on the way out: fw4's DNAT needs conntrack to do the reverse SNAT on
# the reply, and a notracked reply would leave the LAN still carrying its private
# source address. Read-only, /etc/config/firewall is never written.
acl_pf_ports() {
	local want="$1"

	[ -f /etc/config/firewall ] || return 0
	(
		config_load firewall
		config_foreach acl_pf_redirect redirect "$want"
	) 2>/dev/null
}

acl_pf_redirect() {
	local cfg="$1" want="$2" enabled proto dport

	config_get_bool enabled "$cfg" enabled 1
	[ "$enabled" = "1" ] || return 0
	config_get proto "$cfg" proto
	config_get dport "$cfg" src_dport
	[ -n "$dport" ] || config_get dport "$cfg" dest_port
	[ -n "$dport" ] || return 0
	case "$want:$proto" in
	tcp:tcp|tcp:tcpudp|udp:udp|udp:tcpudp) echo "$dport" ;;
	esac
}

# Write (mode=bypass) or remove the fw4 includes. Content is compared before
# anything is reloaded, so a plain restart or a repeat ifup is cheap and a
# changed LAN device name is still picked up.
acl_nft_apply() {
	local mode="$1" lan="$2" mark="$3" mask="$4"
	local tmp_raw=/tmp/.router-acl-raw.$$ tmp_fwd=/tmp/.router-acl-fwd.$$
	local changed=0

	if [ "$mode" != "bypass" ]; then
		if [ -e "$ACL_NFT_RAW" ] || [ -e "$ACL_NFT_FWD" ]; then
			rm -f "$ACL_NFT_RAW" "$ACL_NFT_FWD"
			acl_log "removed fw4 includes, reloading firewall"
			fw4 -q reload 2>/dev/null
		fi
		return 0
	fi

	{
		echo "# generated by /etc/init.d/router-acl - do not edit"
		if [ -n "$lan" ]; then
			local ptcp pudp
			ptcp="$(acl_pf_ports tcp)"
			pudp="$(acl_pf_ports udp)"
			if [ -z "$ptcp" ] && [ -z "$pudp" ]; then
				# nothing forwarded: every LAN->WAN flow can be
				# taken out of conntrack
				echo "iifname \"$lan\" notrack"
			else
				# shellcheck disable=SC2086
				[ -n "$ptcp" ] && echo "iifname \"$lan\" tcp dport != { $(echo $ptcp | tr ' ' ',') } notrack"
				# shellcheck disable=SC2086
				[ -n "$pudp" ] && echo "iifname \"$lan\" udp dport != { $(echo $pudp | tr ' ' ',') } notrack"
				echo "iifname \"$lan\" meta l4proto != tcp meta l4proto != udp notrack"
			fi
		fi
		echo "meta mark & 0x$mask == 0x$mark notrack"
	} > "$tmp_raw"
	{
		echo "# generated by /etc/init.d/router-acl - do not edit"
		echo "meta mark & 0x$mask == 0x$mark accept"
	} > "$tmp_fwd"

	mkdir -p "$(dirname "$ACL_NFT_RAW")" "$(dirname "$ACL_NFT_FWD")"
	cmp -s "$tmp_raw" "$ACL_NFT_RAW" || changed=1
	cmp -s "$tmp_fwd" "$ACL_NFT_FWD" || changed=1

	if [ "$changed" = 0 ]; then
		rm -f "$tmp_raw" "$tmp_fwd"
		return 0
	fi

	mv "$tmp_raw" "$ACL_NFT_RAW"
	mv "$tmp_fwd" "$ACL_NFT_FWD"
	acl_log "installed fw4 includes, reloading firewall"
	fw4 -q reload 2>/dev/null
	return 0
}

# ------------------------------------------------------------------ map side

acl_port_spec() {
	# "6:tcp/8080" -> family proto port ; returns 1 if unparseable
	local spec="$1" family=4 rest proto port

	case "$spec" in
	6:*|ipv6:*)
		family=6
		rest="${spec#*:}"
		;;
	4:*|ipv4:*)
		family=4
		rest="${spec#*:}"
		;;
	*) rest="$spec" ;;
	esac

	case "$rest" in
	*/*) proto="${rest%%/*}"; port="${rest#*/}" ;;
	*)   proto="$rest"; port=0 ;;
	esac

	[ -n "$proto" ] || return 1
	[ -n "$port" ] || return 1
	printf '%s %s %s' "$family" "$proto" "$port"
	return 0
}

acl_port_add() {
	local scope="$1" spec="$2" out

	out="$(acl_port_spec "$spec")" || return 1
	# shellcheck disable=SC2086
	set -- $out
	"$ACL_CTL" port add "$1" "$2" "$scope" "$3" 2>/dev/null
}

acl_push_ports() {
	local forward_list="$1" input_list="$2" spec

	"$ACL_CTL" port flush 2>/dev/null
	for spec in $forward_list; do
		acl_port_add forward "$spec"
	done
	for spec in $input_list; do
		acl_port_add input "$spec"
	done

	# Built-ins, not configurable: the router is a DHCP/DHCPv6 client and the
	# replies are unsolicited by nature. If the lease was acquired before the
	# program was attached the mapping table is empty, and without these the
	# first renew would be dropped.
	"$ACL_CTL" port add 4 udp input 68 2>/dev/null
	"$ACL_CTL" port add 6 udp input 546 2>/dev/null
}

# Pull fw4's own DNAT port forwards into the FORWARD list so that switching the
# ACL on does not silently break port forwards that already worked. Read-only:
# /etc/config/firewall is never written.
acl_import_firewall() {
	config_get_bool import global import_firewall 1
	[ "$import" = "1" ] || return 0
	[ -f /etc/config/firewall ] || return 0

	(
		config_load firewall
		config_foreach acl_import_redirect redirect
	) 2>/dev/null
}

acl_import_redirect() {
	local cfg="$1" enabled proto dport

	config_get_bool enabled "$cfg" enabled 1
	[ "$enabled" = "1" ] || return 0
	config_get proto "$cfg" proto
	config_get dport "$cfg" src_dport
	[ -n "$dport" ] || config_get dport "$cfg" dest_port
	[ -n "$proto" ] && [ -n "$dport" ] || return 0

	case "$proto" in
	tcp)	"$ACL_CTL" port add 4 tcp forward "$dport" 2>/dev/null ;;
	udp)	"$ACL_CTL" port add 4 udp forward "$dport" 2>/dev/null ;;
	tcpudp)
		"$ACL_CTL" port add 4 tcp forward "$dport" 2>/dev/null
		"$ACL_CTL" port add 4 udp forward "$dport" 2>/dev/null
		;;
	esac
}

acl_einat_enabled() {
	[ "$(uci -q get einat.config.enabled)" = "1" ]
}

acl_status() {
	local dev any=0

	for dev in /sys/class/net/*; do
		dev="${dev##*/}"
		if acl_is_attached "$dev"; then
			echo "  $dev: attached (ingress+egress pref $ACL_PREF)"
			any=1
		fi
	done
	[ "$any" = 1 ] || echo "  no interface has the program attached"
	echo "--- config ---"
	[ -x "$ACL_CTL" ] && "$ACL_CTL" show
	echo "--- allow list ---"
	[ -x "$ACL_CTL" ] && "$ACL_CTL" port list
	echo "--- counters ---"
	[ -x "$ACL_CTL" ] && "$ACL_CTL" stats
	echo "--- fw4 includes ---"
	[ -e "$ACL_NFT_RAW" ] && sed 's/^/  raw: /' "$ACL_NFT_RAW"
	[ -e "$ACL_NFT_FWD" ] && sed 's/^/  fwd: /' "$ACL_NFT_FWD"
	[ -e "$ACL_NFT_RAW" ] || echo "  none (not in bypass mode)"
}
