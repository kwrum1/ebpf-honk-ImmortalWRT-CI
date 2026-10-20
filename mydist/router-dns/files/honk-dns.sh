#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# honk-dns.sh -- keep DNS in OUR resolver plane while honk is running.
#
# Why this file has to exist
# -------------------------
# honk takes transparent DNS away from the system while it runs, on purpose:
#   * its shipped policy excludes port 53 from the in-kernel direct path
#     (`dip(geoip: cn) && !dport(53) -> direct(must)`), because its DNS engine
#     wants to see the qname, and
#   * its datapath therefore redirects LAN :53 into its own engine, which
#     answers from its own `dns.upstream` entries.
# So the SmartDNS plane (dnsmasq is not a resolver in this firmware: port 0)
# is bypassed for every LAN client the moment honk starts.
#
# Measured 2026-10-18 in QEMU (x86_64, honk 995a80cd, real node):
#   * a client's by-name fetch failed ("Could not resolve host"), and honk
#     logged, once per query:
#         WARN honk_core::control::dns_control: DNS controller forward failed;
#         sending SERVFAIL ... upstream 'default' failed via 223.5.5.5:443
#     i.e. its stock DoH upstream is not usable from this box at all.
#   * the router's own resolution died too: `nslookup 223.5.5.5` timed out and
#     so did TCP to 223.5.5.5:443 (code=000, connect=0.000000). Unmarked
#     router-local egress is blackholed while honk runs; forwarded client
#     traffic and honk's own marked dials are fine.
#
# The fix is three lines of policy, each doing one job:
#   1. `dport(53) -> direct(must)` as the FIRST routing rule: DNS belongs to the
#      kernel path, so SmartDNS answers LAN clients, and
#      the router's own queries are attributable to a rule and go out normally.
#   2. drop the now-redundant `&& !dport(53)` from the two direct(must) rules, so
#      the file says one thing instead of two contradicting ones.
#   3. `dns.upstream.default` -> `udp://127.0.0.1:53`, so anything honk still
#      resolves itself (its own node/domain dialling) uses smartdns too. Its
#      internal sockets carry honk's own mark and are therefore not caught by
#      honk's datapath, which is why this direction works where a plain client
#      query does not.
#
# Why a patch and not a shipped conffile
# --------------------------------------
# /etc/honk/config.dae is the user's file: the doona UI edits it, and `reset`
# restores the factory copy from /usr/share/honk/default-config.dae. Shipping our
# own copy would either fight the UI or freeze the routing policy, and shipping
# the same path as the doona package makes apk refuse the whole install. So patch
# in place, idempotently, and only while the relevant lines are still the stock
# ones -- an operator who deliberately pointed honk somewhere else keeps it.
#
# Called from /etc/init.d/router-dns (START=18, i.e. well before honk's S95), so
# the patched file is what honk reads when it starts. A factory reset re-creates
# the stock file, and the next boot patches it again.
#
# There is a second half, because the policy alone is not enough: with honk
# running, the router's own UDP never completes (measured: direct and proxied
# both time out, local TCP to the same address answers), so a resolver whose
# upstream is UDP resolves nothing cold. That is why `patch` also calls
# ensure_dot_upstreams() -- DoT rides TCP. See the comment above that function,
# and docs/proxy-accel-coexistence.md §9.
#
# `honk-dns.sh` (patch) and `honk-dns.sh status` are safe to run by hand.

CONF="${HONK_CONF:-/etc/honk/config.dae}"
MARK="# mydist: honk-dns"
SMARTDNS='udp://127.0.0.1:53'
STOCK_DNS="default: *'https://223\\.5\\.5\\.5/dns-query"
RULE='dport(53) -> direct(must)'

log() { logger -t router-dns "$*"; }

# Is this a file we are willing to edit at all?
#
# It used to refuse anything that was no longer stock (marker present, or a bare
# :53 rule already there). That made the handover "apply once, then silently
# never again": the doona UI can rewrite config.dae, and a box whose DNS policy
# half-applied resolves nothing. DNS is this firmware's plane, so the handover is
# ENFORCED at every boot: patch() removes its own previous lines first, which
# makes it idempotent without having to trust the file's current shape.
usable() {
	[ -f "$CONF" ] || return 1
	[ ! -L "$CONF" ] || return 1
	# Already ours: nothing to do (patch() would be idempotent, but skipping here
	# keeps the boot log quiet).
	grep -qF "$MARK" "$CONF" && return 1
	# BRE, on purpose: in ERE a bare `{` may be an interval operator, and the
	# first version of this check matched nothing and refused every patch.
	grep -q '^[[:space:]]*routing[[:space:]]*{' "$CONF" || return 1
	return 0
}

patch() {
	# The UI can rewrite config.dae (it is the user's file). If our rule is gone
	# and we kept the stock copy from the first boot, start from that copy again --
	# the handover is the firmware's DNS plane, not a one-shot suggestion.
	if [ -f "$CONF" ] && ! grep -qF "$RULE" "$CONF" 2>/dev/null && [ -f "$CONF.mydist.bak" ]; then
		cp -f "$CONF.mydist.bak" "$CONF" 2>/dev/null &&
			log "config.dae had been rewritten without the DNS handover; restored the backup and re-applying"
	fi
	usable || return 0
	cp -p "$CONF" "$CONF.mydist.bak" 2>/dev/null

	# 1. our own lines are removed first: that is what makes the handover
	#    idempotent even after the UI rewrote the file, and it also means a :53
	#    rule that drifted out of the first position is re-inserted at the top.
	# 2. the two `&& !dport(53)` clauses are contradicted by rule 1.
	# 3. the :53 rule itself, right after the top-level `routing {`.
	awk -v m="$MARK" -v r="$RULE" '
		$0 ~ "^[[:space:]]*" r "[[:space:]]*$" { next }
		$0 ~ "^[[:space:]]*" m "[[:space:]]*$" { next }
		{ gsub(/ && !dport\(53\)/, ""); print }
		!done && $0 ~ /^routing[[:space:]]*\{/ {
			print "    " m
			print "    " r
			done = 1
		}
	' "$CONF" >"$CONF.new" || { rm -f "$CONF.new"; return 1; }
	# 4. honk's own resolution goes through smartdns as well (only the stock DoH
	#    line is rewritten; an operator's own upstream is left alone).
	sed -i "s|^\([[:space:]]*\)$STOCK_DNS[^']*'|\1default: '$SMARTDNS'|" "$CONF.new"

	# The two facts that must be true together: the :53 handover rule is there and
	# nothing contradicts it. The upstream is deliberately NOT part of the check --
	# an operator's own upstream is left alone, and demanding ours would make the
	# handover refuse to apply to exactly the file it must fix.
	if grep -qE '^[[:space:]]*dport\(53\)' "$CONF.new" &&
		grep -qF "$MARK" "$CONF.new" &&
		! grep -qF '!dport(53)' "$CONF.new"; then
		mv -f "$CONF.new" "$CONF"
		chmod 0644 "$CONF" 2>/dev/null
		if grep -qF "$SMARTDNS" "$CONF"; then
			log "DNS policy patched: '$RULE' first, redundant !dport(53) dropped, default upstream -> $SMARTDNS"
		else
			log "DNS policy patched: '$RULE' first, redundant !dport(53) dropped (operator's own upstream kept)"
		fi
		if pgrep -f /usr/bin/honk-core >/dev/null 2>&1; then
			log "honk is already running; it keeps the old policy until it is restarted"
		fi
		return 0
	fi
	log "ERROR: refused to write an incompletely patched $CONF; honk keeps its stock DNS policy"
	rm -f "$CONF.new"
	return 1
}

status() {
	if [ ! -f "$CONF" ]; then
		echo "honk config: absent ($CONF)"
		return 0
	fi
	if grep -qF "$MARK" "$CONF"; then
		echo "honk DNS policy: patched by mydist"
	else
		echo "honk DNS policy: NOT patched (stock)"
	fi
	echo "--- dns block ---"
	sed -n '/^dns {/,/^}/p' "$CONF"
	echo "--- routing block ---"
	sed -n '/^routing {/,/^}/p' "$CONF"
}

# ---- the other half: the resolver's transport -------------------------------
#
# Patching honk's policy only gives :53 back to dnsmasq/smartdns. It does not
# make the resolver able to leave the box: while honk runs, the router's own UDP
# never completes (measured 2026-10-18: direct AND proxied both time out, while a
# local TCP connection to the same address answers). A UDP upstream therefore
# resolves nothing cold -- dnsmasq and smartdns keep answering from cache until a
# TTL runs out, which looks healthy until it does not. DNS-over-TLS rides TCP and
# works in both states (honk on: cold names resolve through a LAN client).
#
# Fresh installs get DoT from /etc/uci-defaults/97-mydist-dns. uci-defaults do
# not run again on an upgrade, so a box that keeps its config would keep the old
# UDP upstreams and lose DNS the moment honk is enabled. Convert exactly that one
# case: our old default set (223.5.5.5 / 119.29.29.29, either or both, and no
# @server section of its own). Anything else is the operator's choice.
LEGACY_UDP='223.5.5.5 119.29.29.29'
ensure_dot_upstreams() {
	local list sections s added=0
	command -v uci >/dev/null 2>&1 || return 0
	sections=$(uci -q show smartdns 2>/dev/null | grep -c '@server\[')
	[ "${sections:-0}" = 0 ] || return 0
	list=$(uci -q get smartdns.@smartdns[0].server)
	[ -n "$list" ] || return 0
	for s in $list; do
		case " $LEGACY_UDP " in
			*" $s "*) ;;
			*) return 0 ;;	# a custom upstream: not ours to rewrite
		esac
	done
	add_dot_upstream() {
		local sec
		sec=$(uci -q add smartdns server) || return 0
		# no quotes inside the values: uci stores them literally, and a value of
		# `'tls'` makes smartdns's init fall back to udp (measured 2026-10-18)
		uci -q set "smartdns.$sec.enabled=1"
		uci -q set "smartdns.$sec.ip=$1"
		uci -q set "smartdns.$sec.type=tls"
		uci -q set "smartdns.$sec.port=853"
		uci -q set "smartdns.$sec.host_name=$2"
		added=1
	}
	add_dot_upstream 223.5.5.5    dns.alidns.com
	add_dot_upstream 119.29.29.29 dot.pub
	[ "$added" = 1 ] || return 0
	uci -q delete smartdns.@smartdns[0].server
	uci -q add_list smartdns.@smartdns[0].server='223.5.5.5'
	uci -q commit smartdns || return 0
	log "smartdns upstreams migrated to DoT + a plain-UDP fallback (UDP alone cannot leave the box while honk runs)"
	if pgrep -f /usr/sbin/smartdns >/dev/null 2>&1; then
		/etc/init.d/smartdns restart >/dev/null 2>&1
	fi
}

case "${1:-patch}" in
patch)
	ensure_dot_upstreams
	patch
	;;
status) status ;;
*) echo "usage: $0 [patch|status]" >&2; exit 1 ;;
esac
