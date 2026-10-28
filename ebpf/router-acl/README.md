# router-acl — the WAN eBPF ACL

The piece that lets the distribution stop asking `nf_conntrack` whether an
inbound packet belongs to something we started.

```
                       WAN device
   ingress :  einat TCX  ->  router-acl (pref 90)  ->  dpd-fastpath (pref 100)
   egress  :  einat TCX  ->  router-acl (pref 90)
```

`sch_handle_ingress()` runs `tcx_run()` before `tc_run()`, so einat always sees a
packet first. pref 90 puts this program in front of the fastpath: a packet we
drop must never reach it.

## Redlines

* It does **not** do NAT. NAT has exactly one owner, `einat-ebpf`.
* It does **not** read einat's maps. Everything it knows it learned itself, by
  watching the WAN **egress** direction.
* It never redirects and never rewrites a packet — it only accepts or drops.
* Anything it is not sure about is returned as `TC_ACT_UNSPEC`, so fw4 still
  gets to decide. This is a pre-filter, not the last word on protocols it does
  not model.
* Killer switch: `acl_cfg.mode == 0` makes both programs return `UNSPEC`.

## Why the IPv4 table is keyed by the remote endpoint

einat does **both** halves of the translation in eBPF — SNAT on egress (TCX) and
the reverse on ingress (TCX) — and both of its links run *before* this program,
because the kernel calls `tcx_run()` before `tc_run()` in both
`sch_handle_ingress()` and `sch_handle_egress()`. So the two hooks do not see the
same packet:

```
egress    the packet AFTER SNAT:     src = wan_ip : wan_port
ingress   the packet AFTER un-SNAT:  dst = lan_host : lan_port
```

The port is therefore a **different number** on the two sides. A table keyed by
port can never match: every reply would be dropped and every flow would die.
That is not theory — it was measured, and the signature was "ICMP works, TCP and
UDP are all dead", because einat does not rewrite the ICMP echo id, so a
port-keyed table is right for ICMP by accident. See 工作计划.md §13.21 and
交付报告.md §4.7.1.

The only field that survives both translations is the **remote endpoint**: what
we sent to is exactly what the reply comes from.

```
egress   learn  (proto, iph->daddr, dport)
ingress  match  (proto, iph->saddr, sport)
```

That is exact for every flow the box starts, forwarded or local, and it is also
safe: a third party cannot get a packet accepted without spoofing the exact
remote endpoint we are already talking to, and then it is blind.

The cost is that a **third-party initiated** inbound packet — a genuine full cone
peer that learned the mapping elsewhere — does not match. `fullcone '1'` restores
it by additionally accepting inbound TCP/UDP whose destination is inside a LAN
prefix. That is the same posture einat's own procd data takes (a blanket
WAN→LAN accept), and it is off by default because with it on, anything able to
forge a LAN destination can inject into the LAN: by the time the packet reaches
TC, einat has already un-SNATed it, so "einat did this" and "somebody wrote a LAN
address in the header" are indistinguishable. Telling them apart needs a hook
before einat's un-SNAT, i.e. XDP, which this baseline does not use.

ICMP errors (PMTU, traceroute) look up the **remote endpoint of the quoted inner
packet**, which is also NAT-invariant, so they work whether or not einat rewrote
the quoted header.

IPv6 has no NAT here (no NAT66), so nothing is rewritten and the exact reverse
5-tuple works: learned on egress, matched on ingress.

## Modes

| mode | what it does | risk |
| --- | --- | --- |
| `off` | no-op; every packet `UNSPEC` | none |
| `guard` | drop unsolicited inbound on the WAN | see below — *stricter* than the baseline |
| `bypass` | `guard` + mark + notrack | needs einat; see below |

### `guard` is additive, but stricter than the einat baseline

fw4 and conntrack keep working exactly as before, because the flows stay
tracked. All that changes is that junk never reaches either of them: a port scan
no longer creates conntrack entries and no longer walks the nft ruleset.

Measured: with fw4 alone, three pings aimed at the WAN move
`nf_conntrack_count`; with `guard` on, the count does not move and the ACL's
`ingress_drop` counter does instead.

Worth being explicit about one thing, because it is easy to get backwards:
**with einat enabled, the baseline already accepts everything from the WAN into
the LAN.** einat's own procd data emits a blanket `WAN→LAN accept`, and it has
to, because its SNAT is not a conntrack operation and the replies would otherwise
have no ct state to match. So `guard` does not remove an existing filter — it
*adds* one. Inbound is accepted only if it is a reply we can recognise, an
explicitly allowed port, or (with `fullcone '1'`) addressed into a LAN prefix.

The consequence is that a genuine full cone peer which learned the mapping
somewhere else is dropped unless `fullcone '1'`. That is a real behaviour change
and the reason the default is `enabled '0'`.

### `bypass` is the actual conntrack escape

In this mode the init script writes two files under `/usr/share/nftables.d/`,
which fw4 auto-includes, and reloads fw4:

```nft
# chain-post/raw_prerouting/10-router-acl.nft
iifname "br-lan" notrack
meta mark & 0xff000000 == 0x01000000 notrack

# chain-pre/forward/10-router-acl.nft
meta mark & 0xff000000 == 0x01000000 accept
```

* `raw_prerouting` is priority `raw`, i.e. before conntrack, so the flow never
  gets a ct entry at all.
* `chain-pre/forward` puts the accept before the first rule of the forward
  chain, ahead of fw4's `policy drop`. `accept` there is a terminating verdict,
  so fw4 never asks conntrack anything about that packet.
* `/etc/config/firewall` is **never written**. These are fw4 *includes*, and the
  init owns their lifetime.

When fw4 has DNAT port forwards, the blanket LAN rule becomes port-aware, because
a notracked reply would break them — fw4's DNAT needs conntrack to do the reverse
SNAT, and without it the reply would leave the LAN still carrying its private
source address:

```nft
iifname "br-lan" tcp dport != { 8002 } notrack
iifname "br-lan" udp dport != { 5000 } notrack
iifname "br-lan" meta l4proto != tcp meta l4proto != udp notrack
```

**`bypass` requires einat.** fw4's own `masquerade` is a conntrack operation and
cannot NAT a notracked packet. The init checks `einat.config.enabled` and falls
back to `guard` with a loud log line rather than silently breaking NAT.

### The `forwarded` flag

At the egress hook `skb->sk` is NULL for forwarded traffic and non-NULL for
traffic a local socket generated. Only forwarded flows are marked on the return
path, so the router's own connections keep full fw4 input filtering instead of
silently bypassing it.

## Stopping

`stop_service()` removes the includes and reloads fw4 **unconditionally**. A
leftover `notrack` with nothing doing the NAT would break every LAN→WAN flow, so
this is not optional. Verified in `qemu-acl.sh` §S8.

## Configuration

`/etc/config/router_acl`, section `router_acl 'global'`. Default is
`enabled '0'` — nothing is attached and nothing changes.

```sh
uci set router_acl.global.enabled=1
uci set router_acl.global.mode='guard'
uci commit router_acl
/etc/init.d/router-acl restart
```

Allow list entries are `[family:]proto[/port]`, family defaults to 4:

```sh
uci add_list router_acl.global.forward='tcp/8080'   # inbound to a LAN host
uci add_list router_acl.global.forward='6:tcp/443'   # same, IPv6
uci add_list router_acl.global.input='tcp/22'        # the router's own services
uci add_list router_acl.global.input='icmp'          # ping the router from WAN
```

`import_firewall '1'` (the default) reads `/etc/config/firewall` and adds every
DNAT port forward it declares to the FORWARD list, so switching the ACL on does
not silently break port forwards that already worked. Reading is all it does.

`fullcone '1'` additionally accepts inbound TCP/UDP whose destination is inside a
LAN prefix (read from the LAN interface at start). It is what restores
third-party-initiated full cone inbound, and it is off by default for the reason
explained at the top of this file.

UDP 68 and 546 to the router itself are always allowed (DHCP/DHCPv6 client
replies) and cannot be removed: if the lease was acquired before the program was
attached the mapping table is empty, and without them the first renew would be
dropped.

## What it deliberately does not cover

* **Third-party initiated full cone inbound**, unless `fullcone '1'`. The key is
  the remote endpoint, so a peer that learned the mapping elsewhere is not
  recognised. See the long comment above for why that is the honest default.
* fw4 `rule` sections that accept inbound traffic from a specific source. The
  ACL's allow list is by port only; add the port to `input`/`forward` or leave
  the mode at `off`.
* ICMPv6 extension headers and non-TCP/UDP/ICMPv6 v6 protocols: these are passed
  to fw4 rather than dropped, and fw4 is still fully in the path for anything
  unmarked, so this is a pass-through rather than a hole.
* IPv4 non-first fragments are passed for the same reason — they are useless
  without a first fragment, and that one is filtered.

## CLI

```sh
aclctl show          # configuration
aclctl stats         # per-reason packet counters
aclctl flows         # learned IPv4 flows (proto, remote ip, remote port, …)
aclctl port list     # the allow list
aclctl flush         # forget all learned state
aclctl set mode guard
```

`/etc/init.d/router-acl status` prints attach state, config, allow list, counters
and the generated includes in one go.

## Files

| path | what |
| --- | --- |
| `src/acl.bpf.c` | both programs, compiled twice |
| `src/acl_common.h` | shared ABI, redlines, mode/scope/stat enums |
| `src/aclctl.c` | map access only |
| `files/router_acl.init` | service, mode arbitration, include lifetime |
| `files/router-acl.sh` | attach/detach, include generation, port import |
| `files/91-router-acl` | hotplug: pppoe-wan appears only after the dial |
