# router-dns

smartdns is the only resolver and owns `:53`. dnsmasq has no DNS role at all
(`port 0`) and is stopped by `ebpf-posture`; odhcpd is the DHCP authority.

> **Round 10 (2026-10-20) changed the upstream model.** Everything below
> "Round 10" describes the earlier dnsmasq-on-:53 front design and is kept for
> the reasoning it contains; the behaviour that ships now is in the next two
> sections.

## Upstreams, `resolv.conf` and local names (current)

The files below are all maintained by `/usr/libexec/router-dns-sync`, which runs at
`S18` and on every interface event (`/etc/hotplug.d/iface/89-router-dns-sync`):

| path | what |
|---|---|
| `/var/etc/router-dns/resolv.upstream` | the resolvers netifd actually learned (DHCP option 6), with loopback and **every address this box owns filtered out**. smartdns reads it as `resolv-file`. |
| `/var/etc/router-dns/hosts.lan` | the router's own name plus the names odhcpd publishes, in both `name` and `name.lan` form. smartdns reads it as `hosts-file`. |
| `/var/etc/router-dns/hosts.lan.conf` | the same names as static `address /name/ip` rules, rendered into a file smartdns includes with `conf-file` (`smartdns.@smartdns[0].conf_files`). **This is what actually answers.** |
| `/tmp/resolv.conf` | `nameserver 127.0.0.1` + `search lan`. `/etc/resolv.conf` is a symlink to it, so the router resolves through this box like a LAN client. |

The hosts *file* alone is not enough on smartdns 48.4: it turns a hosts-file
entry into a cache record with a 120 s TTL and, when that expires, asks
upstream instead of re-reading the file. Measured 2026-10-20 on the lab VM:
`OWRT.lan` answered for the first ~120 s after every smartdns start, then went
NXDOMAIN for good while the file, its mtime and the smartdns pid were all
unchanged (the upstream answers NXDOMAIN for `.lan`, and that gets negatively
cached too). An `address` rule is consulted on every query and never
forwarded, which is why the rules are the authoritative copy and the hosts
file is kept only for tools that read it.

Why: `resolv-file` defaults to netifd's own `/tmp/resolv.conf.d/resolv.conf.auto`,
i.e. the nameservers from the WAN lease. A lease that points at the router
itself (a DHCP server in the same L2 answering our DISCOVER, a stale
`network.lan.dns`) put our own address in that list, smartdns asked itself, and
every query timed out while the daemon looked healthy. `/etc/init.d/boot`
re-creates `/tmp/resolv.conf` as a symlink to that same file on every boot,
which is why the sync replaces the *link* with a real file instead of writing
through it: writing through it would destroy the only copy of the WAN's
resolvers.

`dhcp.@dnsmasq[0].resolvfile` is repointed at `resolv.upstream` because that is
the uci option smartdns's init reads to decide what `resolv-file` to emit.
dnsmasq itself is not a resolver here; if it is ever re-enabled it reads a
valid nameserver list.

Plain-UDP upstreams are no longer hardcoded (`223.5.5.5`): a network that
filters public DNS -- like the test lab, which only allows its own resolvers --
made that a black hole. DoT entries (`@server` sections, port 853) are still
seeded on first boot and kept.

## What it installs

| path | what |
|---|---|
| `/etc/init.d/router-dns` | START=18; runs the sync, patches `no-resolv` + `server=127.0.0.1#6053` into `/etc/dnsmasq.conf` (unused while dnsmasq has port 0), applies the DNS egress policy, patches honk's DNS policy |
| `/usr/libexec/router-dns-sync` | upstreams / `resolv.conf` / local names, idempotent |
| `/etc/hotplug.d/iface/89-router-dns-sync` | the same sync on `ifup`/`ifupdate`/`ifdown` |
| `/etc/uci-defaults/97-ebpf-dns` | turns smartdns on, `port=53`, `auto_set_dnsmasq=0`, DoT upstream seeds, **and enables router-dns** |
| `/usr/libexec/router-honk-dns` | keeps honk's own DNS upstream on `udp://127.0.0.1:53` |

Nothing compiles, and nothing outside our own files is written at build time.

### The two lines that decide whether any of this works

`/etc/uci-defaults/97-ebpf-dns` ends with

```sh
/etc/init.d/smartdns enable >/dev/null 2>&1
/etc/init.d/router-dns enable >/dev/null 2>&1    # <- load-bearing
```

The second one is not decoration, and it was missing from the committed feed for
a while (fixed in `b14f2b6`). Without `/etc/rc.d/S18router-dns` the init never
runs, `/etc/dnsmasq.conf` keeps its stock contents, dnsmasq goes on resolving
through `/tmp/resolv.conf.auto`, and smartdns sits on `127.0.0.1:6053` with
nobody asking it anything. The image *looks* fine in every other way — dnsmasq
answers, the box has internet — which is exactly why the check at the bottom of
this file pulls smartdns out instead of grepping for it.

## Why this shape

### dnsmasq is not replaced, only defanged

The two supported smartdns topologies on OpenWrt are:

* `port 53` + `auto_set_dnsmasq=1` — smartdns takes :53, smartdns's init sets
  `dhcp.@dnsmasq[0].port=0`. Literally "smartdns replaced dnsmasq".
* `port <non-53>` + forward — dnsmasq stays on :53 and forwards to smartdns.

We take the second one, because with dnsmasq at port 0 the box also loses
everything that is served *by dnsmasq* rather than resolved by it:

* `/etc/hosts`
* `option local '/lan/'` and the `lan` domain
* the names odhcpd publishes in `/tmp/hosts/odhcpd.hosts.lan` (dnsmasq reads it
  with `--addn-hosts`; it is how LAN clients get each other's names after the
  odhcpd DHCP handover)

Upstream behaviour is identical either way: in both modes every lookup is
answered by smartdns, concurrently, with the fastest result. What changes is
only who answers the LAN-facing side. So "smartdns replaces dnsmasq's
resolution" holds, and the local name service survives.

### A boot-time patch of `/etc/dnsmasq.conf`, not a shipped file

dnsmasq's init reads that file unconditionally:

```sh
local dnsmasqconffile="/etc/dnsmasq.${cfg}.conf"
if [ ! -r "$dnsmasqconffile" ]; then
    dnsmasqconffile=/etc/dnsmasq.conf
fi
[ -f "${dnsmasqconffile}" ] && {
    xappend "--conf-file=${dnsmasqconffile}"
}
```

(`package/network/services/dnsmasq/files/dnsmasq.init`, ~942–950.)

So the forwarding half needs no write into `/etc/config/dhcp` at all. But that
file cannot be *shipped* either: it is owned by `dnsmasq-full`, and a second
package providing it makes apk abort the entire transaction —

```
ERROR: router-dns-0.1.0-r1: trying to overwrite etc/dnsmasq.conf
       owned by dnsmasq-full-2.93-r4.
```

— which is what this package did in round 4. Hence `/etc/init.d/router-dns`,
at START=18 (after dnsmasq's own configuration has been generated, before
S19dnsmasq starts), appending `no-resolv` and `server=127.0.0.1#6053` if they
are not already present. The patch is idempotent, and it re-applies itself after
any dnsmasq upgrade that restores the stock file — a better failure mode than a
shipped file, which would either be refused or silently overwritten.

`no-resolv` is the load-bearing line. Without it the stock config's

```
option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
```

keeps the ISP resolvers in the pool, dnsmasq races them against smartdns, and
smartdns stops being the authority — which is the whole point of installing it.

### `auto_set_dnsmasq=0` is load-bearing too

Left at its default of 1, smartdns's own init rewrites `/etc/config/dhcp`:

* `set_forward_dnsmasq` → `dhcp.@dnsmasq[0].server`, `.noresolv`,
  `.rebind_protection`, `.domainneeded`
* `set_main_dns` → `dhcp.@dnsmasq[0].port=0`, `dhcp.lan.dhcp_option`

(`feeds/packages/net/smartdns`, from `package/openwrt/files/etc/init.d/smartdns`.)

Those writes are upstream's supported integration and they are reverted on
`stop`, but this distribution does not let a package rewrite the base config, so
the mode is forced to 0 and the dnsmasq half is done here instead.

### One deliberate difference from upstream's mechanism

Upstream also clears `rebind_protection` and `domainneeded` on dnsmasq. Neither
can be turned off from a dnsmasq conf file — there is no inverse of
`--stop-dns-rebind`. They stay at the stock values, which is slightly stricter
and harmless in practice: rebind protection only rejects *public* names that
resolve into RFC1918 space, and `--domain-needed` only refuses to forward names
without a dot.

## Defaults and how to change them

Upstreams default to `223.5.5.5` (AliDNS) and `119.29.29.29` (DNSPod), so a
freshly flashed box resolves without any further setup. smartdns queries both
concurrently and answers with the fastest result.

```
uci delete smartdns.@smartdns[0].server
uci add_list smartdns.@smartdns[0].server='your.resolver'
uci commit smartdns
/etc/init.d/smartdns restart
```

Domain-based splitting, DoT/DoH upstreams, caching and TTL policy are all
normal `smartdns` uci options; the LuCI page is installed
(`luci-app-smartdns`) without the optional WebUI dashboard, which would pull in
node and rust-bindgen to build.

## Interaction with the rest of the baseline

* **odhcpd** hands out the router as the only DNS server; `dns_redirect 1` in the
  stock dnsmasq config keeps clients that hard-code a resolver pointed at the
  box. Both still apply.
* **Domain + VLAN steering** now lives in the dataplane (`router-dataplane`): the
  VLAN axis is a policy gate in `dpd`, the domain axis is honk's own rules. The
  old `router-steer` package was retired and deleted — its kernel-side DNS
  snooping was redundant with what honk already knows, and an extra in-kernel DNS
  parser below smartdns is exactly the kind of thing this baseline removes.
* **honk** does its own DNS handling for its domain rules. If honk is ever told
  to hijack :53, that decision has to be reconciled with smartdns being the
  resolver; by default honk does not.

## Verifying it actually took effect

```
# 1. the init that does the patching is enabled (without this, nothing below matters)
ls -l /etc/rc.d/S18router-dns /etc/rc.d/S19smartdns

# 2. the patch is in the file dnsmasq actually reads
grep -E 'no-resolv|server=127.0.0.1#6053' /etc/dnsmasq.conf

# 3. smartdns is bound to 6053 (17A5 in /proc/net/udp) and is the only upstream
grep -i 17A5 /proc/net/udp
uci show smartdns | grep -E 'port|enabled|auto_set_dnsmasq'

# 4. end to end through the router
nslookup www.example.com 192.168.10.1
```

The decisive check is behavioural, and `build/qemu-closure.sh` (stage C3) runs
it that way: **stop smartdns and the box must stop resolving.** On this image
dnsmasq answers `SERVFAIL` and nothing else, which is the proof that `no-resolv`
took and that dnsmasq has no resolver of its own. If a lookup still succeeds
with smartdns stopped, dnsmasq is racing the ISP resolvers and smartdns is
decorative — which is precisely the state the missing `enable` line produces,
except that in *that* state even the greps in step 2 come up empty.
