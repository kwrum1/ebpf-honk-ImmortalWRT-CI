# mydist / router-dns

smartdns does the resolution. dnsmasq keeps :53 and forwards everything to it.

## What it installs

| path | what |
|---|---|
| `/etc/init.d/router-dns` | START=18; patches `no-resolv` + `server=127.0.0.1#6053` into `/etc/dnsmasq.conf` at every boot |
| `/etc/uci-defaults/97-mydist-dns` | turns smartdns on, `port=6053`, `auto_set_dnsmasq=0`, default upstreams, **and enables router-dns** |

That is the whole package. Nothing compiles, and nothing outside our own files
is written at build time.

### The two lines that decide whether any of this works

`/etc/uci-defaults/97-mydist-dns` ends with

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
