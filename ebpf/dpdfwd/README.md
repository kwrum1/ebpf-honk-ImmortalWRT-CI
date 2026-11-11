# dpdfwd — DPD Flow Manager

> **源码不在本仓库。** `src/` 与 `files/` 在构建时由 `Scripts/Fetch-DPD.sh`
> 从 `kwrum1/dpd-fw` 的 `arm` 分支（`packaging/dpdfwd/`）拉取，本仓只保留
> Makefile。这样 `dpdfwd.c` 只有一份，不会再和固件里的副本漂移。


Control-plane daemon for DPD-FW.

## Implemented (MVP)

- Subscribes to rtnetlink **link / IPv4 address / IPv4 route / neighbour**
  events. A burst of events is coalesced (300 ms) into **one** flow-cache
  epoch bump (`dpdctl bump`), which invalidates every cached egress decision
  without walking the flow table.
- Subscribes to **conntrack** new / update / destroy events (NETLINK_NETFILTER,
  CTNETLINK groups) and keeps per-type counters. This is the hook for a future
  per-flow delete; it never blocks or drops anything.
- Publishes `/var/run/dpd/flowd.json` every 2 s:

  ```json
  { "uptime": 42, "link": 1, "addr": 1, "route": 2, "neigh": 0,
    "ct_new": 12, "ct_update": 8, "ct_destroy": 10,
    "epoch_bumps": 2, "unknown": 0, "errors": 0, "last_event": 1700000000 }
  ```

- `--dry-run` counts without calling `dpdctl`; `--once` exits after the first
  debounced bump (used by tests).

## Split with the dataplane

- The BPF program owns the direct flow lifecycle: learn on miss,
  `accel_after_pkts`, FIN/RST release, per-protocol TTL, epoch validation.
  `dpdfwd` never touches a packet and is not in the fast path.
- `dpdfwd` owns the environment: a link/route/neighbour change invalidates the
  cache in one place, even when the change did not come through a hotplug
  script (operator `ip route`, tunnel, carrier flap).

## Targeted invalidation (implemented)

On a conntrack DESTROY, the orig and reply 5-tuples are parsed from ctnetlink
and queued (128 max). Once per second the daemon writes them to
`/tmp/dpd-ct-delete` and calls `dpdctl delete -f` **once**; dpdctl scans the
UFS map and deletes every key matching any tuple. A conntrack that no longer
exists therefore does not leave a UFS entry behind until its TTL.

`--no-ct-delete` disables the batch; `--dry-run` keeps the tuples but skips the
call. The UFS key's ingress ifindex is not in the conntrack message, so the
pattern uses `any` for it (the 5-tuple is unique per direction in practice).

## Not yet implemented

- `accel_after_pkts` / TTL policy decisions: the daemon publishes nothing into
  `dpd_cfg` today; the values come from UCI via the datapath init script.
- Plugin classification (ACL/QoS/MWAN/honk) is still done by the individual
  packages; `dpd_class` is the cache, but there is no plugin registration ABI
  yet.
