# dpd-napi

System-level tuning component for DPD-FW.

## Scope

- Enumerate NAPI instances and IRQs through the kernel's `netdev` generic
  netlink family (plus `/sys/class/net/*/queues` for RPS/XPS).
- Apply per-NAPI settings:
  - `defer-hard-irqs`
  - `gro-flush-timeout`
  - `irq-suspend-timeout`
  - `threaded` (threaded NAPI)
- Configure RPS/XPS and `net.core.netdev_budget` / `netdev_budget_usecs` /
  `dev_weight`.
- Record the effective state in `/var/run/dpd/napi.json`, plus
  `/var/run/dpd/irq.json`, `gro.json` and `qdisc.json` for the optional
  helpers.

## Binaries / scripts

- `/usr/sbin/dpd-napi` — procd service, applies UCI `dpd_napi`.
- `/usr/sbin/dpd-napi-netdev` — raw NETLINK_GENERIC helper:
  `list [dev]`, `set <dev> <key> <value> ...`.
- `/usr/sbin/dpd-napi-irq` — NAPI/MSI IRQ affinity (`smp_affinity_list`).
- `/usr/sbin/dpd-napi-gro` — per-device GRO/GSO/TSO/checksum A/B.
- `/usr/sbin/dpd-napi-qdisc` — qdisc gate: `keep` / `off` / `cake` / `hybrid`.

## UCI options

| Option | Default | Meaning |
|---|---|---|
| `enabled` | `0` | Apply the NAPI knobs at boot. |
| `irq_cpus` | `''` | CPU list (e.g. `2-3` or `4`) for the data-device NAPI IRQs. Empty = IRQ affinity untouched. |
| `qdisc_mode` | `keep` | `keep`, `off` (root noqueue, `mq` fallback), `cake` (WAN), or `hybrid` (LAN noqueue + WAN cake). |
| `qdisc_cake_args` | `''` | Arguments passed to `tc qdisc ... root cake`, e.g. `bandwidth 500mbit dual-srchost nat`. Empty = unshaped cake (a warning is logged). |

`gro` has no UCI option on purpose: the daemon only records the boot state
(`/var/run/dpd/gro.json`, default `keep`). A feature change is an A/B action:

```sh
# record without changing anything
dpd-napi-gro --dev eth1

# A/B: disable GRO on one NIC
dpd-napi-gro --dev eth1 --gro off
dpd-napi-gro --dev eth1 --gro on

# checksums
dpd-napi-gro --dev eth1 --rx-checksum off --tx-checksum off --dry-run

# any other ethtool feature
dpd-napi-gro --dev eth1 --feature sg=off
```

IRQ affinity:

```sh
dpd-napi-irq --cpus 2-3 --dev eth1
dpd-napi-irq --cpus 4              # all physical NICs if --dev omitted
dpd-napi-irq --cpus 2-3 --dry-run  # report only
```

The IRQ list comes from `dpd-napi-netdev list <dev>` first, then
`/sys/class/net/<dev>/device/msi_irqs`, then `/proc/interrupts`. The summary
(`/var/run/dpd/irq.json`) records the previous mask and whether each write
succeeded. If `irqbalance` is running it can overwrite the masks; disable it
for a pinned profile.

qdisc gate:

```sh
dpd-napi-qdisc --mode off --lan br-lan --wan eth1
dpd-napi-qdisc --mode cake --wan eth1 --bandwidth 500mbit
dpd-napi-qdisc --mode hybrid --lan br-lan --wan pppoe-wan \
               --cake-args 'bandwidth 500mbit dual-srchost nat'
dpd-napi-qdisc --mode off --dev eth1 --dry-run
```

A foreign root qdisc (`fq_codel` from SQM, `htb`, ...) is not replaced unless
`--force` is given; the script exits 1 and changes nothing. `keep` only records
the current root qdiscs in `/var/run/dpd/qdisc.json`.

## Principles

- Standard kernel interfaces only; no driver changes.
- Every setting is recorded with the measured effect; no blind tuning.
- Threaded NAPI and busy-poll trade latency for throughput/jitter; A/B them.
- `qos=off` is required for the 10G line-rate gate; `cake` gets its own gate.

## Status

P4.1 delivered: per-NAPI get/set verified on x86_64 (6.18, vmxnet3). Threaded
NAPI needs a driver that opts in; the knob is exposed but the profile choice
needs real-hardware A/B. See `docs/P4-NAPI.md` in the dpd-fw repo.

The IRQ-affinity, GRO-A/B and qdisc helpers are new in this release. Their
interfaces are stable and `--dry-run` is safe, but the CPU masks, offload
choices and CAKE parameters still need per-platform A/B numbers (1G/2.5G/10G).
