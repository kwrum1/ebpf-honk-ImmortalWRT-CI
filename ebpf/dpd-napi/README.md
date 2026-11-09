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
- Record the effective state in `/var/run/dpd/napi.json`.

## Binaries / scripts

- `/usr/sbin/dpd-napi` — procd service, applies UCI `dpd_napi`.
- `/usr/sbin/dpd-napi-netdev` — raw NETLINK_GENERIC helper:
  `list [dev]`, `set <dev> <key> <value> ...`.

## Principles

- Standard kernel interfaces only; no driver changes.
- Every setting is recorded with the measured effect; no blind tuning.
- Threaded NAPI and busy-poll trade latency for throughput/jitter; A/B them.
- `qos=off` is required for the 10G line-rate gate; `cake` gets its own gate.

## Status

P4.1 delivered: per-NAPI get/set verified on x86_64 (6.18, vmxnet3). Threaded
NAPI needs a driver that opts in; the knob is exposed but the profile choice
needs real-hardware A/B. See `docs/P4-NAPI.md` in the dpd-fw repo.
