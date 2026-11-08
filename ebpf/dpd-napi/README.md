# dpd-napi

System-level tuning component for DPD-FW.

## Scope

- Enumerate NAPI instances and IRQs (`netdev-genl`, `/sys/class/net/*/queues`).
- Apply per-NAPI settings:
  - `defer-hard-irqs`
  - `gro-flush-timeout`
  - `irq-suspend-timeout`
  - `threaded` (threaded NAPI)
- Bind NAPI kthreads / IRQs to the intended CPUs.
- Configure RSS/RPS/XPS and `net.core.netdev_budget` / `dev_weight`.
- A/B GRO/GSO/TSO per device.
- Select qdisc mode: `noqueue`/`mq` (pure forwarding) or `cake` (QoS).

## Principles

- Standard kernel interfaces only; no driver changes.
- Every setting is recorded with the measured effect; no blind tuning.
- Threaded NAPI and busy-poll trade latency for throughput/jitter; A/B them.
- `qos=off` is required for the 10G line-rate gate; `cake` gets its own gate.

## Status

Scaffold (P0). Implementation lands in P4.
