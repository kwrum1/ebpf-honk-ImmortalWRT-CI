# dpd-honk

`dpd-honk` is the **only proxy plugin** shipped for DPD-FW. It is optional:
`dpd-core` runs direct-only without it.

## Boundary

- honk owns the proxy datapath (TCX redirect to `dae0`).
- `dpd-honk` owns orchestration only:
  - ensure honk’s TCX program runs before DPD’s classic filter;
  - translate honk reload/policy changes into UFS epoch or targeted invalidation;
  - expose honk health/nodes/gate to `dpd-observe` and LuCI;
  - optionally tag flows as `proxy`/`direct` for the Flow Manager.
- `dpd-honk` never proxies packets itself and never links honk code.

## Runtime

- Talks to honk over ubus/config files; no shared BPF maps.
- If honk is absent or stopped, DPD continues direct-only and the gate reports
  `honk_unavailable` rather than failing closed.

## License

GPL-3.0-only. Kept as a separate process/plugin so `dpd-core` stays GPL-2.0.
