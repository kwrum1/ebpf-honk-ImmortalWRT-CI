# honk: x86/RK overlay, IPQ/MTK stock

This directory removes the `kwrum1/openwrt-honk` fork from the build. The
firmware always clones the latest **upstream** `kenzok8/openwrt-honk`; the
files here are applied only for `X86` / `ROCKCHIP`.

## What is overlaid

`overlay/` is copied over the cloned package tree for X86/RK:

```
overlay/honk/files/90-honk-boot        DNS/SmartDNS/NFQUEUE/Doona boot fixes
overlay/honk/files/config.dae          SmartDNS-only resolver + proxy DoH routing
overlay/honk/files/system.dae          nfqueue off, Doona native API on LAN
overlay/honk/files/control.sh          nfqueue gating + boot-time auto-recover
overlay/honk/files/maintenance.sh      auto-recover without nested start
overlay/honk/files/honk.init           auto-recover before the enabled gate
overlay/honk/files/direct-unspec      marker: core hands direct flows back
overlay/luci-app-honk/.../rpcd/honk    auto-recover before taking the lock
```

These are owned by this repository. Upstream changes to the same files are
intentionally not merged for X86/RK; that is the trade-off that removes the
fork and its conflicts. IPQ/MTK never see them.

## Makefile

`apply-makefile.sh` edits the upstream `honk/Makefile` in place (anchored; a
rename fails the build):

- pins `CORE_COMMIT=ce0380...` (the commit the p1 patch is written against);
- points `HONK_SOURCE_TAG`/`HONK_SOURCE_URL` at this repository's `core-p1`
  release instead of the fork;
- appends the `-p1` suffix to the per-arch asset names, hashes `SKIP` (the real
  hashes come from `generated-stage.mk`);
- adds `@KERNEL_DEBUG_INFO_BTF` and installs `direct-unspec`.

## Patched core

`ci/` is the source-build side, run by `.github/workflows/HONK-CORE.yml`:

- `pins.env` pins `daeuniverse/honk` at the same commit and the release repo;
- `build-core.sh` builds x86_64/aarch64/armv7 and publishes under `core-p1`;
- `patches/honk-direct-unspec.py` hands direct-classified flows back to the
  classic TC chain (`DIRECT_UNSPEC_MARK` + `TC_ACT_UNSPEC`), so dpd keeps
  seeing direct traffic while honk proxies the rest;
- `patches/honk-core-config-validate.patch` is the upstream config check.

The patch script is anchor-based on purpose: if upstream changes the core, the
HONK-CORE run fails loudly and the pin/patch must be bumped together.

## IPQ / MTK

No overlay, no Makefile edit, no `fetch_honk_stage`: the stock upstream honk
package and its stock core assets are used unchanged (hardware flowtable/PPE
path).

## Updating

1. Bump `CORE_COMMIT` in `ci/pins.env` and `apply-makefile.sh` together.
2. Run **HONK-CORE** manually; it publishes `core-p1`.
3. Rebuild an X86 or ROCKCHIP image.
