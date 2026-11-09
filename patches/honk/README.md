# honk: x86/RK source patch, IPQ/MTK stock

This directory removes the `kwrum1/openwrt-honk` fork from the build. The
firmware always clones the latest **upstream** `kenzok8/openwrt-honk`; for
`X86` / `ROCKCHIP` two things are applied on top of that clone:

1. `honk-x86rk.patch` — a plain unified diff against the upstream package
   (`patch -p1 -d ./package`), applied by `Scripts/Packages.sh`;
2. `apply-makefile.sh` — anchored edits to `honk/Makefile` (core pin and asset
   URL) plus the `direct-unspec` install line.

IPQ/MTK get neither: they keep the stock package and the stock honk core
(hardware flowtable/PPE path).

## What the patch changes

```
honk/files/90-honk-boot        add the .lan/.local DNS rule; boot-time auto-recover
honk/files/config.dae          SmartDNS-only resolver + proxy DoH routing
honk/files/system.dae          nfqueue off, Doona native API on LAN
honk/files/control.sh          nfqueue gating + boot-time auto-recover
honk/files/maintenance.sh      auto-recover without a nested start
honk/files/honk.init           auto-recover before the enabled gate
honk/files/direct-unspec       new: marker "core hands direct flows back"
luci-app-honk/.../rpcd/honk    auto-recover before taking the lock
```

Why for x86/RK only: honk owns the LAN TCX hook. The p1 core returns direct
flows as `TC_ACT_UNSPEC`, so the classic TC chain (dpd on x86/RK) still sees
them. On IPQ/MTK the kernel flowtable/PPE does the acceleration and the stock
core is correct.

## Makefile

`apply-makefile.sh` edits the upstream `honk/Makefile` in place (anchored; a
rename fails the build):

- pins `CORE_COMMIT` (the commit the p1 patch is written against);
- points `HONK_SOURCE_TAG`/`HONK_SOURCE_URL` at this repository's `core-p1`
  release instead of upstream's;
- appends the `-p1` suffix to the per-arch asset names; hashes stay `SKIP` (the
  real hashes come from `generated-stage.mk`, fetched from the release);
- adds `@KERNEL_DEBUG_INFO_BTF` and installs the `direct-unspec` marker.

## Patched core

`ci/` is the source-build side, run by `.github/workflows/HONK-CORE.yml`:

- `pins.env` pins `daeuniverse/honk` and the release repo;
- `build-core.sh` builds x86_64/aarch64/armv7 and publishes under `core-p1`;
- `patches/honk-direct-unspec.py` hands direct-classified flows back to the
  classic TC chain (`DIRECT_UNSPEC_MARK` + `TC_ACT_UNSPEC`);
- `patches/honk-core-config-validate.patch` is the upstream config check.

Both patch scripts are anchor-based on purpose: if upstream moves, HONK-CORE or
the image build fails loudly and the pin/patch must be bumped together. That is
the whole maintenance cost — no branch to merge.

## Keeping up with upstream

`honk-x86rk.patch` carries only the ~180 lines this project actually changes.
When `kenzok8/openwrt-honk` moves:

1. refresh the clone, run `patch -p1 --dry-run`; a rejected hunk is the only
   thing to rebase (usually a few lines);
2. if the core commit changed, bump `CORE_COMMIT` in `ci/pins.env` **and** in
   `apply-makefile.sh`, re-run `honk-direct-unspec.py` against the new commit
   (it fails if the anchors moved), then run **HONK-CORE** to republish
   `core-p1`;
3. rebuild an X86 or ROCKCHIP image.

Regenerating the patch: clone upstream, copy the desired files, and
`git diff --no-index` the two trees into `honk-x86rk.patch` (keep `a/` / `b/`
prefixes so `patch -p1` works).

## IPQ / MTK

No patch, no Makefile edit, no `fetch_honk_stage`: the stock upstream honk
package and its stock core assets are used unchanged.
