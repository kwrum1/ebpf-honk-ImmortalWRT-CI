# CI layout (this repository)

Last updated: 2026-10-28

## Where the code comes from

| Layer | Source | Notes |
|---|---|---|
| Firmware | `VIKINGYFY/immortalwrt` | the upstream tree, unchanged. Branch decides the flavour (see below). |
| eBPF datapath | **this repository, `ebpf/`** | copied into `wrt/package/ebpf/` by `Scripts/Packages.sh`, for X86/ROCKCHIP only. |
| Third-party packages | cloned by `Scripts/Packages.sh` | aurora theme, honk (kwrum1/openwrt-honk@main), v2ray-geodata, partexp. Only what actually lands in the image. |

There is no second copy of the datapath anywhere: the firmware repo is
upstream, and `ebpf/` here is the only place a `dpd_fastpath.bpf.c` change can
live. `BPF-CHECK` compiles it on every change (~1 minute) instead of finding out
at the end of a 90-minute image build.

`einat-ebpf` is the same idea one step removed: upstream source, built here
with `patches/einat-perf.py` (p1) and `patches/einat-perf-p2.py` (p2)
against a pinned commit. `EINAT-BUILD` runs `patches/einat-e2e-nat.sh` in
network namespaces (EIM, EIF/full cone, ICMP, a 20 MB TCP transfer) and only
then publishes the `einat-p2` release that the package downloads.

## Branches and what they mean

| Branch | Meaning | Built by |
|---|---|---|
| `owrt` | mainline tree, **PPE** flow offload (kernel flowtable) | EBPF-WRT-ALL, MTK-ALL, QCA-PPE |
| `main` | Qualcomm **NSS firmware** variant (`qca-nss-drv`) | QCA-NSS |

## Workflows

| Workflow | Configs | Source | Purpose |
|---|---|---|---|
| `EBPF-WRT-ALL` | X86, ROCKCHIP | `@owrt` | the eBPF images (datapath from `ebpf/`) |
| `QCA-PPE` | IPQ60XX / IPQ807X (wifi yes/no) | `@owrt` | **PPE** variant |
| `QCA-NSS` | IPQ60XX / IPQ807X (same boards) + IPQ53XX / IPQ95XX | `@main` | **NSS firmware** variant (53xx/95xx are NSS-only) |
| `MTK-ALL` | MEDIATEK-WIFI-YES/NO | `@owrt` | MediaTek |
| `WRT-TEST` | one config, by hand | `owrt` or `main` | reproduce a single build |
| `BPF-CHECK` | — | `ebpf/` | compile the datapath + dpdctl in ~1 min |
| `EINAT-BUILD` | x86_64, aarch64 | `patches/` + upstream `EHfive/einat-ebpf` (pinned commit) | einat binaries with the p1/p2 datapath patches; publishes the `einat-p2` release only after the netns e2e passes |

Automation, restored to the upstream shape:

| Workflow | When | What |
|---|---|---|
| `Auto-Clean` | daily 22:00 UTC, or manual | delete yesterday's releases/tags/runs, then **trigger every build pipeline** |
| `Cache-Clean` | Sundays 20:00 UTC, or manual | `gh cache delete --all` |
| `EBPF-WRT-ALL` / `QCA-PPE` / `QCA-NSS` / `MTK-ALL` | on `Auto-Clean` completion, or manual | the images |
| `WRT-TEST` | manual only | one config |
| `BPF-CHECK` | weekly + manual | compile the datapath in ~1 min |
| `UPSTREAM-CHECK` | daily 18:15 UTC + manual | verify the build-time anchors on both branches |
| `EINAT-BUILD` | on `patches/einat-*` change, or manual | netns e2e (EIM/EIF/ICMP/TCP), then build and publish einat |

A push alone never starts a build: a nightly build always pins the source commit
it cloned, and the release records it.

## What each build records

Every release carries `provenance-<CONFIG>.txt`:

```
config / source / branch / commit / commit_full / commit_date / target
kernel / dpd_abi / bpf_object sha256+size / dpd_src_tree sha256
clang / libbpf / built_at
```

That is what makes "which datapath is in this image" answerable without
rebuilding it.

## Housekeeping rules

* Do not re-add the `flow_offloading -> 0` edit outside the X86/ROCKCHIP block
  in `Scripts/Handles.sh`: IPQ/MTK acceleration *is* the flowtable. The script
  asserts this at build time and prints `offload: <CONFIG> keeps ...`.
* Do not point a workflow back at a fork of immortalwrt: the firmware source is
  upstream, the datapath is `ebpf/`.
* Third-party clones live in `Scripts/Packages.sh` and must be listed in
  `Scripts/verify-packages.sh` so a package that silently drops out is noticed.
