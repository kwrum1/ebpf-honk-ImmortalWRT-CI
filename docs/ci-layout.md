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

## Branches and what they mean

| Branch | Meaning | Built by |
|---|---|---|
| `owrt` | mainline tree, **PPE** flow offload (kernel flowtable) | EBPF-WRT-ALL, MTK-ALL, QCA-ALL |
| `main` | Qualcomm **NSS firmware** variant (`qca-nss-drv`) | QCB-ALL |

## Workflows

| Workflow | Configs | Source | Purpose |
|---|---|---|---|
| `EBPF-WRT-ALL` | X86, ROCKCHIP | `@owrt` | the eBPF images (datapath from `ebpf/`) |
| `QCA-ALL` | IPQ60XX / IPQ807X (wifi yes/no) | `@owrt` | **PPE** variant |
| `QCB-ALL` | IPQ60XX / IPQ807X (wifi yes/no) | `@main` | **NSSFW** variant |
| `MTK-ALL` | MEDIATEK-WIFI-YES/NO | `@owrt` | MediaTek |
| `WRT-TEST` | one config, by hand | `owrt` or `main` | reproduce a single build |
| `BPF-CHECK` | — | `ebpf/` | compile the datapath + dpdctl in ~1 min |
| `Clean` | — | — | keep 12 releases / 14 days of runs, drop caches |

All build workflows are triggered by their own schedule and by
`workflow_dispatch`. Nothing chains off upstream's `Auto-Clean` any more, and no
push alone starts a build.

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
