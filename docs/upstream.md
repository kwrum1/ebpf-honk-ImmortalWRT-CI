# Upstream model: no fork to merge

Last updated: 2026-10-28

## Short answer

The firmware is built **from upstream, unmodified**:

```
VIKINGYFY/immortalwrt@owrt   (PPE / eBPF / MediaTek images)
VIKINGYFY/immortalwrt@main   (Qualcomm NSS-firmware images)
```

cloned fresh in every build (`WRT_REPO` in the workflow). There is no branch of
ours in that repository to keep in sync, and therefore no upstream merge.

What this repository contributes is **additive**, plus a few scripted edits:

| Kind | Where | Merge burden |
|---|---|---|
| eBPF datapath packages (8 dirs) | this repo, `ebpf/` | none - upstream has no such packages; copied into `package/` at build time |
| Third-party packages (aurora, honk, v2ray-geodata, partexp) | cloned in `Scripts/Packages.sh` | none |
| Edits to upstream files (x86 GPU trim, firewall4 offload default, target.mk, dnsmasq/odhcpd handover) | `Scripts/Handles.sh`, `Scripts/Settings.sh` | pattern-anchored `sed`, checked by `UPSTREAM-CHECK` |
| Build config | `Config/{X86,ROCKCHIP,GENERAL,...}.txt` | none; they are `.config` fragments, not source |

`kwrum1/immortalwrt@mydist` (the old dev mirror) is **not used by any
workflow** any more. It can be archived or deleted.

## Why not a patch file for everything

The datapath is new files, so a patch would have to be an "add these 78 files"
patch - a copy with extra steps. Packaging it as `ebpf/` (a local feed) is the
same thing with a simpler failure mode: a missing package is a build error, not
a fuzzily-applied hunk.

The edits that *do* touch upstream files stay as anchored `sed` rather than
`.patch` hunks on purpose: a unified diff breaks on every upstream context
change (line numbers, neighbouring comments), while an anchored sed keeps
working and - with `UPSTREAM-CHECK` - fails loudly when the anchor itself is
gone. That is the property that makes "follow upstream" cheap: bump the branch,
run `UPSTREAM-CHECK`, and only look at the anchors that changed.

## Following upstream

1. Upstream pushes to `owrt` / `main`; nothing to do.
2. Nightly `UPSTREAM-CHECK` (both branches) re-verifies every anchor:
   ```
   sh Scripts/upstream-check.sh <fresh clone>
   ```
3. If it reports a missing anchor, update the matching block in
   `Scripts/Handles.sh` (or `Settings.sh`) and re-run the check.
4. Build pipelines (`EBPF-WRT-ALL`, `QCA-PPE`, `QCA-NSS`, `MTK-ALL`) always
   clone upstream HEAD, so an upstream change is picked up by the next build.
   Each release's `provenance-<CONFIG>.txt` records the exact commit.

## What "our source" means now

| Question | Answer |
|---|---|
| Is the OS from my tree? | No. It is upstream `owrt`/`main`, cloned per build. |
| Where does the eBPF code live? | this repo's `ebpf/` (copied to `package/ebpf/`), built only for X86/ROCKCHIP |
| Do I have to merge upstream? | No. The only thing that can drift is the anchor list; `UPSTREAM-CHECK` watches it. |
| How do I know which datapath a release has? | `provenance-<CONFIG>.txt`: firmware commit + `ebpf_abi` + `ebpf_object` sha256 + `ebpf_src_tree` sha256 |
