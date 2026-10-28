# IPQ / MTK: what accelerates them today, and what is worth testing

Status: **analysis only** (2026-10-28). No IPQ/MTK hardware in the lab, so
nothing below is applied blindly. Each item lists how to prove it on a device.

Scope: upstream `VIKINGYFY/immortalwrt` — `owrt` for MTK-ALL / QCA-PPE, `main` for
QCA-NSS. The X86/ROCKCHIP eBPF work in `ebpf/` is never
installed on these targets.

## 1. The acceleration path is the kernel flowtable, not a QCA driver

Checked in the tree and in the configs:

| Evidence | What it says |
|---|---|
| `package/network/config/firewall4/patches/002-default-enable-fullcone.patch` adds `option flow_offloading 1`, `option flow_offloading_hw 1`, `option fullcone 1` | every image built from this tree enables software + hardware flow offload by default |
| `Config/GENERAL-STOCK.txt` has `CONFIG_PACKAGE_kmod-nft-offload=y`, `kmod-nft-fullcone=y`, `kmod-nft-fib=y` | the flowtable exists in the image |
| no `kmod-qca-nss-*` / `nss-drv` / `qca-ssdk` in `Config/IPQ60XX*.txt`, `IPQ807X*.txt` | these images do **not** load the QCA NSS driver stack; "NSS" in this branch means the mainline PPE/flowtable path plus the ath11k PPE patches |
| `Scripts/Handles.sh` (platform guard, `X86|ROCKCHIP`) | the `flow_offloading -> 0` edit that the eBPF targets need is **not** applied here. `Handles.sh` now asserts the IPQ/MTK side keeps `1` and prints the result ("offload: ... keeps flow_offloading_hw=1") |
| `target/linux/qualcommax/config-6.18` | `CONFIG_RPS=y`, `CONFIG_XPS=y`, `CONFIG_GRO_CELLS=y`; `# CONFIG_QCOM_PPE is not set` (that symbol belongs to the newer `qualcommbe` subtargets) |

Consequence: there is no NSS knob to tune in this branch. The wins, if any, are
in flowtable sizing, interrupt placement and CPU behaviour.

## 2. Candidates, in the order I would test them

### 2.1 conntrack / flowtable sizing (cheap, measurable)
A flow only reaches the flowtable after the first packets, and every
non-offloaded flow costs a conntrack entry. Defaults (`nf_conntrack_max`
16384, `nf_flowtable_*_timeout` 30 s) are fine for a home router and thin for a
box with many short flows.

Test: `cat /proc/sys/net/netfilter/nf_conntrack_count` at peak; if it approaches
`nf_conntrack_max`, raise max + `hashsize` and lengthen `nf_flowtable_tcp_timeout`
(fewer re-offload round trips on long downloads). Measure with
`conntrack -C` and `nft list flowtable inet fw4` counters.

### 2.2 IRQ placement (the usual cause of "it drops at 1 Gbit/s")
`/proc/interrupts` shows whether the ethernet/PPE queue IRQs and the ath11k
IRQs land on the same core. On a router build, one hot core is the limit, not
the offload engine. Test: `mpstat -P ALL 1` under iperf; if one CPU sits at 100%
while others idle, pin the wifi IRQs away from the WAN NAPI CPU (or the reverse,
whichever keeps the flowtable CPU free).

`irqbalance` (if the image ships it) is a moving target for this workload:
either pin manually or drop it.

### 2.3 RPS / packet_steering
`CONFIG_RPS=y` is a kernel capability, not a setting. If the image enables a
full RPS mask through `packet_steering`/`rps` configs, non-offloaded packets
bounce between cores; with hardware offload that is extra work for no gain.
Test: `cat /sys/class/net/<dev>/queues/rx-*/rps_cpus` and compare PPS with the
mask cleared. Keep GRO on either way.

### 2.4 CPU governor / frequency
`emortal/cpufreq` exists in the tree. For a router, `performance` removes
frequency-ramp jitter at the cost of heat; `schedutil` is the safer default.
Test: p95/p99 RTT under a saturated upload with each governor, plus SoC
temperature over 30 minutes.

### 2.5 Subtarget PPE symbols
`CONFIG_QCOM_PPE` is not set for `qualcommax` (it belongs to `qualcommbe`
subtargets). Do not enable a symbol that the target's Kconfig does not own;
if a specific board's DTS advertises PPE, test it **per board** with a full
regression (NAT, bridge, wifi offload), because a wrongly enabled PPE path can
black-hole forwarded frames.

## 3. What not to do

* Do not copy the X86/ROCKCHIP `flow_offloading=0` change here: it would remove
  the only acceleration these targets have.
* Do not install `einat-ebpf` / `dpd-fastpath` here: they need the classic TC
  chain on an interface that the flowtable bypasses, and they are untested on
  PPE-capable silicon.
* Do not "tune" `nf_conntrack_max` without measuring the count first; the
  memory cost is per-entry and IPQ boards are RAM-limited.

## 4. How this is guarded now

`Scripts/Handles.sh` ends with a platform assertion: for every
`WRT_CONFIG` that is not X86/ROCKCHIP it checks the firewall4 patch still
contains `flow_offloading 1` and `flow_offloading_hw 1`, and prints
`offload: <CONFIG> keeps flow_offloading_hw=1` or a loud `!!` warning. That
turns a silent performance regression into a line in the build log.
