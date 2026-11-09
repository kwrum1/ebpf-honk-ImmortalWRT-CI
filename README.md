# DPD-FW-WRT

在 [VIKINGYFY/OpenWRT-CI](https://github.com/VIKINGYFY/OpenWRT-CI) 基础上做的
ImmortalWrt 云编译：**固件源码始终是上游 `VIKINGYFY/immortalwrt`**，本仓库只加
eBPF 数据面（`ebpf/`）、少量构建期改动和 X86/RK 的专属 UI/插件。

数据面本身（DPD、einat、honk p1 core）在 **[kwrum1/dpd-fw](https://github.com/kwrum1/dpd-fw)**
编译发布，本仓库只下载产物。

## 型号

| 工作流 | 配置 | 源码分支 | 数据面 | 说明 |
|---|---|---|---|---|
| `EBPF-WRT-ALL` | `X86` / `ROCKCHIP` | `owrt` | DPD TC/eBPF + einat + honk p1 core | 专属 UI（`luci-app-ebpf`）、ACL/QoS/多 WAN 等插件 |
| `QCA-PPE` | `IPQ60XX` / `IPQ807X`（WIFI-YES/NO） | `owrt` | 内核 flowtable / PPE | 原版包、原版 honk |
| `QCA-NSS` | 同上四个配置 | `main` | `qca-nss-drv` / ECM | 原版包、原版 honk |
| `MTK-ALL` | `MEDIATEK`（WIFI-YES/NO） | `owrt` | 原版 | 原版包、原版 honk |
| `WRT-TEST` | 任选 | 任选 | 按配置 | 手动单型号/只出 `.config` |

IPQ53XX / IPQ95XX 的配置保留但不在矩阵里：上游 `kmod-ath12k` 的依赖在
`owrt`/`main` 上都未满足，镜像组装会失败。

## 发布形式

- 每个平台一个 release，tag 为 `dpd-fw-wrt-<CONFIG>-<构建时间>`，例如
  `dpd-fw-wrt-X86-26.11.10-06.12.01`。
- 固件文件名同样以 `dpd-fw-wrt-` 开头，带目标、wifi 变体和时间：
  `dpd-fw-wrt-immortalwrt-x86-64-generic-squashfs-combined-none-26.11.10-06.12.01.img.gz`。
- 每个 release 附带 `provenance-<CONFIG>.txt`：源码提交、配置、内核、clang/libbpf；
  X86/ROCKCHIP 另含 eBPF ABI、BPF 对象哈希与源码树哈希、einat 资产名。

## 触发

| 方式 | 行为 |
|---|---|
| 定时 | `Auto-Clean` 每天 04:00（北京时间）清理旧 release/tag/工作流产物（保留数据面输入 `core-p1`），完成后通过 `workflow_run` 同时触发四个构建 |
| 手动 | Actions → 选工作流 → Run workflow；`WRT-TEST` 可只出配置（`TEST=true`） |
| 上游检查 | `UPSTREAM-CHECK` 每天核对构建期改动是否还匹配上游 |
| 编译自检 | `BPF-CHECK` 只编译 `ebpf/` 的 BPF 对象，1 分钟出结果 |

## 目录

```
Config/              各型号的 defconfig 片段
ebpf/                数据面包（X86/ROCKCHIP 专用）：router-dataplane、einat-ebpf、LuCI
patches/honk/        X86/RK 的 honk 源码补丁 + p1 core 构建
Scripts/             Packages.sh / Handles.sh / Settings.sh
.github/workflows/   薄工作流 + 公用核心 WRT-CORE.yml
```

## 维护

- honk：`X86/ROCKCHIP` 用上游包 + `patches/honk/honk-x86rk.patch` + 自建 `core-p1`；
  `IPQ/MTK` 用原版。补丁只带本项目改动的那部分，上游漂移会在 `Packages.sh` 直接报错。
- einat：二进制来自 `kwrum1/dpd-fw` 的 `einat-p2` release，哈希写死在
  `ebpf/einat-ebpf/Makefile`；返回码/回归由 dpd-fw 的 `einat` 工作流保证。
- 构建缓存包含 `.ccache`、`staging_dir/host*`、`staging_dir/tool*`；离线/弱网环境
  可把 `dl/` 里已有的源码包保留下来，`make download` 会直接复用、不再下载。
