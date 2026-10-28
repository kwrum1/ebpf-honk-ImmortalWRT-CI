# 内核选型（XanMod）与首启自动调优 —— 研究报告

> 触发（2026-10-18，用户提问）：
>
> 1. **"如果替换内核用 XanMod 内核、编译 OpenWrt 专用版本，提升大吗？成本怎么样？"**
> 2. **"单独开发出 x86/RK/IPQ 首启根据 CPU、内存、环境等针对路由环境自动优化的性能脚本，
>    找寻一切能够优化速度、吞吐、最简单收益最大的。"**
>
> **结论先行：**
>
> - **XanMod 不值得换。** 它是 **amd64-only 的桌面/游戏向内核**：我们的三个目标里
>   RK、IPQ60xx 两个是 aarch64，**它根本不存在**；对**转发型**路由器，它的招牌特性
>   （500 Hz 全抢占、sched_ext、futex2、块层多队列）收益≈0 甚至为负。它唯一跟我们沾边的
>   三样东西是 BBRv3、`nf_tables` full-cone NAT 补丁、`FLOWOFFLOAD` target —— 其中
>   **BBR 的 v1 我们勾一个包就有**（v3 是**单文件补丁**），后两者我们已经用
>   `einat-ebpf` + `dpd_fastpath` 自己实现了，而且更贴合本方案（独立表、独立 map、不进
>   fw4）。成本侧要常态化 rebase **517 个 generic-6.18 补丁 + 各 target 补丁**
>   （x86 4 / rockchip 198 / qualcommax 105），ARM 两个平台实际上办不到。→ **不换内核。**
>
> - **真正"最简单、收益最大"的清单在 §4.3**，全部是**零内核改动**（包选择 + sysctl）。
>   其中：
>   * 最大的一条（多核上把 NAPI/IRQ 负载摊开）**上游 OpenWrt 已经默认开了**，我们镜像实测
>     `S25packet_steering` 是 enabled；
>   * 第二条（**BBR + fq**）我们**只差两行包选择** —— OpenWrt 自带 `kmod-tcp-bbr`
>     （还顺带 `/etc/sysctl.d/12-tcp-bbr.conf`）和 `kmod-sched`（其 `KCONFIG` 里就有
>     `CONFIG_NET_SCH_FQ` / `sch_fq.ko`，这是 BBR 的首选 pacing qdisc）；
>   * 其余是 sysctl / ethtool / governor 级的小项，交给首启脚本按 CPU/内存/网卡自动定档。

证据等级标记（沿用 `docs/proxy-accel-coexistence.md`）：

| 标 | 含义 |
|---|---|
| **实测** | 本轮在真实内核源码树 / 真实镜像 rootfs 上看到的 |
| **上游文档** | 官方文档/仓库写的（含外网资料），未在我们机器上验证 |
| **待测** | 有明确判据、还没跑的 |

---

## 1. XanMod 到底是什么，跟我们相关的只有三样

XanMod 是一条 **amd64（x86-64）only** 的 mainline 派生内核：`-march=x86-64-v3` 级别的编译器
调优（LLVM Polly / 软件流水线）、面向交互延迟的抢占与定时器设置、桌面/游戏向的调度与内存
调优，外加一组外挂补丁。（**上游文档**：xanmod.org；v4 构建已停，官方理由是内核态用不上
AVX-512。）

逐条对"转发型路由器"判定：

| XanMod 的东西 | 对我们的意义 | 判定 |
|---|---|---|
| Preemptive Full Tickless **@500 Hz**、RCU boost、调度器面向交互延迟 | 我们实测是 `PREEMPT_NONE` + `HZ=100` + `NO_HZ_IDLE`。对**吞吐**导向的路由器，更高的定时器频率和更多抢占点 ≈ 纯开销 | **不采纳** |
| **BBRv3**（默认 CC） | 唯一真正和我们相关的内核算法。但见 §1.1：BBRv1 勾包即得，v3 只差一个文件 | 用**补丁**，不换内核 |
| x86-64-v3 构建 + LLVM Polly/软件流水线 | 只对 x86 有效；内核数据面是 C + **BPF JIT**（honk/dpd/einat 都在 JIT 里跑），编译器调优影响的是剩下的 C 路径，量级个位数 % | 可选，代价是内核长期维护 |
| `nf_tables` **RFC3489 full-cone NAT** 补丁 | 我们有 `einat-ebpf`（独立 nft 表 + 独立 eBPF map + 独立 procd 服务），且默认开 | **不需要** |
| nf **FLOWOFFLOAD** target | 我们**刻意**不用 nft offload（`.config` 里 `kmod-nft-offload` = `not set`，实测），加速走 `dpd_fastpath`（TC ingress classic filter） | **不需要** |
| sched_ext (SCX) / futex2 / ntsync / LRNG / ZSTD / 块层多队列 | 与路由器无关 | 不需要 |
| **MGLRU** | **mainline 早已有**：我们内核 `CONFIG_LRU_GEN=y` / `LRU_GEN_ENABLED=y`（实测） | 已经是我们的 |
| 架构 | 官方仓库与安装指南都写 **amd64 only**（ARM 不支持，**上游文档**） | **RK/IPQ 一票否决** |

### 1.1 BBR 的真实状态（决定 BBRv3 值不值得补）

| 事实 | 证据 |
|---|---|
| mainline 6.18.55 的 `net/ipv4/tcp_bbr.c` **仍是 BBRv1**：只有 `bbr_pacing_gain[]` / `bbr_cwnd_gain` / `bbr_full_bw_cnt`，**没有** `bbr3_*` 符号 | **实测**（`build_dir/.../linux-6.18.55/net/ipv4/tcp_bbr.c`） |
| BBRv1 自 4.9 就在 mainline；`bbr2`/`bbr3` 至今**不是**合法的 `tcp_congestion_control` 值，BBRv3 是 `google/bbr` 的 v3 分支补丁 | **上游文档**（2026-07 的资料仍这么写） |
| BBR 的首选 pacing qdisc 是 **`fq`**；没有 `fq` 时 BBR 退化为 TCP 层 pacing（4.20+） | **上游文档** |

结论：**要 BBR，勾 `kmod-tcp-bbr` 就有（BBRv1）；要 BBRv3，只 carry `net/ipv4/tcp_bbr.c`
一个文件**，完全不必碰内核基线。

---

## 2. "换内核"的成本：定量答案

在真实源码树里数字（**实测**，`find target/linux -name '*.patch'`）：

| 树 | 6.18 线补丁数 | 细分 | 说明 |
|---|---|---|---|
| `generic` | **517** | backport-6.18 **184** / hack-6.18 **81** / pending-6.18 **252** | 另有 6.12 线的 662 个（backport 430 / hack 63 / pending 169）同树共存 |
| `x86` | **4** | patches-6.18 | 最轻 |
| `rockchip` | **198** | patches-6.18 | vendor BSP，对内核 API 版本敏感 |
| `qualcommax` | **105** | patches-6.18 | 同上（ipq50xx/ipq60xx/ipq807x） |

OpenWrt 的补丁语义决定了这件事的代价：`backport-*` 是把**更新的上游实现反向移植**，
`pending-*` 是**还没上游的**，`hack-*` 是 **OpenWrt 特有的**。换成 XanMod（另一套基线 +
它自己的一堆外挂补丁）意味着：

1. `backport-*` 与 XanMod 自带的同文件不同版本**必然冲突**，要逐个重写；
2. 每次 OpenWrt 内核小版本跳动（6.18.x → 6.18.y，以及 6.12/6.18 双线共存）都要重做一遍；
3. rockchip/qualcommax 的 vendor 补丁对内核版本/API 有硬要求 —— **ARM 侧实际上不可行**；
4. 还得自建产物、APT 之外的分发与验证链路。

**判定：不做。** 收益（x86 上可能个位数 % + BBRv3）≪ 长期持有成本。

---

## 3. 我们真正该动的最小内核面（按收益/成本排序）

| # | 手段 | 收益 | 成本 | 状态 |
|---|---|---|---|---|
| 1 | `kmod-tcp-bbr`（BBRv1）+ `kmod-sched`（内含 `sch_fq`）+ `net.core.default_qdisc=fq` | 代理链路（长肥/丢包）吞吐提升明显；honk 出站 socket 跑在主机内核，直接受益 | **0 内核改动**（`Config/GENERAL.txt` 两行） | **本轮建议做** |
| 2 | TCP/内存 sysctl 组（§4.3） | 中 | 0 | 交给首启脚本 |
| 3 | `packet_steering`（RPS/XPS/IRQ 负载摊开） | **大**（x86 多核 pps） | 0 | **上游已默认开（实测）** |
| 4 | NIC ring / coalescing / offload（ethtool） | 中（高 pps 丢包） | 0 | 交给首启脚本 |
| 5 | CPU governor = `performance` | 小（延迟一致性） | 0 | 交给首启脚本 |
| 6 | `net.ipv4.tcp_mtu_probing=1` | 修 PMTU 黑洞（我们上一轮已踩到 MSS/PPPoE 问题） | 0 | 交给首启脚本 |
| 7 | BBRv3 单文件补丁 | 小-中 | 1 文件 × 每次内核跳版 | 可选，先量 BBRv1 |
| 8 | `HZ=1000` / 全抢占 | 对转发**负收益** | 内核补丁 | **不做** |
| 9 | `einat` / `dpd` / `CAKE` / `SmartDNS` 内部参数 | 视场景 | 0 | 首启脚本只提示，不擅自改 |

> 顺带回答一个隐含问题：**"我们内核面还有没有漏"?** 没有大漏。`RPS/XPS/BQL/RFS/LRU_GEN/
> HIGH_RES_TIMERS` 都已开（实测）；数据面该在 eBPF 里的（NAT、ACL、加速）都已经在 eBPF 里；
> 剩下能拿的都是 sysctl/ethtool 级。

---

## 4. 第二问：首启自动调优脚本

### 4.1 先看现场，避免重复造轮子（全部实测）

| 现场事实 | 证据 | 对我们的影响 |
|---|---|---|
| 镜像**已有** `/etc/init.d/packet_steering`，且 `etc/rc.d/S25packet_steering` **已 enable** | 镜像 rootfs `etc/rc.d/` | **"最大的一条"上游已给**：它把 NAPI/IRQ 任务按负载 `taskset` 摊到 CPU，并给每个 rx 队列写 `rps_cpus`/`rps_flow_cnt`（`usr/libexec/network/packet-steering.uc`，用 busybox `taskset`）。我们**不要重写它**，只在它没覆盖的地方补位 |
| 镜像**已有** `/etc/init.d/sysctl`，**START=11**，先于 `network`(S20) | 镜像 `etc/init.d/sysctl` | 它 `for CONF in /etc/sysctl.d/*.conf /etc/sysctl.conf; do sysctl -e -p "$CONF"; done`，并已按 MemTotal 设 `vm.min_free_kbytes`、关 `accept_ra` → **我们把 sysctl 放进 `/etc/sysctl.d/` 就会在任何网卡创建之前生效**（`default_qdisc` 只有这样设才有意义） |
| 内核：`RPS=y RFS_ACCEL=y XPS=y BQL=y NET_RX_BUSY_POLL=y NET_FLOW_LIMIT=y HZ=100 PREEMPT_NONE HIGH_RES_TIMERS=y NET_SCH_FQ_CODEL=y DEFAULT_NET_SCH="fq_codel" CAKE=m INGRESS=m CLS_BPF=m ACT_BPF=m LRU_GEN=y` | `linux-6.18.55/.config` | 可调面已经具备；**没有 `CONFIG_NET_SCH_FQ`** → 要 `fq` 必须再勾 `kmod-sched` |
| 工具齐：`/sbin/ip`→`ip-full`、`/sbin/tc`→`tc-bpf`、`/usr/sbin/ethtool`（真 ethtool）、`/usr/sbin/bpftool`、busybox `sysctl`/`taskset` | 镜像 rootfs `ls -l` | 脚本可以用 iproute2 语义 |
| **CAKE 占着 WAN 根 qdisc**；honk 自己会设 `rp_filter/accept_local/ip_forward/rmem_max/wmem_max` | `router-qos.sh`；`strings honk-core` | **调优脚本绝不能跟这两家抢**：不碰 WAN 的 qdisc、不写 honk 写过的键（或只"抬升不降低"） |
| 出厂 `firewall` 有 `option mtu_fix 1`，但**加速路径（dpd 接管）绕过 fw4**，MSS clamp 不生效 | 上一轮 F5 | MSS 补偿要么做进 dpd（O-4），要么用 `tcp_mtu_probing=1` 兜住客户端侧 |

### 4.2 设计原则

1. **只写自己的东西**：自己的 uci `/etc/config/router_tuning`、自己的 sysctl
   `/etc/sysctl.d/29-router-tuning.conf`、自己的 procd 服务 + hotplug。
   **不改** `/etc/config/{network,dhcp,firewall}`（沿用项目红线）。
2. **不抢所有权**：CAKE 的 WAN qdisc、honk 的 `rp_filter/forwarding/rmem_max`、
   上游 `packet_steering` 的 `rps_cpus` —— 一律"只补空、只抬升"。
3. **幂等 + 可回滚**：施加前把原值存 `/etc/router-tuning.state`，`--restore` 原样退回。
4. **按环境定档**（这就是"根据 CPU/内存/环境自动优化"）：
   | 探测项 | 来源 | 用途 |
   |---|---|---|
   | CPU 核数 / 是否 SMP | `/sys/devices/system/cpu/online` | RPS/XPS 掩码、IRQ 轮转、backlog 档位 |
   | 内存 | `/proc/meminfo` `MemTotal` | 缓冲档位（≤256 MB 保守 / ≤1 GB 标准 / >1 GB 激进） |
   | 虚拟化 | DMI / `/sys/class/net/*/device/uevent` `virtio` | guest 里 RPS 价值低、ring 由宿主决定 → 跳过相关项 |
   | WAN 类型 | `ubus call network.interface.wan status` / `/etc/config/network`（**只读**） | PPPoE/DHCP/static → `tcp_mtu_probing`、MTU 相关 |
   | 网卡驱动 / 队列 / 速率 | `ethtool -i/-l/-g/-k/-C` | ring、coalescing、offload、XPS 是否多队列 |
   | 架构 | `uname -m` + `/proc/cpuinfo` model | x86（intel_pstate/igb/r8169）vs RK（stmmac，4×A55）vs IPQ（NSS/nss-dp，别乱动） |
5. **只做有判据的事**：每项都要能在审计里看到"生效了/跳过了/为什么"。

### 4.3 杠杆清单（"最简单收益最大"的实际内容）

**A. 包选择级（零内核改动，收益最直观）**

| 项 | 具体动作 | 预期 | 风险 |
|---|---|---|---|
| BBR | `CONFIG_PACKAGE_kmod-tcp-bbr=y`；包自带 `/etc/sysctl.d/12-tcp-bbr.conf`（`tcp_congestion_control=bbr`） | 代理/长肥链路吞吐↑，丢包恢复快 | 个别老 NAT 设备对 BBR 不友好（可 `--restore`） |
| `fq` pacing | `CONFIG_PACKAGE_kmod-sched=y`（含 `CONFIG_NET_SCH_FQ`→`sch_fq.ko`） | BBR 的 pacing 走 qdisc，更省 CPU、更顺 | 多 ~10 个小 .ko |
| 默认 qdisc | `net.core.default_qdisc=fq`（脚本先 `modprobe sch_fq` 成功才写） | 新网卡自动用 fq | 写之前必须确认 `sch_fq` 可加载 |

**B. sysctl 级（随内存档位缩放）**

| 键 | 保守(≤256M) | 标准(≤1G) | 激进(>1G) | 说明 |
|---|---|---|---|---|
| `net.core.netdev_max_backlog` | 2048 | 4096 | 8192 | 软中断跟不上时先在这里体现 |
| `net.core.netdev_budget` | 300 | 600 | 900 | 每次软中断处理量 |
| `net.core.somaxconn` | 1024 | 4096 | 8192 | |
| `net.core.rmem_max`/`wmem_max` | 4M | 8M | 16M | 只"抬升不降低"（honk 也设这两个） |
| `net.ipv4.tcp_rmem`/`tcp_wmem` | 4K/64K/2M | 4K/128K/8M | 4K/256K/16M | |
| `net.ipv4.tcp_slow_start_after_idle` | 0 | 0 | 0 | 空闲后不重置 cwnd |
| `net.ipv4.tcp_mtu_probing` | 1 | 1 | 1 | **PPPoE / ICMP 被封的 PMTU 黑洞** |
| `net.ipv4.tcp_fastopen` | 3 | 3 | 3 | |
| `net.ipv4.tcp_tw_reuse` | 1 | 1 | 1 | |
| `net.ipv4.tcp_fin_timeout` | 30 | 30 | 30 | （出厂已 30） |
| `net.ipv4.ip_local_port_range` | 10240 65535 | 同 | 同 | **full-cone NAT 并发端口容量** |
| `net.ipv4.udp_rmem_min`/`udp_wmem_min` | 16384 | 32768 | 65536 | UDP 代理/QUIC |
| `net.ipv4.tcp_notsent_lowat` | — | 131072 | 131072 | 缓解上行 bufferbloat；**没开 CAKE 才建议** |

**C. 网卡/中断级（ethtool + sysfs，只对有 `device` 的物理口）**

| 项 | 动作 | 说明/风险 |
|---|---|---|
| ring | `ethtool -G <dev> rx <max> tx <max>`（先 `-g` 读上限再夹取） | 高 pps 时显著减少 drop；内存代价小 |
| coalescing | 标准档：`-C rx-usecs 16`（若支持 adaptive 则先关 adaptive）；延迟档：0/关 | 吞吐 vs 抖动取舍，做成 profile |
| offload | 确保 `gro/gso/tso/rx/tx on`；**LRO 保持默认** | 转发场景 LRO 可能把超大段带进转发路径 |
| txqueuelen | WAN 口 1000→5000 | 配合 PPPoE/CAKE，别让 qdisc 前就丢包 |
| **XPS** | 多队列时按 CPU 数写 `xps_cpus` | 上游 `packet_steering` **不碰** XPS → 这是真正的补位点 |
| **RPS** | 默认交给上游 `packet_steering`；**仅当** `rps_cpus` 全 0 且 steering 关闭时才补 | 不抢所有权 |
| IRQ 亲和 | 同上，默认交给 upstream；仅补位 | |

**D. CPU / 平台级**

| 平台 | 动作 |
|---|---|
| x86 | `intel_pstate`/`acpi-cpufreq` → `performance`（若可用）；虚拟化 guest 跳过 |
| RK（aarch64 4×A55） | 有 cpufreq 就 `performance`；RPS 掩码按 4 核；stmmac 的 ring 探测后设 |
| IPQ60xx | **保守**：NSS offload 自管数据面，只做 sysctl 轻档 + 如果存在 `nss-dp` 就不要用 ethtool 乱改队列 |

**E. 我们的栈（只提示，不擅改）**

| 项 | 现状 | 建议 |
|---|---|---|
| MSS clamp 缺口 | 加速流绕过 fw4 的 `mtu_fix` | ① `tcp_mtu_probing=1` 兜客户端；② 正解是 O-4（dpd 里做 MSS） |
| SmartDNS / dnsmasq 缓存 | SmartDNS 自己在 6053，dnsmasq 只做转发 | dnsmasq `cache-size` 只能走**构建期默认**或 `conf-dir`，**运行期不改 `/etc/config/dhcp`** |
| einat map / dpd 模式 | ABI 3，stateless/stateful | 不因调优改所有权 |

### 4.4 怎么证明它有效（A/B）

- `build/qemu-tuning-audit.sh`：boot → **审计 dump**（所有上面这些键的当前值 + `rps_cpus`/
  `xps_cpus`/ring/coalescing/governor/IRQ 分布/qdisc）→ **基线吞吐**（宿主 http 服务 +
  客户端 netns 直穿路由器拉大文件）→ **施加杠杆** → **复测** → 打印 delta。
- 已知限制：宿主**无 KVM**，QEMU 是 TCG、网卡是 virtio → 绝对吞吐不代表真机；A/B **相对**
  delta 仍有指示性，且审计 dump 本身就是"环境适配正确性"的证明。
- 进 `check-plat-artifacts.sh` 的静态断言：包存在、`/etc/sysctl.d/29-router-tuning.conf`
  存在且值随内存档位正确、`/etc/rc.d/S*router-tuning` 存在、脚本可执行位正确。

### 4.5 交付物（本轮的）

| 文件 | 内容 |
|---|---|
| `ebpf/router-tuning/` | 首启自动调优包（uci + 引擎 + procd + hotplug + uci-defaults + README） |
| `docs/kernel-and-tuning-research.md` | 本文 |
| `build/qemu-tuning-audit.sh` | 审计 + A/B 测试台（staged，待跑） |
| `dist/…` | 需要时随 feed 补丁一起出（本包属 `ebpf/`） |

---

## 5. 结论与下一步

1. **内核不换。** 想要 BBR 就勾两个包（`kmod-tcp-bbr` `kmod-sched`）+ `default_qdisc=fq`；
   想要 BBRv3 就 carry `net/ipv4/tcp_bbr.c` 一个文件。XanMod 的其余部分对转发路由器是噪声，
   且 ARM 两个平台根本无法使用。
2. **首启调优**按 §4.3 落地成 `router-tuning` 包：**默认只做"零风险且可验证"的那一档**
   （sysctl 档位 + `fq`/BBR 探测 + XPS 补位 + ring 夹取 + governor + MTU probing），
   每一项都能 `--report` 看到状态，`--restore` 能退。
3. **下一步实测**：跑 `qemu-tuning-audit.sh` 拿到"现状审计"，再决定是否把 BBR 包选择写进
   `Config/GENERAL.txt`（需要一次 x86 重建）；同时补 O-4（dpd MSS）把 `tcp_mtu_probing`
   从"兜底"降级为"保险"。
