# ebpf-honk-ImmortalWRT-CI

在 [VIKINGYFY/OpenWRT-CI](https://github.com/VIKINGYFY/OpenWRT-CI) 的基础上做的固件云编译流水线：
**固件源码始终是上游 `VIKINGYFY/immortalwrt`**，本仓库只额外提供 eBPF 数据面（`ebpf/`）和少量构建期改动。

- **X86 / ROCKCHIP**：上游 `@owrt` + 本仓库 `ebpf/` 数据面（einat + dpd + ACL + QoS + DNS + luci-front + LuCI 页）。
- **IPQ60XX / IPQ807X**：同一批设备出两版 —— `QCA-PPE`（`@owrt`，内核 flowtable/PPE）和 `QCA-NSS`（`@main`，`qca-nss-drv` 固件加速）。
- **IPQ53XX / IPQ95XX**：只有 `QCA-NSS`（`@main`；`owrt` 的 `target/linux/qualcommbe` 没有 `image/`，出不了 PPE 版）。
- **MEDIATEK**：上游 `@owrt`，原版包集。

### 我该刷哪个？

| 设备 | 选这个 | 说明 |
|---|---|---|
| x86 软路由 / 虚拟机 | `EBPF-WRT-ALL` → `X86` | eBPF 数据面 + pingora 前端 |
| RK3399 / RK3568 等 ARM64 | `EBPF-WRT-ALL` → `ROCKCHIP` | 同上，aarch64 |
| IPQ60xx / IPQ807x（要 PPE） | `QCA-PPE` | 内核 flowtable，兼容性最好 |
| IPQ60xx / IPQ807x（要 NSS 固件） | `QCA-NSS` | 同型号，`@main`，NSS 驱动栈 |
| IPQ53xx / IPQ95xx | `QCA-NSS` | 只有 NSS 版 |
| MediaTek | `MTK-ALL` | 原版 |

---

## 1. 产物矩阵

| 工作流 | 配置 | 源码 | 分支 | 数据面 |
|---|---|---|---|---|
| `EBPF-WRT-ALL` | `X86`, `ROCKCHIP` | `VIKINGYFY/immortalwrt` | `owrt` | 本仓库 `ebpf/`（eBPF） |
| `QCA-PPE` | `IPQ60XX-WIFI-YES/NO`, `IPQ807X-WIFI-YES/NO` | `VIKINGYFY/immortalwrt` | `owrt` | 内核 flowtable / PPE |
| `QCA-NSS` | 同上四个 + `IPQ53XX`, `IPQ95XX` | `VIKINGYFY/immortalwrt` | `main` | `qca-nss-drv` / ECM |
| `MTK-ALL` | `MEDIATEK-WIFI-YES/NO` | `VIKINGYFY/immortalwrt` | `owrt` | 原版 |
| `WRT-TEST` | 任选一个 | 任选 | `owrt` / `main` | 按配置 |

发布 tag：`<CONFIG>-<源码所有者>-<分支>-<构建时间>`，例如

```
X86-VIKINGYFY-owrt-26.10.28-06.12.01
IPQ807X-WIFI-YES-VIKINGYFY-main-26.10.28-06.12.44
```

每个 release 都带 `provenance-<CONFIG>.txt`：

```
config / source / branch / commit / commit_full / commit_date / target / kernel
ebpf_abi / ebpf_object sha256+size / ebpf_src_tree sha256 / clang / libbpf / built_at
```

（`ebpf_*` 只出现在 X86/ROCKCHIP 的 provenance 里。）

---

## 2. 触发方式

| 方式 | 行为 |
|---|---|
| 定时清理 | `Auto-Clean` 每天 22:00 UTC（可手动）删掉上一轮 release/tag/运行记录 |
| 定时编译 | `Auto-Clean` 完成后，`EBPF-WRT-ALL` / `QCA-PPE` / `QCA-NSS` / `MTK-ALL` 通过 `workflow_run` **同时**触发 |
| 缓存清理 | `Cache-Clean` 每周日 20:00 UTC `gh cache delete --all` |
| 数据面快编译 | `BPF-CHECK`：每周 + 手动，1 分钟编译 `ebpf/` 的 BPF 对象与 `dpdctl` |
| NAT 加速构建 | `EINAT-BUILD`（手动 / 补丁变更）：上游源码（pin 提交）+ p1/p2 补丁构建 einat，发布前在 netns 里跑 EIM/EIF/ICMP/20MB TCP 回归，产物发在固定 tag `einat-p2` |
| 上游锚点检查 | `UPSTREAM-CHECK`：每天 18:15 UTC，对 `owrt` / `main` 各 clone 一次上游，核对构建期改动还匹配不匹配 |
| 手动 | Actions → 选工作流 → Run workflow（`WRT-TEST` 默认只出 `.config`） |

保留策略是上游的默认值（`releases_keep_latest: 0`、`workflows_keep_day: 0`）：只留当天产物。想留几天改 `Auto-Clean` 里那一行即可。

---

## 3. 目录

```
.github/workflows/   Auto-Clean / Cache-Clean / EBPF-WRT-ALL / QCA-PPE / QCA-NSS
                     MTK-ALL / WRT-TEST / WRT-CORE / BPF-CHECK / UPSTREAM-CHECK / EINAT-BUILD
ebpf/                数据面包（构建时拷进 package/ebpf/，只给 X86/ROCKCHIP）
  router-dataplane     dpd_fastpath.bpf.c + dpdctl + ebpf-mwan + 门禁/看门狗/回归脚本
  router-acl           WAN eBPF ACL（acl.bpf.c + aclctl）
  router-dns           SmartDNS 独占 :53、租约派生上游、honk DNS 交接
  router-qos           WAN root qdisc（cake/fq_codel，无限速）
  router-tuning        首启 sysctl/NIC/BBR 调优（throughput/balanced/latency）
  luci-front           :80/:443 前端（pingora，x86_64/aarch64 预编译）
  luci-app-ebpf        菜单、端口控制页、多 WAN 负载页、posture
  einat-ebpf           Full Cone NAT44（上游 release 二进制）
Config/              每个目标的 .config 片段
  GENERAL.txt          X86 / ROCKCHIP（eBPF 数据面那一套）
  GENERAL-STOCK.txt    IPQ / MTK（原版包集）
  X86 / ROCKCHIP / IPQ60XX-* / IPQ807X-* / IPQ53XX / IPQ95XX / MEDIATEK-* / TEST
Scripts/
  Packages.sh         第三方包 + 数据面拷贝（只 X86/ROCKCHIP）+ honk 资产
  Settings.sh         .config 生成、LAN IP/WiFi/主机名
  Handles.sh          构建期对上游文件的修补（X86/RK 段单独门控）
  upstream-check.sh   核对上游锚点（UPSTREAM-CHECK 调用）
  verify-packages.sh  固件包清单闸门（手动运行）
```

> 数据面只在本仓库的 `ebpf/`；固件源码只来自上游 `VIKINGYFY/immortalwrt`，流水线不引用任何本仓库的源码分支。

---

## 4. 构建流水线（`WRT-CORE.yml`）

| 步骤 | 做的事 |
|---|---|
| Initialization Environment | 官方依赖脚本、`/mnt/build_wrt` 软链到 `./wrt` |
| Initialization Values | 解析 `WRT_TARGET` / `WRT_INFO` / 日期 |
| Clone Code | `git clone --depth=1 --branch $WRT_BRANCH $WRT_REPO ./wrt`；X86/ROCKCHIP 额外断言本仓库有 `ebpf/router-dataplane/src` |
| Check Caches | 缓存 `ccache` + `staging_dir/host*`/`tool*` |
| Update Feeds | `feeds update -a && install -a` |
| Custom Packages | `Packages.sh` + `Handles.sh`（cwd = `wrt/package`） |
| Custom Settings | `Settings.sh` 生成 `.config`，`make defconfig && make clean` |
| Download Packages | `make download -j` |
| Compile Firmware | `make -j || make -j1 V=s` |
| Package Firmware | 收集 `bin/targets`，按 `CONFIG-OWNER-BRANCH-DATE` 改名 |
| Build Provenance | 写 `provenance-<CONFIG>.txt` + release 正文的 `WRT_PROV_LINE` |
| Release Firmware | `softprops/action-gh-release` |

---

## 5. eBPF 数据面（X86 / ROCKCHIP）

### 5.1 为什么关掉 flow offload

软件/硬件 flow offload 会把首包之后的流量交给 netfilter flowtable，**绕过 TC**；而本方案的 NAT 与快路径都在 TC/eBPF 上，两者互斥。所以 eBPF 镜像里：

- `/etc/config/firewall` 默认 `flow_offloading=0`、`flow_offloading_hw=0`；
- `kmod-nft-offload` 从 `DEFAULT_PACKAGES` 与 firewall4 依赖里移除；
- 都是**构建期默认值**，不是运行期覆盖。IPQ/MTK 保持上游默认（`owrt` 为 1，`main` 为 0，NSS 走 ECM）。

### 5.2 钩子顺序（实测）

```
WAN ingress : honk TCX(wan_ingress) → einat TCX(reverse SNAT) → router-acl(classic 90) → dpd(classic 100)
LAN ingress : honk TCX(lan_ingress) → dpd(classic 100)
WAN egress  : honk TCX(wan_egress) → einat TCX(SNAT) → router-acl(classic 90) → CAKE root qdisc
```

TCX 先于 classic `cls_bpf`：honk 判给代理的流到不了 dpd；classic 链按 pref 排序，router-acl 先表态。dpd 挂载时若发现有人排在自己后面，会自动降级 `observe`。

### 5.3 组件

| 组件 | 来源 | 作用 | 默认 |
|---|---|---|---|
| **einat-ebpf** | `EHfive/einat-ebpf` v0.1.11 静态二进制 | TC 上的 Full Cone NAT44（EIM+EIF），不依赖 conntrack | 端口段 20000-29999 / 30000-39999（多 WAN 各一段）；本仓库打 p1/p2 性能补丁（少一次解析、dest_config 快路径、已建立 TCP 的 CT 快路径）并由 EINAT-BUILD 构建 + netns 回归 |
| **dpd-fastpath** | `ebpf/router-dataplane` | TC ingress 快路径；**不做 NAT**，只加速已建立的直连转发 | `mode=stateful`，`downlink=1`，`flow_refresh_ms=250` |
| **router-acl** | `ebpf/router-acl` | WAN eBPF ACL/guard，丢弃无主入站 | `guard` + `import_firewall=1` |
| **router-qos** | `ebpf/router-qos` | WAN root qdisc，无限速：≤1G `cake diffserv4 nat`，更快 `fq_codel`；`profile=auto/throughput/latency` | 开启，无 UI |
| **router-tuning** | `ebpf/router-tuning` | sysctl/BBR/ring/coalescing/XPS/governor；`mode=throughput/balanced/latency` | `profile=auto`，`mode=balanced` |
| **router-dns** | `ebpf/router-dns` | SmartDNS 独占 :53，dnsmasq 端口 0；上游来自租约；honk DNS 交回本地 | 开启 |
| **luci-front** | `ebpf/luci-front` | :80/:443（HTTP/2、TLS、安全头），`/cgi-bin`、`/ubus` 反代到 uhttpd | 两架构自动选 |
| **luci-app-ebpf** | `ebpf/luci-app-ebpf` | 菜单（DNS/代理/防火墙/多 WAN 负载）、端口控制、多 WAN 页、`ebpf-posture` | `firewall.ebpf999` 默认开且不在 UI 显示 |

### 5.4 ABI 9（2026-10-28）

命中路径每包只需 3 次 map 查询（`dpd_cfg`、`dpd_stats` 单块、`dpd_flows`）：

- `dpd_stats` 是每 CPU 一个整块；
- 流表项记录**代际号**（`ebpf epoch`），链路/地址/路由/WAN 表变化时 `dpdctl bump` 一次全失效；
- 出口方式（L2 / dev / neigh）学习时定一次；
- 时间戳按 `flow_refresh_ms` 限频刷新；
- GSO 分段长度按 `ihl + L4 头 + gso_size` 计算；
- IPv6/:53/DHCP/非单播在 FIB 查询**之前**拒绝。

回归脚本：`/usr/libexec/dpd-regress.sh --target <上游可达地址>`（ABI 对齐、observe/off/卸载 四态仍转发、门禁计数、epoch 失效、MTU 1500/1492/1400 矩阵、钩子清单）。

### 5.5 代理 + 加速共存（honk p1）

honk 的 `lan_ingress_l2` 是 TCX，dpd 是 classic。上游 core 的 direct 出口返回 `TC_ACT_OK`，整条 classic 链被跳过，dpd 只能 `observe`。

`ebpf` 镜像用的 honk 来自 `kwrum1/openwrt-honk@main`，构建期打 **p1** 补丁（`ci/patches/honk-direct-unspec.py`，不改上游源码）：

1. 4 个 direct 出口返回 `TC_ACT_UNSPEC` 并打 `DIRECT_UNSPEC_MARK`；
2. bridge 二次遍历看到该 mark 时跳过分类、仍返回 `UNSPEC`；
3. proxy 仍 redirect 到 `dae0`，block 仍 `SHOT`。

dpd 通过 `/usr/share/honk/direct-unspec` 判断 core 是否带 p1；没有就保持 `observe`。

| 流 | honk | dpd |
|---|---|---|
| direct | `UNSPEC` + mark | 进 classic，正常加速（含多 WAN 选路） |
| proxy | redirect `dae0` | 不进 classic |
| block | `SHOT` | 不进 classic |

---


### 5.6 einat 补丁（p1 / p2）与每包收益

`einat-ebpf` 不再直接下载上游 release，而是由 `EINAT-BUILD` 从上游源码（pin 到 `ba647ce6`）打补丁后构建：

| 补丁 | 内容 | 收益 |
|---|---|---|
| `patches/einat-perf.py`（p1） | 构建用上游 `static` 预设（不带 `ipv6` feature）；并且 v4-only 构建里 `get_is_ipv4()` 仍解析一遍 L2/L3，`parse_packet()` 紧接着又解析同一份头 | BPF 程序里没有 NAT66/v6 解析分支；每包每方向少一次 L2/L3 头解析 |
| `patches/einat-perf-p2.py`（p2）① | `dest_config` 只有 WAN 地址一个条目时，用 32 位目的地址比较代替 LPM 查表 | 出向每包少一次 LPM 查表 |
| `patches/einat-perf-p2.py`（p2）② | 已建立 TCP 连接的数据包，1 秒内跳过 CT 查表 + `bpf_timer_start()` | TCP 数据包少一次 hash 查表 + 一次带锁的定时器重排 |

#### 每包 map 开销（v4，单个 einat 实例）

| 路径 | 上游 | 现在 |
|---|---|---|
| WAN egress，普通流量 | LPM(dest) + LPM(src) + hash(binding) + hash(ct) = **4** | LPM(src) + hash(binding) + hash(ct) = **3** |
| WAN egress，已建立 TCP 数据 | 同上 + 每包 `bpf_timer_start` | LPM(src) + hash(binding) = **2**，定时器刷新最多 1 次/秒/流 |
| WAN ingress，普通流量 | LPM(dest) + hash(binding) + hash(ct) = **3** | **3**（不变） |
| WAN ingress，已建立 TCP 数据 | 同上 + 每包 `bpf_timer_start` | LPM(dest) + hash(binding) = **2**，定时器刷新最多 1 次/秒/流 |
| 每包固定开销 | `get_is_ipv4` + `parse_packet` 两次解析 | 一次解析 |

LPM 是这三种 map 里最贵的一种（前缀树遍历），hash 命中要算 jhash + 桶，`bpf_timer_start` 要拿定时器锁并重排 hrtimer——所以 ② 省的不只是一次查表，主要是每包一次带锁的定时器操作。

按 1 Mpps 粗算（只是算术，不是实测）：出向普通流量每秒少 100 万次 LPM 查表；已建立 TCP 每秒少 100 万次 hash 查表，定时器重排从"每包一次"降到"每流每秒最多一次"。

#### 等价性边界

* p2 ① 只在「dest_config 恰好一个条目、等于默认外部地址、且为满前缀」时启用比较：此时 LPM(daddr) 只可能在 `daddr == 外部地址` 时命中，比较结果与查表**完全等价**。其它情况（多地址、非满前缀、空表）分别落到 mode 2 / mode 0，其中 mode 2 就是上游行为；表更新期间先写 mode 2 兜底再写真实值。
* p2 ② 只跳过「只会刷新定时器」的路径：`CT_ESTABLISHED` + TCP 数据包。SYN/FIN/RST、ICMP 错误、UDP/ICMP、任何非 ESTABLISHED 状态全部照旧走慢路径；`map_ct` 仍是状态/超时/refcount 的唯一来源，映射分配和全锥行为一行没动。实际差异只是 TCP 定时器刷新从每包一次变成最多每秒一次（7200 s 的超时最多提前 <1 s 到期）。
* 两者都不改变 NAT 映射：外部端口分配、binding/ct 的 refcount 与 seq、hairpin/dest_config 语义都保持上游逻辑。

#### 怎么自己量

`bpftool prog profile id <egress_snat 的 prog id> duration 5` 看每包指令/cycles，或 `iperf3 -P 8` 对比两个镜像。本项目**不出 perf 数字**：实验机是共享 ESXi，抖动 ±40%，量出来的差值说明不了问题。

#### 发布门禁

`EINAT-BUILD` 的 `e2e (netns)` 作业在发布前跑 `patches/einat-e2e-nat.sh`：EIM（同一本地端口对两个 peer 只有一种外部端口）、EIF（没通信过的 peer 仍能打到映射端口）、ICMP、20MB TCP 传输（全程走 CT 快路径）。任一失败就不发布。


## 6. 配置分层

| 文件 | 谁用 | 内容 |
|---|---|---|
| `Config/GENERAL.txt` | X86 / ROCKCHIP | eBPF 包集、关 docker/upnp/iptables、关 flow offload、odhcpd 接管 |
| `Config/GENERAL-STOCK.txt` | IPQ / MTK | 原版 CI 的包集 |

```sh
X86 / ROCKCHIP  -> Config/<CONFIG>.txt + Config/GENERAL.txt
其它            -> Config/<CONFIG>.txt + Config/GENERAL-STOCK.txt
*TEST*          -> 只用 Config/<TEST>.txt
```

平台 `Config/*.txt`（IPQ60XX/807X/53XX/95XX、MEDIATEK、ROCKCHIP）直接取自上游 CI，设备表跟着上游走。

---

## 7. 脚本要点

### 7.1 `Packages.sh`

- 第三方包只保留真正进固件的五个：`aurora`、`aurora-config`、`honk`、`v2ray-geodata`、`partexp`。
- honk 单分支：`kwrum1/openwrt-honk@main`（含 p1 core 与 `.lan/.local` DNS 规则）。
- honk 的 `generated-stage.mk` / `generated-provenance.json` / `generated-doona-stage.mk` 是 release 资产，按 `CORE_COMMIT` 下载并改写 URL，x86_64 资产先 HEAD 预检。
- 数据面：`X86|ROCKCHIP` 时从 **本仓库 `ebpf/`** 拷到 `package/ebpf/`，同时算出 `DPD_SRC_SHA`；找不到直接失败。其它平台打印一行跳过。

### 7.2 `Settings.sh`

- `.config` 唯一生成点。
- `WRT_IP` 为空时保留上游默认，并断言 LAN 地址不为空。
- qualcommax 的 `KERNEL_SIZE` 只在该目录存在时修改。
- WiFi SSID/密码/国家、主机名按工作流输入写入。

### 7.3 `Handles.sh`

- 通用段：aurora 主题、mini-diskmanager 菜单修复。
- `if [[ "$WRT_CONFIG" == "X86" || "ROCKCHIP" ]]` 段：x86 DRM 裁剪、flow offload 归零、`kmod-nft-offload` 移除、odhcpd/dnsmasq 接管、honk NFQUEUE 裁剪。
- 末尾断言：非 X86/RK 的配置必须仍带 `flow_offloading` 两行，并打印实际值（`owrt`=1，`main`=0）。
- 所有 sed 幂等；锚点缺失由 `UPSTREAM-CHECK` 每天核对。

### 7.4 `upstream-check.sh`

```sh
sh Scripts/upstream-check.sh <fresh clone of VIKINGYFY/immortalwrt>
```

核对上面所有 sed 依赖的行（x86 Makefile、firewall4 patch、target.mk、dnsmasq/odhcpd）。返回非零 = 上游改了，需要更新对应脚本段落。

---

## 8. 与上游的关系

**不是 fork，不需要合并上游。**

- 固件 = 上游 `VIKINGYFY/immortalwrt`（`owrt` / `main`），每次构建 clone 最新。
- 我们只加：`ebpf/`（新包，上游没有）、`Config/GENERAL*.txt`、构建期锚点修补。
- 上游改动会由下一次构建自动带上；锚点变了 `UPSTREAM-CHECK` 会报。
- 详见 [`docs/upstream.md`](docs/upstream.md)、[`docs/ci-layout.md`](docs/ci-layout.md)、[`docs/ipq-offload-notes.md`](docs/ipq-offload-notes.md)。

---

## 9. 已知限制

- **eBPF 只覆盖 X86/ROCKCHIP**；IPQ/MTK 走各自的原厂加速。
- **IPv6 加速（`option ipv6 '1'`，默认开）**：出站发起的 v6 TCP/UDP 流，上下行都进快路径；回程条目在学习上行流时用该帧的 L2 预置（不依赖 WAN 侧 FIB/邻居），反向首包仍过栈让 conntrack 先看到。入站主动发起的 v6 连接、带 802.1Q 标签的帧、扩展头/分片/组播/link-local/`::`/53/DHCPv6/hop_limit≤1 不加速。v6 一律直连——honk 补丁块加了 `dip('::/0') -> direct(must)`，因为 honk 处理 v6 会打断连接（实测）。异常 v6 环境用 `option ipv6 '0'` 关掉。
- **honk 直连加速依赖 p1 core**：用上游原版 core 时 dpd 会保持 `observe`。
- **PPPoE**：`bpf_fib_lookup` 首次 `NO_NEIGH` 会重试一次（`fib_retry`），出口用 `bpf_redirect`；没有真实 PPPoE 线路的实验室只验证到这条路径能发出去。
- **性能数字**：`docs/BENCHMARK.md` 里的吞吐/pps 是 2026-10-27 在共享 ESXi 上测的（ABI 8 对象）；ABI 9 的收益体现为每包工作量减少，共享环境下的 A/B 差异落在噪声里，不作为结论。

---

## 10. 排障

| 现象 | 处理 |
|---|---|
| `Cannot find appropriate hash command`（honk） | `generated-stage.mk` 没取到；看 `Custom Packages` 里的 `honk:` 行 |
| 改了源码但镜像没变 | 缓存 key 是 `CONFIG-OWNER-HASH`；确认上游 commit 变了，或删对应缓存 |
| X86/RK 没有数据面 | 看 `Custom Packages` 是否打印 `ebpf datapath installed into package/`；以及 `Config/GENERAL.txt` 是否被使用 |
| IPQ 里出现 einat/dpd | 检查 `Packages.sh` 的平台判断是否被改 |
| `UPSTREAM-CHECK` 报 MISSING | 上游动了锚点，更新 `Handles.sh` 对应段落；不要放宽检查 |
| dpd 不加速 | `/usr/libexec/dpd-regress.sh --target <ip>`；再看 `logread -e dpd-fastpath` 的门禁原因 |

---

## 11. 来源与许可

- CI 框架：`VIKINGYFY/OpenWRT-CI`（MIT）。
- einat：`EHfive/einat-ebpf`（GPL-2.0）。
- honk：`Glassyiris/honk`，打包与 Doona 见 `kwrum1/openwrt-honk`。
- `ebpf/` 下其余组件为本仓库原创（GPL-2.0-only）。
