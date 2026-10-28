# einat-ebpf —— eBPF Full Cone NAT（NAT44 加速方案）

## 这个包做什么

普通 NAT 一直由 **netfilter conntrack + masquerade**（fw4 的 nft 规则）承担。
本阶段发现的问题不是「能不能用」，而是：

* 所有 NAT 状态都在 conntrack 里，**对 eBPF 加速层不可见**；
* 端口映射行为是 **Address-and-Port-Dependent**，不是 full cone；
* 每个包都要走 nft 规则链，映射延迟和规则复杂度都叠在软中断里。

`einat` 在 eBPF 的 TC hook 上**独立实现** Endpoint-Independent Mapping +
Endpoint-Independent Filtering（也就是 full cone NAT），不依赖 conntrack。

## 关键约束（来自 einat 官方文档 + 本项目的红线）

| 约束 | 来源 | 本项目处理 |
| --- | --- | --- |
| 必须关掉一切硬件/软件 offload | einat README 的 IMPORTANT | `kmod-nft-offload` 不装；firewall4 写入 DEPENDS；并且默认 `/etc/config/firewall` 里没有 `flow_offloading` —— offload 默认关闭。这和去掉别的 eBPF 加速层是同一件事 |
| 必须关掉 nftables/iptables masquerade | einat README | init 在 **procd data** 里给 fw4 注入一条 `type nat target ACCEPT` 规则，**不改** `/etc/config/firewall` |
| 必须让出 WAN→LAN 转发给 einat 的端口段 | einat README | 同上，procd data 注入一条 `type rule target ACCEPT` |
| PPPoE / 大包接口需要 TCP MSS clamping | einat README、issue #19 | fw4 的 `option mtu_fix` 必须保留（见 `docs/proxy-accel-coexistence.md` 第 8 节 H2） |
| 内核需要 BPF + BTF + BPF-to-BPF calls | einat docs/guide/openwrt.md | x86_64 / aarch64 都满足；`DEBUG_INFO_BTF=y`、`BPF_SYSCALL=y`、`BPF_JIT=y`、`NET_ACT_BPF=m`、`NET_SCH_INGRESS=m` |
| 需要 `CAP_SYS_ADMIN` + `CAP_NET_ADMIN` | einat README | 按 root 运行；`files/capabilities.json` 也装好了（不需要授权直接运行那一行） |

## 二进制来源：本仓库自己构建（p1 / p2 补丁）

以前这里直接下载上游 release 的 `einat-static-*`。现在改成**本仓库构建**：

* 工作流 `EINAT-BUILD`，上游源码 pin 到 `ba647ce6`（不 fork 仓库）；
* 应用 `patches/einat-perf.py`（p1）与 `patches/einat-perf-p2.py`（p2），两者都按锚点打，上游漂移会直接报错；
* Nix 用上游的 `static` 预设（不带 `ipv6` feature，程序里没有 NAT66 代码），`build.rs` 原本就是 `-O2 -mcpu=v3`；
* 产物是静态 musl 二进制 + `aya` loader，运行时不需要 libbpf/elf/zlib；
* 发布在固定 tag `einat-p2`，sha256 写在 `Makefile` 的 `EINAT_HASH`。

### 每包收益

| 方向 | 上游 | 现在 |
| --- | --- | --- |
| WAN egress，普通流量 | LPM(dest) + LPM(src) + hash(binding) + hash(ct) = **4** | LPM(src) + hash(binding) + hash(ct) = **3**（少一次 LPM） |
| WAN egress，已建立 TCP 数据 | 同上 + 每包 `bpf_timer_start` | **2**，定时器刷新最多 1 次/秒/流 |
| WAN ingress，普通流量 | LPM(src) + hash(binding) + hash(ct) = **3** | **3**（不变） |
| WAN ingress，已建立 TCP 数据 | 同上 + 每包 `bpf_timer_start` | **2**，定时器刷新最多 1 次/秒/流 |
| 每包固定开销 | `get_is_ipv4` + `parse_packet` 两次解析 | 一次解析 |

三种 map 里 LPM 最贵（前缀树遍历），hash 命中要算 jhash + 桶，`bpf_timer_start` 要拿定时器锁并重排 hrtimer，所以 ② 省的不只是一次查表。

### 等价性

* **dest_config 快路径**：只在「dest_config 恰好一个条目、等于默认外部地址、且为满前缀」时启用 32 位比较——此时 LPM(`daddr`) 只可能在 `daddr == 外部地址` 时命中，与查表完全等价。多条目、非满前缀、空表分别落到 mode 2（= 上游行为）和 mode 0；表更新期间先写 mode 2 兜底，改完再写真实值。
* **CT 快路径**：只跳过 `CT_ESTABLISHED` + TCP 数据包——上游在这条路径上也只做 `RESET_TIMER`。SYN/FIN/RST、ICMP 错误、UDP/ICMP、以及任何非 ESTABLISHED 状态全部照旧走慢路径；`map_ct` 仍是状态/超时/refcount 的唯一来源，外部端口分配、binding/ct 的 refcount 与 seq 一行没动。

按 1 Mpps 粗算（只是算术）：出向普通流量每秒少 100 万次 LPM 查表；已建立 TCP 每秒少 100 万次 hash 查表，定时器重排从「每包一次」降到「每流每秒最多一次」。

发布前 `EINAT-BUILD` 的 `e2e (netns)` 作业会跑 `patches/einat-e2e-nat.sh`：EIM（同一本地端口对两个 peer 只有一种外部端口）、EIF/full cone（没通信过的 peer 仍能打到映射端口）、ICMP、20MB TCP 传输（全程走 CT 快路径）。任一失败就不发布。

为什么不把 einat 编进固件：上游 OpenWrt 打包（`muink/openwrt-einat-ebpf`）声明

```make
PKG_BUILD_DEPENDS:=rust/host libbpf HAS_BPF_TOOLCHAIN:bpf-headers
```

意味着还要在构建机 bootstrap 一套 host Rust、下载 `llvm-bpf` 工具链，并且
`bpf-headers` 会拉 linux-6.12（不在我们的 download 缓存里）。用预编译产物换来
约 2.4 MB 的包体积和零构建依赖。

## 为什么 `--bpf-log` / `--bpf-loader` 不写进 init

* `--bpf-log`：**上游没有这个选项**（`--help` 里没有，代码里也没有），
  einat 的日志级别只能从配置文件/环境读取。照抄旧 init 的 `--bpf-log "$level"`
  会让进程在启动阶段因为未知选项退出。
* `--bpf-loader`：我们装的是 `aya` 版本，`libbpf` 后端在加载阶段会失败。

## 与 router-dataplane 的 hook 顺序

```
WAN ingress:  einat (pref 1)  ->  dpd_fastpath (pref 100)
LAN ingress:                      dpd_fastpath (pref 100)
```

einat 固定占用 **pref 1 / handle 1**，并且**永远不返回 `TC_ACT_OK`**
（没接管的包返回 `TC_ACT_UNSPEC`），所以它后面的程序仍然会被调用；pref 100 的
dpd 一定看得到流量。顺序是 pref 决定的，不是代码顺序。

## 配置步骤

默认 `enabled='0'`（和 honk、router-dataplane 一致：先让已知 good 的
fw4 masquerade 顶着，等 einat 侧验证完再开）：

```sh
uci set einat.config.enabled='1'
uci commit einat
/etc/init.d/einat restart
/etc/init.d/firewall reload      # 让 fw4 重新读 procd 注入的规则
```

验证 full cone（两个方向都要看，不要只看路由表）：

* `stunclient`（stuntman）；
* `NatTypeTester`（Windows）；
* `go-stun`

注意：只有当 WAN 拿到的是公网 IPv4 时，才能测出 full cone。

## 已验证 / 未验证

* **CI（每次补丁变更）**：`EINAT-BUILD` 的 `e2e (netns)` 在 network namespace 里
  跑 EIM/EIF/ICMP/20MB TCP，通过后才发布二进制。
* **实验机（x86_64，p2 二进制）**：TCX 双向挂载正常；`.data` 的
  `g_ipv4_dest_config_mode = 1`（单个 WAN 地址，走 32 位比较快路径）；已建立
  TCP 流的 binding 里 `ct_state_cached = 2`（ESTABLISHED，快路径生效）；
  ping、iperf3 TCP 上行/下行、UDP 均正常。
* **未验证**：aarch64 真机、PPPoE 拨号场景、真实 hairpin（需要端口转发 + 实网
  客户端）、以及高 PPS 下的性能数字（ESXi 方差太大，本项目不出 perf 数据）。
