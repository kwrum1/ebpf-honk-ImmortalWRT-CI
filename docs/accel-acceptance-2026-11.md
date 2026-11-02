# 加速数据面优化：实现与验收矩阵（2026-11-02）

本文对应本轮五项优化（ABI 11）的**实现方式**与**本机 VM 验收结果**。每条结论都
有可复现的命令；没有跑到的项目在 §5 明确列出，不当作已验证。

## 0. 本轮改了什么

| # | 事项 | 落点 | 状态 |
|---|---|---|---|
| 1 | 快路径 TCP MSS clamp | `ebpf/router-dataplane/src/dpd_fastpath.bpf.c`、`dpd_common.h`（ABI 11）、新 map `dpd_mtu` | 已实现、已验收 |
| 2 | `dpdctl status [-j]` | `src/dpdctl.c`，含 map `max_entries`、gate、计数器 | 已实现、已验收 |
| 3 | 独立「加速状态」页 | `ebpf/luci-app-ebpf/files/htdocs/.../view/ebpf/status.js`、菜单、ACL | 已实现、静态验证 |
| 4 | gate 原因可见 | `files/dpd-fastpath.sh` 的 `dpd_gate_publish()` → `/var/run/ebpf/gate[.json]`；`dpdctl`/LuCI 读取 | 已实现、已验收 |
| 5 | 文档/CI 一致性 | `Config/GENERAL.txt`、`Scripts/verify-packages.sh`、新 `Scripts/verify-drift.sh`、两个 workflow | 已实现、已验收 |
| 6 | ABI 12：cfg+stats 合一 | `dpd_common.h`（`struct dpd_cpu`）、`dpd_fastpath.bpf.c`、`dpdctl.c` 的读-改-写 | 已实现、已验收 |
| 7 | 多 WAN 保留代理 mark | `dpd_fastpath.bpf.c` 写 mark 处 + `ebpf-mwan` 的 `ip rule .../0x0fffffff` | 已实现、待 multi-WAN 场景验收 |

额外的两处**实现期发现并修掉的缺陷**（都是验收跑出来的，不是设计时就有的）：

1. **Ethernet 冷 ARP 被当成 PPP 处理**：`dpd_emit_class()` 原来把
   `bpf_fib_lookup() == NO_NEIGH` 一律映射成 `bpf_redirect(ifindex)`（DEV 类）。
   veth/以太网在邻居表未解析时也会返回 NO_NEIGH，此时帧里还是入口侧的 L2 头
   （dmac 是自己的 LAN MAC），直接 redirect 会把包发给错误的 MAC。
   实测：`pkt_total=16 redirect_ok=11` 但零回包，iperf 卡死。现在只有
   `POINTOPOINT|NOARP`（ppp/tun）才走 DEV，其余 NO_NEIGH 交给
   `bpf_redirect_neigh()` 去解析邻居。
2. **`mss_skip` 把每个 TCP 数据包都算进去**：第一版在 SYN 判断之前就
   `ST_MSS_SKIP++`，一次 2 秒 iperf 就 +36598，计数器失去意义。现在只在
   「确实是 SYN/SYN-ACK，但出口 MTU 未知或 < 536」时计数。

## 1. MSS clamp 的实现要点

- **为什么需要**：接管一个流会跳过 netfilter，fw4 的
  `tcp option maxseg size set rt mtu`（mangle forward 的 mtu_fix）也不会跑。
  PPPoE 上行 1492、两端 1460 MSS 时，第一个满段 1514 字节被上游丢弃，只能靠
  PMTUD；ICMP 一被过滤就是「网页能开、下载卡死」。
- **改哪个包**：只在程序真正接管的 SYN / SYN-ACK 上改，且只在 `cfg->mss_clamp=1`
  时。慢路径继续由 fw4 负责，不重复改写。
- **用哪个 MTU**：`min(ingress MTU, egress MTU) - 40`（IPv6 为 `-60`）。
  MSS 语义是「本端愿意接收的段长」，约束的是**反方向**；只用 egress MTU 会修好
  下载、把上传留在黑洞里（SYN-ACK 的 MSS 决定客户端往 1492 上行发多大）。
- **MTU 从哪来**：新 map `dpd_mtu`（ifindex → u32），由 `dpdctl ifaces` 从
  `/sys/class/net/<dev>/mtu` 读入；init / hotplug ifup+ifupdate / gate refresh
  都会重新教学，PPPoE 重新协商后自动跟上。
- **改写方式**：`bpf_skb_load_bytes()` 遍历 TCP 选项（20 次展开，verifier 可接受），
  命中 kind=2/len=4 后 `bpf_skb_store_bytes()` 写回新 MSS，再
  `bpf_l4_csum_replace()` 增量修 TCP 校验和（与 TTL 改写同一套机制，兼容
  CHECKSUM_PARTIAL）。
- **失败方向**：MTU 未知或算出的 MSS < 536（RFC 879 下限）时不改、计入
  `mss_skip`。宁可保持旧行为，也不改写成一个更糟的值。

## 2. 状态与 gate 的实现要点

- `dpdctl status`：人类可读；`-j` 输出 JSON（`cfg` / `maps.max_entries` /
  `ifaces`（含 MTU、flags）/ `vlans` / `wans` / `stats` / `gate`）。
  `gate` 是原样嵌入 `/var/run/ebpf/gate.json`（先校验是 JSON 对象，避免读到
  半写文件）。
- `dpd_gate_mode()` 现在把判定结果落盘，而不是只写日志：
  - `/var/run/ebpf/gate`：4 行（requested / effective / code / reason），给 shell。
  - `/var/run/ebpf/gate.json`：同样的内容 + `checks{uplink,einat,einat_on_uplink,
    honk,honk_p1}` + `at` / `uptime_s`。
  - code 是稳定 token：`ok`、`uci-disabled`、`mode-off`、`mode-observe`、
    `no-uplink`、`no-einat`、`einat-unknown`、`einat-not-on-uplink`、
    `honk-unpatched`、`chain-guard`。
- watchdog 每个 tick（默认 20s）额外写 `/var/run/ebpf/status.json`
  （`dpdctl status -j` 的快照）；LuCI 页面优先用 `file.exec` 直接跑
  `dpdctl status -j`（2s 刷新），拿不到权限时退回读快照。
- `dpdctl` 不再依赖 libbpf：map 访问改为 `src/dpd_bpf.h` 里的 `bpf(2)`
  薄封装（`BPF_OBJ_GET` / `MAP_*` / `OBJ_GET_INFO_BY_FD`）。好处是控制面二进制
  可以静态链接、可以在任意 musl 交叉工具链上编译，包也不再需要
  `PKG_BUILD_DEPENDS:=libbpf`。

## 3. 验收环境

```
QEMU 11.1.0 (Windows host, TCG)
OpenWrt 25.12.4 x86_64, kernel 6.12.87, 2 vCPU
BPF 对象：clang 23.1.4 -target bpf -O2 -g
dpdctl：zig 0.17 `zig cc -target x86_64-linux-musl -static`
拓扑（全部在 guest 内，netns）：
  cli ns  192.168.10.2/24  --veth--  lan0 192.168.10.1/24  [router]
  isp ns  198.18.0.2/24    --veth--  wan0 198.18.0.1/24     [router]
  wan0 MTU 1492（模拟 PPPoE），lan0 1500，isp0 1500
  无 fw4（stop 掉，避免干扰数据面测量），ip_forward=1，rp_filter=0
```

## 4. 验收矩阵

### 4.1 对象与工具

| ID | 检查 | 期望 | 实测 | 结论 |
|---|---|---|---|---|
| A1 | 对象加载（6.12.87 verifier） | 通过，7 个 map 全建 | `tc filter add` 两条均成功；`dpd_cfg` value 40B、`dpd_stats` 184B、`dpd_flows` 16384 条 | PASS |
| A2 | ABI | 11 / 11 | `abi 11`，`loaded_abi 11` | PASS |
| A3 | `dpdctl status -j` | 合法 JSON，字段齐全 | `json.loads` 通过；keys = abi, attached, cfg, gate, ifaces, loaded_abi, maps, stats, tool, vlans, wans | PASS |
| A4 | `dpdctl ifaces` 写 MTU | map 中有 lan0=1500 / wan0=1492 | `dpd_mtu` dump 一致 | PASS |
| A5 | 无效接口 | 打印错误、不中断 | `dpdctl ifaces nosuchdev` → stderr，rc=0 | PASS |

### 4.2 MSS clamp（数据面）

上传方向（client → server）：SYN-ACK 的 MSS 决定客户端往 1492 上行发多大。

| ID | 条件 | 期望 | 实测 | 结论 |
|---|---|---|---|---|
| B1 | clamp=1，wan 1492 / lan 1500 | SYN 与 SYN-ACK 都是 1452 | wan-out `mss 1452`，lan-out `mss 1452`，`mss_clamp` +4，iperf 4.42 Gbit/s | PASS |
| B2 | clamp=0，同上 | 都是 1460，不改写 | 1460 / 1460，`mss_clamp` +0，4.12 Gbit/s | PASS |
| B3 | clamp=1，全 1500 | 保持 1460，不改写 | 1460 / 1460，`mss_clamp` +0 | PASS |
| B4 | clamp=1，两个 MTU 都不在表里 | 不改写，`mss_skip` 增加 | 1460 / 1460，`mss_skip` +4 | PASS |
| B5 | **黑洞复现**：wan 1492 + 客户端丢弃 ICMP frag-needed | clamp=0 时卡死，clamp=1 恢复 | clamp=0：`0.00 Bytes / 0.00 bits/sec`；clamp=1：3.24 Gbit/s；再开：3.84 Gbit/s | PASS |
| B6 | 校验和 | 接收端接受（TCP 校验和正确） | 全部 B1–B5 的 iperf 传输成功即证明（内核在接收侧校验） | PASS |
| B7 | stateful 模式回归 | 流表命中、转发正常 | `flow_hit=80491 / flow_miss=4 / flow_write=4`，5.57 Gbit/s（TCG），双向 entry 正确 | PASS（无 clamp 计数：握手走 prime 慢路径，见 §5.6） |

B5 是本轮唯一「会实际伤到用户」的缺陷的直接证据：同一套拓扑、同一条 ICMP 过滤
规则，只切换 `mss_clamp`，吞吐在 0 与 3.8 Gbit/s 之间跳。

一个需要说清的边界：**默认的 stateful 模式下，握手本来就走 prime 慢路径**
（每方向第一个包交给协议栈），所以 fw4 的 mtu_fix 仍然会 clamp SYN/SYN-ACK；
本程序的 clamp 主要覆盖 stateless 模式、以及 5 元组在 TTL 内被复用导致握手直接
命中流表的情况。也就是说它是「把已经存在的洞堵上」，不是「替代 fw4」。

### 4.3 gate 原因可见

| ID | 操作 | 期望 code | 实测 | 结论 |
|---|---|---|---|---|
| C1 | 没有 wan 接口 | `no-uplink` | `no-uplink` | PASS |
| C2 | 加 wan（wan0）后，无 einat | `no-einat` | `no-einat`，effective=observe | PASS |
| C3 | `dpd_fastpath.global.enabled=0` | `uci-disabled` | `uci-disabled` | PASS |
| C4 | `enabled=1, mode=observe` | `mode-observe` | `mode-observe` | PASS |
| C5 | `dpdctl status -j` | 内嵌 gate 对象 | `"gate": {"code": "no-einat", ...}` | PASS |
| C6 | `dpdctl status`（人类） | 一行说明 code + reason | `gate observe (no-einat)` + `gate reason ...` | PASS |
| C7 | `status.json` 快照 | 由 gate refresh / watchdog 产生 | 1524 B，内容与 `status -j` 同构 | PASS |

### 4.4 状态页（LuCI）

| ID | 检查 | 期望 | 实测 | 结论 |
|---|---|---|---|---|
| D1 | `status.js` 语法 | node --check 通过 | rc=0 | PASS |
| D2 | 静态资源可访问 | HTTP 200 | `wget` 取到 14075 B | PASS |
| D3 | `file.exec` 路径 | rpcd 返回 dpdctl stdout | `{"code":0,"stdout":"{...}"}` | PASS |
| D4 | 菜单/ACL JSON | 合法 | `json.load` 通过 | PASS |
| D5 | 浏览器实际渲染 | 页面出现卡片/表格 | **未测**（见 §5） | N/A |

### 4.5 文档 / CI 一致性

| ID | 检查 | 期望 | 实测 | 结论 |
|---|---|---|---|---|
| E1 | `Scripts/verify-drift.sh` | 通过 | `verify-drift: PASSED` | PASS |
| E2 | 负向：加一个没人读的配置项 | 必须失败 | `FAIL ... 'bogus_drift_test'`，rc=1 | PASS |
| E3 | `router_qos.global.upload` 残留 | 0 处 | 0 处 | PASS |
| E4 | REQUIRED ∩ FORBIDDEN | 空集 | 27 / 56，无交集 | PASS |
| E5 | 菜单 path → view 文件 → Makefile 安装 | 全链路存在 | `ebpf/status` 通过；`smartdns/*`、`honk/*` 标记为外部页面跳过 | PASS |

### 4.6 ABI 12（cfg + 计数器合一）

不在 6.12 台架里，而是在**编译机 10.1.18.100 的内核 6.17** 上用私有 netns 验证
（`unshare -n`，dummy/veth，不产生任何台架性能数据）：

| ID | 检查 | 期望 | 实测 | 结论 |
|---|---|---|---|---|
| G1 | 对象加载 | verifier 接受 | `tc filter add ... bpf da` 成功 | PASS |
| G2 | per-CPU 值 | 一个 map 同时含 cfg/stats | `dpd_cfg` 为 per-CPU，`status -j` 显示 `abi: 12` | PASS |
| G3 | 读-改-写 | 改配置不清空计数 | 20 个包后 `pkt_total=6`，`set mode observe` 后仍为 6 | PASS |
| G4 | 状态输出 | `status -j` 字段不变 | `cfg/maps/ifaces/stats/gate` 全部存在 | PASS |

### 4.7 ABI 13：802.1Q 接管（VLAN）

在编译机内核 6.17 的私有 netns 里做（ESXi 侧需要 VGT/4095 portgroup，实测该
portgroup 的 vmxnet3 link 起不来，改在原生内核验证；生产路径的 tag 处理与内核
版本无关）：

| ID | 检查 | 结果 |
|---|---|---|
| V1 | 现状（ABI 12）：tagged 流 | VLAN10 客户端 ping 100% 丢包，WAN 侧看到**带 tag** 的帧 |
| V2 | ABI 13，observe 基线 | 2/2 通（dpd 不接管） |
| V3 | ABI 13，stateless 接管 | 2/2 通，RTT 0.12 ms |
| V4 | WAN 侧帧格式 | `ethertype IPv4 (0x0800)`，**无 802.1Q**，MAC 已按出口重写 |
| V5 | 计数器 | `tag_pop=2`、`tag_skip=0`、`redirect_ok=4` |
| V6 | 元数据 tag（skb->vlan_tci） | 同样被识别并摘除（veth/vmxnet3 路径） |

结论：带 VLAN 的流现在可以走 L2 直发；出口是堆叠设备时仍然让路，tag 归属不被
破坏。

### 4.8 ABI 13 在 6.18 台架上的部署

ABI 13 对象已复制到 `ebpf-router` 并成功加载（`dpdctl` 报 `ABI 13 loaded`），
`tc filter show` 显示 `dpd_fastpath id 40 jited`。台架回归（untagged 吞吐/MSS）
在客户端 VM 恢复后补跑。

### 4.8 ABI 13 在 6.18 台架上的部署与回归

ABI 13 对象部署到 `ebpf-router`（6.18.55）后：

| ID | 检查 | 结果 |
|---|---|---|
| F10 | 对象加载 | `ABI 13 loaded`，`tc filter` 显示 `dpd_fastpath … jited` |
| F11 | 客户端连通 | client→server 3/3，0.82 ms |
| F12 | untagged 回归 | 4 流上传 **4.83 Gbit/s**（retr 443） |
| F13 | MSS 仍在 | server 侧抓到 SYN `mss 1452`（WAN 1492），`mss_clamp=6` |
| F14 | tag 计数 | `tag_pop=0`、`tag_skip=0`（untagged 流量不应触发） |

> 期间 `ebpf-client` VM 反复起不来，重启 ESXi 的 `hostd` 后恢复——是宿主服务问题，
> 与镜像/数据面无关。

### 4.9 性能对照（2026-11-02，ESXi，vmxnet3，2 vCPU）

大包（默认 1460 MSS，4 流 10s）——**NIC 受限，看不出差异**：

| 组 | 上传 | 下载 |
|---|---|---|
| 基线（无 dpd） | 5.92 / 6.27 | 6.23 / 6.48 |
| dpd stateful | 5.86 / 6.11 | 3.55* / 6.19 |
| dpd stateless | 5.77 / 6.04 | 6.21 / 5.97 |

\* 单次抖动（服务器刚重启）。上限约 6 Gbit/s 是 vmxnet3/内部 vSwitch 的瓶颈。

小包（MSS 100，8 流，上传，路由器 CPU 95%+，CPU 受限）：

| 组 | 结果 | 相对基线 |
|---|---|---|
| 基线（无 dpd） | 366 / 377 Mbit/s | — |
| dpd stateless | 404 / 405 Mbit/s | **+9%** |
| dpd stateful | 422 / 421 Mbit/s | **+13.5%** |

MSS 200 同向但噪声更大（基线 ~800，dpd 865–900，+8–11%）。

qdisc A/B（MSS 100，stateful，3 轮交替）：

| qdisc | 结果 |
|---|---|
| fq_codel（默认） | 416 / 426 / 426 |
| pfifo_fast | 426 / 424 / 421 |

**结论：在这个负载下两者无差异**（±1%），报告里"pfifo 换 CAKE 可 +3–10%"的估算没有
复现；而且镜像里没有 fq/cake 模块，只有 fq_codel/pfifo_fast。因此 `router-qos` 不改。

### 4.10 性能结论

- 大包吞吐：dpd 不改变（NIC 受限），但也不回退；
- 小包/高 pps：stateful **+13.5%**、stateless +9%（CPU 受限场景才是加速的真正收益）；
- stateful 优于 stateless（命中路径省掉每包 FIB）；
- qdisc 不是瓶颈，不调整。

## 5. 6.18 / ESXi 台架（最终验收）

上面的数字来自 6.12 QEMU，只能证明逻辑正确。**生产验收**改在：

```
编译机 10.1.18.100 : VIKINGYFY/immortalwrt@owrt（kernel 6.18）最小镜像
ESXi 10.1.18.124   : vmxnet3 + pvscsi，bench-lan / bench-wan 内部 vSwitch
                     router 10.1.18.230 / client .231 / server .232
```

该环境只跑**功能矩阵**；吞吐/延迟等测速在“完全体”定稿后一次性进行，避免用中间
版本的数字做决策。对照组是同一份 `.config` 去掉 `dpd-fastpath` 后增量重编的
非 eBPF 镜像。

### 5.2 6.18 / ESXi 功能矩阵（已实测）

```
ebpf-router  10.1.18.230  6.18.55  vmxnet3 x3 (mgmt/lan/wan)
ebpf-client  10.1.18.231  6.18.55
ebpf-server  10.1.18.232  6.18.55
镜像：VIKINGYFY/immortalwrt@owrt 最小配置 + dpd-fastpath(ABI 12)
```

| ID | 检查 | 结果 |
|---|---|---|
| F1 | 内核 | 三台均 6.18.55 |
| F2 | client→server 连通 | 3/3，0.8–1.7 ms |
| F3 | 挂载 | eth1、eth2 各一条 `pref 100 bpf` classic 过滤器 |
| F4 | ABI 12 计数保持 | `dpdctl set mode observe` 前后 `pkt_total` 均 2505098 |
| F5 | MSS clamp=1 | server 侧抓到 client SYN `mss 1452`（WAN 1492） |
| F5b | MSS clamp=0 | 同一路径 `mss 1460`（不改写） |
| F6 | 黑洞对照（client 丢弃 ICMP frag-needed） | clamp=0 → **0.000 Gbit/s**；clamp=1 → **3.366 Gbit/s** |
| F7 | gate 码 | `uci-disabled` → `mode-observe` → `einat-unknown`（最小镜像无 bpftool） |
| F8 | `dpdctl status -j` | 合法 JSON，`abi=12`、`attached=true` |
| F9 | detach 后仍转发 | 过滤器移除后 client→server ping 正常 |

打流冒烟（stateful，4 流，vmxnet3 内部 vSwitch，非最终性能验收）：
上传 3.43 Gbit/s / 下载 5.42 Gbit/s。

**未做**（按"完全体定稿后再测"的约定）：出口 qdisc A/B、非 eBPF 基线对照、
满载 p99。台架已具备这些测试的全部条件。

### 5.1 6.12 QEMU 阶段没测到的

1. **LuCI 页面真实渲染**：需要登录会话（本镜像 root 无密码，`session.login`
   走不通）。已用 node 语法检查 + 静态资源可达 + rpcd exec 返回值验证了数据链路，
   但没有在浏览器里看最终 DOM。
2. **honk-unpatched 分支**：本镜像没有 honk，只验证到 `no-einat`。
   `honk-unpatched` 的判定逻辑与 `no-einat` 同构，但未在真机触发。
3. **真机 PPPoE**：1492 是用 veth MTU 模拟的；PPPoE 的 `ifa->ifa_mtu` 变化触发
   `ifupdate` → `dpdctl ifaces` 的路径没有在真机上跑过。
4. **性能数字**：全部是 TCG（软件模拟）下的相对结论，只用于证明行为正确
   （0 与 3.8 Gbit/s），不能当作真机吞吐。
5. **stateful 模式的 clamp 命中路径**：状态化模式下 SYN/SYN-ACK 大多走
   prime 慢路径（由 fw4 clamp），只有「5 元组在 TTL 内被复用」时才会走本程序
   的 hit path。逻辑与 stateless 共用同一函数，但没有单独构造该场景。
   （B7 证明了 stateful 的流表/转发本身没有回归。）
6. **fw4 在环**：数据面测量时 fw4 是 stop 的，避免它的 clamp/forward 规则干扰
   「0 与 3.8 Gbit/s」的对照。生产路径是 fw4 + einat + dpd 三层同时在场。

## 6. 复现

```sh
# 构建
clang -target bpf -g -O2 -D__KERNEL__ -D__BPF_TRACING__ \
      -I<toolchain include> -I<bpf headers> \
      -c ebpf/router-dataplane/src/dpd_fastpath.bpf.c -o dpd_fastpath.bpf.o
zig cc -target x86_64-linux-musl -static -O2 \
      -I<kernel uapi headers> -o dpdctl ebpf/router-dataplane/src/dpdctl.c

# 装载与配置
tc qdisc add dev lan0 clsact
tc filter add dev lan0 ingress pref 100 handle 100 bpf da obj dpd.o sec classifier
tc filter add dev wan0 ingress pref 100 handle 100 bpf da obj dpd.o sec classifier
dpdctl ifaces lan0 wan0
dpdctl set mode stateless
dpdctl set mss 1
dpdctl status -j

# 行为验证（上传方向）
tcpdump -i wan0 -n -vv -Q out 'tcp[tcpflags] & tcp-syn != 0'   # 期望 mss 1452 @ wan mtu 1492
```

`Scripts/verify-drift.sh` 已接进 `WRT-CORE.yml`（编译前）和 `BPF-CHECK.yml`，
所以上面 E 段的漂移检查以后每次 CI 都会跑。
