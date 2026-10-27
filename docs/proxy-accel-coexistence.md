# 代理与加速共存 —— 研究报告与优化方向

> 触发（2026-10-18，用户提问）：**"目前 honk 和 dpd 无法同时工作吗？加速就不能代理、
> 代理就不能加速？参考 chawrt 和 landscape 的优化，继续研究打磨优化方向和代理加速
> 兼容方式。"**
>
> **结论先行**：这个前提**不准确**。honk(dae) 自己就把路由策略**编译成 eBPF 在内核里
> 判定**，并把**直连判定 offload 回内核**（`RoutingMeta` bit 57 / "native direct"）；
> 只有**代理判定**和**"域名终局性未定"的直连判定**才进用户态。所以"代理 + 加速"本来
> 就是**按流分区**，不是二选一。
>
> 我们上一轮测到"honk 跑着时 dpd 计数器不涨"，用的恰好是**必然进用户态**的两种流量
> （被代理域名 + 非 must 的 fallback 直连）。**从没有测过 `direct(must)` 流量** ——
> 唯一一种必须在内核里跑完的直连。
>
> 所以下一件事不是"设计共存"，而是：**(1) 做一次定向实验，证明 CN `direct(must)` 流量
> 仍然经过 dpd；(2) 把"还会掉进用户态"的直连压到最少；(3) 补上加速路径真正缺的东西
> （MSS clamp）。
>
> ---
>
> ### ⚠️ 2026-10-18 02:00 更正：实验做完了，**上面的结论被证伪**
>
> 定向实验（`build/qemu-honk-dpd-coexist.sh`）跑完了，**P1 失败**：honk 一开，
> `dip(geoip:cn) → direct(must)` 的流**在 dpd 上计数为 +0**（同一目的地址在 honk 关掉时是
> `+38574`）。而且 `dae0` 这个"honk 用户态"见证**无效** —— P3 的代理明确成功（出口是节点
> IP）时 `dae0` 依然是 +0。
>
> 所以：**"代理与加速按流分区"在本挂法下不成立**，实测是 **honk 的 TC redirect 管线整体
> 让位**。§2 的归属矩阵作废；细节、原始数字、能说/不能说的边界、以及两条可走的方案
> （B 接受现状 / C 改到 WAN 入口做下载方向）见 **§8**。用户最初那句"加速就不能代理、
> 代理就不能加速"**比本文原来的结论更接近事实**。**
>
> ### ✅ 2026-10-27 更新：已按“direct 交回 classic”实现（§9）
>
> 没有走 C（WAN 入口下载方向），而是给 honk 的 direct 判决加 p1 补丁：4 个 direct 出口返回
> `TC_ACT_UNSPEC` + `DIRECT_UNSPEC_MARK`，代理/block 判决不变。dpd 用
> `/usr/share/honk/direct-unspec` 识别；实验台实测直连 3.77–4.18 Gbit/s、64 流 1.85:1，
> 代理流不进 classic。详见 **§9**。

本文中每个论断都标了来源等级：

| 标 | 含义 |
|---|---|
| **实测** | 本轮/上一轮在真实镜像或真实内核源码树上看到的 |
| **上游文档** | honk / landscape 自己文档里写的设计（未在我们机器上验证） |
| **待测** | 有明确判据、还没跑的 |

---

## 1. 本轮新增的实测事实

| # | 事实 | 证据 |
|---|---|---|
| F1 | honk-core 走 **TCX + `bpf_sk_assign`**：`sk_assign` 6 处、`tproxy/TPROXY` 134 处、`dae0` 62 处、`bpf_redirect` 8 处 | `strings` 镜像 `/usr/bin/honk-core`（27 MB） |
| F2 | 我们发货的内核 **6.18.55** 有 `BPF_F_BEFORE` / `BPF_F_AFTER`，uapi 里有 `relative_fd/relative_id/expected_revision`；**libbpf 头里 `bpf_link_create_opts.tcx` 也有这三个字段** | `linux-6.18.55/include/uapi/linux/bpf.h:1223,1649`；`staging_dir/.../include/bpf/bpf.h:443` |
| F3 | 出厂/镜像里 honk 的策略是 `dip(geoip: cn) && !dport(53) -> direct(must)`、`domain(geosite: cn) -> direct`、`fallback: direct`；`dial_mode: domain`；`nfqueue_enable: false`（我们的裁剪） | `root-x86/etc/honk/config.dae`、`/usr/share/honk/default-config.dae`、`system.dae` |
| F4 | 内核只有 `CONFIG_TCP_CONG_CUBIC=y`（`DEFAULT_TCP_CONG="cubic"`），**没有 BBR**，manifest 里也没有 bbr 模块 | `linux-6.18.55/.config` + 镜像 manifest |
| F5 | `option mtu_fix 1` 在出厂 firewall 里（fw4 给转发流量加 `TCPMSS clamp`）；**dpd 完全不做 MSS**；einat 的注释明确把 MSS 推给 firewall（`option mtu_fix`） | 镜像 rootfs `/etc/config/firewall:28`；`einat-ebpf/files/einat.init:37`、`README.md:22` |
| F6 | 三条链的挂载点：honk = **br-lan 的 TCX**（ingress/egress）；dpd = **br-lan 的 classic filter**；einat = **WAN 的 TCX**（ingress `ingress_rev_snat` / egress `egress_snat`）。同 hook 上 TCX 先于 classic | 上一轮 `bpftool net show` 实测 + 本轮 closure 复现 |
| F7 | honk 文档明确写了**内核直连 offload**：`RoutingMeta` bit 57 `OFFLOAD`；`Direct` 模式 "normalize every non-`must`, non-`block` flow to `direct` and offload it"；"No flow is sent to userspace merely because its policy is compiled." | honk `doc/en/design/datapath.md` §Route-time direct offload、`routing.md` |
| F8 | 哪些直连**不** offload：非 `must` 且**域名终局性未定**的直连 → `ControlPlaneRouting`（进用户态嗅探 SNI） | honk `doc/en/design/routing.md` §Compiled routing decision plane |

---

## 2. 机制：为什么"代理就不能加速"是误读

### 2.1 honk 是"决策在内核、代理在用户态"，不是"什么都进用户态"

honk 的 `routing` 策略不是用户态解释执行的规则表，而是**编译成一个 eBPF 函数**
（`RoutingInput -> RoutingDecision`，装进 `ROUTING_POLICY_ROOT` map-in-map 的
`slot0/slot1`），在 `lan_ingress_l2` 的 TCX 里**同步调用**。（上游文档）

判定结果只有三种去向：

```
LAN 客户端包 → br-lan TCX (honk lan_ingress_l2)
                 │  ① 内核编译策略判定
                 ├─ proxy            → 重定向进 dae0 → dae0peer → bpf_sk_assign
                 │                      到 daens 里的透明监听 → 用户态代理
                 ├─ direct(must)     → 交回主机路由（native direct）★ 内核里跑完
                 └─ direct(非 must，域名未定) → ControlPlaneRouting → 也是用户态
```

（`dae0`/`dae0peer` 是 netkit/veth 对，回复经 `dae0_ingress` 换回 MAC 后送到 br-lan。）

### 2.2 按流分区的归属矩阵

| 流的种类 | honk 判定 | honk 动作 | dpd 是否参与 | 状态 |
|---|---|---|---|---|
| CN IP / CN 域（`geoip:cn`） | `direct(must)`，终止、不嗅探 | native direct（交回内核） | **应该参与并加速** | **待测（O-1）** |
| 被代理域名（如 `ipinfo.io`） | proxy | `dae0` → 用户态 | 不参与（合理） | 上游文档 + 上一轮实测一致 |
| 非 CN、域名未定（如 `ifconfig.me`） | `fallback: direct`，非 must、域名终局性未定 | ControlPlaneRouting → 用户态嗅探 | 不参与（**这是可优化处**） | 上游文档，解释了我们上一轮的观测 |
| `:53` | 走 honk 的 DNS 归属策略 | 视策略 | dpd 有 `dns_skip` 主动让路 | 已实测 |

### 2.3 我们上一轮的观测为什么是"正常的"

上一轮 closure 里 honk 打开后的三条流是：

```
client DIRECT  https://ifconfig.me/ip   → 非 CN、域名未定 → fallback → 用户态
client PROXIED https://ipinfo.io/ip     → 代理域名       → 用户态
client DIRECT2 https://ifconfig.me/ip   → 同上
```

三条**全部**落在"必然进用户态"的两类里 → dpd 的 `pkt_total/neigh_ok` 当然不涨。
结论"dpd 原地待命"没错，但它**只覆盖了 honk 会拿走的那部分流量**，不能推出
"直连流量也不能加速"。

对照证据：**本轮 closure 的 C 段（honk 未启动）** 用同样的客户端取 `ifconfig.me/ip`，
`neigh_ok +14`、`eth1_tx +9630` —— 说明计数器本身是灵敏的，差别只在"honk 在不在"。

---

## 3. landscape 的做法（这是我们要找的"决策平面"）

landscape 的架构一句话：**"DNS plane decides. Kernel enforces."**

| 它的机制 | 它的实现 | 我们的现状 | 可借鉴度 |
|---|---|---|---|
| **DNS 答案填充内核 map** | 每个 flow 一条独立 Hickory DNS 实例；答案写进该 flow 的 eBPF map | honk 自己有 DNS 嗅探/学习（F7/F8），但**和我们的 dnsmasq→SmartDNS 链是什么关系没验证过** | **高**（见 O-3） |
| **内核按 map 分流** | XDP/TC 读 map，命中就按策略走；**其余流量直接穿过，不进用户态** | 我们已经是这个形状（honk 编译路由 + dpd） | 已有 |
| **把命中的流转给代理** | `tproxy.bpf.c`：`bpf_skc_lookup_tcp`/`bpf_sk_lookup_udp` 找到透明监听 → `bpf_sk_assign(skb, sk, 0)` + `bpf_skb_change_type(PACKET_HOST)` + `skb->mark=1` | honk 内部同样是 `sk_assign`（F1），**不需要我们做** | 已有（但要理解） |
| **geo 库（DAT/TXT）灌进 map** | 自建 geo 索引 | honk 自己读 `geoip.dat`/`geosite.dat` | 中（O-7 才用得上） |
| **MSS clamp 在内核** | `tc_mss.bpf.c` / `xdp_mss.bpf.c` | **我们没有**（F5） | **高**（O-4） |
| **NAT 目的锁定 + 按域/按 IP 全锥例外** | 默认 stricter-than-symmetric，PCDN/BT 例外开全锥 | 我们全线全锥（红线） | 中（O-6，安全口径） |
| 独立 DNS/策略 per flow、容器重定向、REST API | — | 不需要（我们只有一个 LAN） | 低 |

**关键差别**：landscape 的"代理"（Docker 容器）是**它自己 steering 的下游**，所以它能
保证"只有策略命中的流才进用户态"。我们的"代理"是 honk，**steering 也归 honk**。
这一条决定了 O-8：**不要试图在 honk 前面再插一层我们自己的判定**（除非能证明
我们的 direct 集 ⊆ honk 的 direct 集，见 O-8）。

---

## 4. chawrt 的做法（结论：方向不同，不抄）

chawrt（liudf0716）的卖点是：**eBPF 智能流控**（单机限速、时间策略、FastPath）+
**xDPI**（七层协议识别/合规审计）+ apfree-wifidog 认证 + xfrpc 内网穿透。

| 它的东西 | 我们的对应 | 结论 |
|---|---|---|
| eBPF 单机限速/时间策略 | CAKE（`kmod-sched-cake` 已在镜像，`router-qos`） | **不抄**：两套限速器会互相打架，CAKE 的 per-host fairness + 流隔离比朴素的 eBPF 令牌桶好 |
| FastPath | 我们的 dpd | 已是同一思路 |
| xDPI 七层识别 | honk 自己嗅探 SNI 做分流（F4/F7） | **不抄**：第二套 DPI 只是重复解析，且会成为代理判定的第二个"真相源" |
| xfrpc 内网穿透 | 不在本项目范围 | 不抄 |

chawrt 值得学的只有一条**工程态度**：把"谁在什么 hook 上、什么顺序"当一号证据
（它的 aw-bpf 性能对比就是这么做的）——这也正是本轮实验的设计方式。

---

## 5. 优化方向（按优先级）

### O-1【P0，实验】证明/证伪"共存"

`build/qemu-honk-dpd-coexist.sh`（已写好、`bash -n` 通过、未运行）。对同一条客户端链路
取三种流，每条流三个独立见证：

| 见证 | 手段 | 说明 |
|---|---|---|
| dpd 有没有拿到包 | `dpdctl stats`（`pkt_total/neigh_ok/redirect_ok`） | 加速器视角 |
| honk 用户态有没有拿到包 | **`/sys/class/net/dae0/statistics/tx_packets`** | 用户态路径视角（关键鉴别器） |
| 客户端有没有被服务 | http code / 出口 IP | 端到端 |

判据：

| 编号 | 流 | 预测 | 若成立说明 |
|---|---|---|---|
| P0 | honk 关，CN IP 字面量 | dpd 涨 | 计数器灵敏性对照 |
| **P1** | **honk 开，CN IP 字面量（`direct(must)`）** | **dpd 涨 且 dae0 不涨** | **共存成立：代理在跑，直连照样被 dpd 加速** |
| P2 | honk 开，CN 域名 | dpd 涨 且 dae0 不涨 | DNS 学习也 OK |
| P3 | honk 开，被代理域 | dae0 涨 且 dpd 不涨 | honk 拥有它（合理） |
| P4 | honk 开，非 CN 未定域 | dae0 涨 且 dpd 不涨 | 嗅探缺口（O-3 的靶子） |

### O-2【P0，配置】让直连判定更常"终局"

honk 只在**域名终局性确定**时才 offload 直连（F8）。而"前缀里有没有 live 的 domain
谓词"是决定性的：`fallback: direct` 的**前缀 = 全部规则**，只要有一条 `domain(...)`
规则存在，fallback 就永远不终局 → 所有未知域名连接都进用户态。

- **可做**：出厂配置里的 `domain(geosite: cn) -> direct` 与 `dip(geoip: cn) -> direct(must)`
  **高度重复**，却让 fallback 不终局。去掉它（或改成不依赖 domain 的写法）可以让
  "非 CN 的、无域名规则的直连"也回到内核。代价：CN 域名落在非 CN IP 上的少数情况
  会失去"按域名直连"的兜底。
- **注意**：只要用户策略里有"代理域名列表"（如 `domain(suffix: ipinfo.io) -> proxy`），
  fallback 就**必然**不终局 —— 内核不可能在不嗅探的前提下知道某个域名不在代理列表里。
  这不是缺陷，是信息论。所以 O-3（把域名事实喂给内核）是真正的解。

### O-3【P0，DNS 平面】让 honk 真能拿到域名事实（最大杠杆）

如果内核里有"这个 IP 对应哪个域名/哪些域谓词"的事实，`domain(geosite: cn)` 这类规则
就能在内核直接判定 → verdict 终局 → **直连 offload、代理也少一次往返**。

现状**未验证**的点：LAN 的 DNS 是 `dnsmasq(:53) → SmartDNS(127.0.0.1:6053)`（我们自己的
`router-dns` 包），而 honk 的 `dns.routing.request` 说明它**本意是接管 LAN DNS**。
谁真正回答客户端、honk 学不学得到，**没测过**。

- **先测**：客户端解析一个 CN 域名，看 honk 的连接表/日志里有没有该域名对应的事实
  （harness 的 `api.sh` 段已打印 `/connections` 与 honk 日志）。
- **若要改**：把 `:53` 的所有权交给 honk，让 honk 的上游指向 SmartDNS
  （`127.0.0.1:6053`），形成 `客户端 → honk(学习+分流) → SmartDNS(缓存/优选) → 上游`。
  收益：内核域名事实完整；SmartDNS 的能力保留。代价：DNS 关键路径多一跳，honk 挂了
  要能回落（dnsmasq 直接读 SmartDNS 或 223.5.5.5）。
- **不改的后果**：如 P4 —— 未知域名直连全部走用户态，和"代理就不能加速"的体感一致。

### O-4【P1，数据面缺陷】加速路径没有 MSS clamp

**实测 F5**：`mtu_fix` 在（fw4 会给**转发**流量 clamp），但**dpd 的加速路径根本不进
netfilter forward**（FIB + `bpf_redirect_neigh` 直接出 WAN），而 dpd 自己不做 MSS，
einat 的注释也把 MSS 明确推给 firewall。结果：

- 不加速的转发：MSS 被 clamp ✓
- **dpd 加速的转发：没有 clamp ✗** —— 客户端按 1500 通告 MSS，PPPoE(1492)/隧道
  WAN 上要靠 PMTUD 兜；一旦 ICMP frag-needed 被挡，就是大包黑洞（小包正常，最典型的
  "网页能开、下载卡死"）。

修法：在 dpd 里对 TCP SYN / SYN-ACK 做 clamp（landscape 的 `tc_mss` 同款），
按出口 MTU − 头长算，两个方向都要。优先级 P1，因为它**只影响加速路径**，
而加速路径正是我们要推广的东西。

### O-5【P1，隧道侧】代理流量的外侧腿：BBR + socket 缓冲

代理流的**里侧腿**（客户端 ↔ honk）注定过用户态，拿不回性能；能优化的是
**外侧腿**（路由器 → 真实节点的那条 TCP）：

- 内核**没有 BBR**（F4，只有 cubic）。国际线路 + 丢包下这是实打实的吞吐/时延损失。
  加 `CONFIG_TCP_CONG_BBR=y`（内核 config 片段）并让 `default_qdisc=fq`。
  还要看 honk 的 `auto_config_kernel_parameter: true` 到底设了哪些 sysctl（别互相覆盖）。
- `net.ipv4.tcp_rmem/wmem`、`net.core.rmem_max/wmem_max` 拉高（大带宽×高 RTT 的
  BDP 需求），以及 `tcp_notsent_lowat`。
- 这是"代理侧"唯一能拿到真实收益的方向：加密与用户态拷贝拿不掉，但拥塞控制能换。

### O-6【P2，可选】NAT 目的锁定（landscape 的 NAT 细节）

landscape 默认"目的锁定"（同一内部端点只允许第一个外部目的），按域/按 IP 开全锥例外，
用来压 PCDN 端口消耗。我们的红线是**全锥必需**（BT/PT/游戏），但可以加一层
**例外表**：对指定集合（如 PCDN 对端）使用目的锁定，其余全锥。属于安全/隐私口径，
不是性能，排在后面。

### O-7【P2】我们自己的"DNS → map"平面

landscape 的核心能力。对我们来说它的价值**不在 honk 在的时候**（那时 honk 自己判定，
我们去抢判定只会制造不一致），而在：

- honk 不在时，dpd 的加速策略可以从"`policy allow_all` 全加速"升级成"按域/按集合分流"；
- 为 O-2 的"子集证明"提供数据源（用**同一份** geo 数据与配置生成，保证我们的 direct
  集 ⊆ honk 的 direct 集）。

先做 O-1/O-3；O-7 是它们结论确定后的延伸，不要抢在前面。

### O-8【明确不做】在 honk 前面插我们自己的 TCX 判定

技术上是可行的（F2：`BPF_F_BEFORE` + `relative_id` 都在），但**不建议**：

- 一旦我们抢在 honk 前把某个包发走，honk 就永远看不到这个流；**回复方向**也会变成
  我们拥有（honk 的 `lan_egress` 会看到它没建过状态的回复包）→ 两个真相源。
- 判定不一致的后果是**代理泄漏**（该代理的直连了）。
- 唯一可接受的形式是"同源配置 + 子集证明"，收益却只是"honk 本来就会 offload 的那部分",
  除非 O-1 证伪（P1 不成立）。所以：**等 O-1 的结论**。

### O-9【文档化】UDP 精度 vs 裁掉 NFQUEUE（既有取舍，如实写）

honk README 明确：`nfqueue_enable: true` 时"holders ambiguous LAN-forwarded first
packets before conntrack/NAT"；关掉它是我们的裁剪（`docs/honk-nfqueue-trim.md`），
换来的是不依赖 `nfnetlink_queue` 与 netfilter。**代价**：含糊的 UDP 首包不再被"扣住"，
部分 UDP/QUIC/游戏流量的分流精度可能下降。这条已经存在，缺的是把它写进交付说明，
并给出"如果 UDP 分流不准，先怀疑这里"的排查路径。

---

## 6. 待跑的实验与判据（本轮就绪）

1. **`build/qemu-honk-dpd-coexist.sh`**（已上传、语法通过）：O-1 的 P0–P4 矩阵，
   判据见 §5 O-1。**必须在 closure 跑完之后单独跑**（独占 tap/QEMU）。
2. closure 的 C3 段已经证明 `dnsmasq → SmartDNS` 是真的转发（拔掉 SmartDNS 就不解析）。
   O-3 需要补的是：**honk 能不能看到这些解析**（`api.sh` 段）。
3. O-4（MSS）：先确认现状（`nft list ruleset | grep mss` 在加速流上是否真的不生效），
   再决定 dpd 内实现。

---

## 7. 风险与未决

| # | 风险/未决 | 处置 |
|---|---|---|
| R1 | honk 的 `direct offload` 是否也适用于 LAN→WAN 的**所有** `direct(must)`（本实验只覆盖 IPv4 TCP） | P1/P2 只覆盖 IPv4 TCP；UDP 与 IPv6 另测 |
| R2 | P1 若**不成立**（dae0 也涨 / dpd 不涨），说明 honk 的 offload 与它文档不一致，或我们对 TCX 顺序的理解有误 | 立刻改为抓 `bpftool net` + honk 日志 + 内核 `tracepoint` 三条证据 |
| R3 | `dial_mode: domain` 让 honk 做"域名真实性检查"，可能把更多流推给用户态 | O-3 定论后再评估是否切 `ip` |
| R4 | 改 DNS 所有权（O-3）是全链路关键路径 | 必须带回落：honk 不在时 dnsmasq 直接对 SmartDNS/上游 |
| R5 | BBR 与 honk 的 `auto_config_kernel_parameter` 互相覆盖 | 先读 honk 究竟设了什么，再决定谁写 sysctl |
| R6 | 两条朝向"更多 offload"的改动叠加（O-2 + O-3）后，代理泄漏面变大 | 每次只改一条，P3/P4 必须复测（代理域仍走代理） |

---

## 8. 定向实验的结果（2026-10-18 01:47–01:58，`build/qemu-honk-dpd-coexist.sh`）

**这个实验把 §2 的"按流分区"证伪了。** 原始日志：
`/opt/wrt/logs/qemu-coexist-run.log`（harness）+ `/opt/wrt/logs/qemu-coexist.log`（控制台）。

### 8.1 数字（全部来自这套镜像 + 真实节点 `37.123.192.246`）

| 段 | 流量 | dpd `pkt` | dpd `neigh` | `dae0 tx` | `eth1 tx` | 应用层 | 判定 |
|---|---|---|---|---|---|---|---|
| P0 | honk **关**，CN IP 字面量 `103.235.46.96`（`--resolve`，SNI=baidu） | **+38574** | **+16** | +0 | +38228 | curl (28) 超时 | ✅ 对照组：dpd 确实能看到并加速 |
| P1 | honk 开，同一 CN IP → 应命中 `dip(geoip:cn) → direct(must)` | **+0** | **+0** | +0 | +389 | curl (35) TLS connect error | ❌ **没被 dpd 看到** |
| P2 | honk 开，CN 域名 `www.baidu.com`（走 DNS） | +0 | +0 | +0 | +770 | curl (6) 域名解析失败 | ❌ 没被 dpd 看到（且 DNS 本身失败） |
| P3 | honk 开，`ipinfo.io` → 应走代理 | +0 | +0 | **+0** | +354 | 出口 IP = **37.123.192.246**（节点） | 代理**成功**，但 dpd 没看到 |
| P4 | honk 开，`ifconfig.me`（非 CN，fallback direct） | +0 | +0 | +0 | +354→+271 | 出口 IP = 113.194.4.185 | 直连**成功**，但 dpd 没看到 |

harness 自己的汇总：**PASS=12 FAIL=4**。

### 8.2 从这个结果能说什么、不能说什么

**能说的（实测）：**

1. **honk 在跑的时候，dpd 的 classic ingress 过滤器在 `br-lan` 上一种流都看不到** —— 包括
   `dae0` 也不涨。对照组（P0）在同一个目的地址上 dpd +38574，所以不是"目的地址不可达"
   造成的计数器为 0，而是**honk 的 TCX 层在这些包到达我们的 classic 链之前就把它们处理掉了**。
2. honk 的日志给出了机制线索（**实测**）：
   `INFO honk_core: Using eBPF TC redirect datapath (tproxy_mark=0x8000000)` +
   `dae0peer_ingress attached and link held`。它自己的说法是 TC **redirect** datapath：入口
   TCX 把包 redirect 进自己的管线（带 `0x8000000` mark），于是**根本不会再回到同一设备上的
   classic ingress 链**。
3. **`dae0 tx` 不能当作"honk 用户态接管"的见证**：P3 的代理**确实成功了**（出口是节点 IP），
   而 `dae0 tx` 依然是 +0。所以本文 §1 F 表里把 `dae0` 当判别器是**错的**，上一轮 closure
   用同一个判别器得出的"直连流没进 honk 用户态、只是 dpd 没数到"的结论**同样不可信**（那个
   结论现在既没有正面证据也没有反面证据）。
4. P2 的失败是**另一个平面**的问题（不是本条结论）：honk 接管了 DNS（策略里 `!dport(53)` 就是
   为它留的），而它的上游直连 DoH 失败 —— `WARN honk_core::control::dns_control: DNS controller
   forward failed; sending SERVFAIL ... upstream 'default' failed via 223.5.5.5:443`。客户端因此
   `Could not resolve host`。这与 O-3（DNS 平面）直接相关，需要单独查。
5. P3/P4 说明**数据面本身是通的**（代理出口正确、直连出口正确）—— 被证伪的是"dpd 与 honk 按流
   分工"，不是"代理能不能用"。

**不能说的：**

* 不能断定"一定是 honk 的 TCX redirect 导致 dpd 看不到"（这是最符合证据的解释，但没有直接抓到
  一次 redirect 事件；要定论得在 honk 的 TCX 程序返回点打 tracepoint，或在它前面挂一个只计数的
  探针 TCX）。
* 不能断定"direct(must) 在 honk 里是在内核完成还是去了用户态" —— dae0 见证失效后，我们**两个
  方向都没有证据**。

### 8.3 因此修正的结论

* **§2.2 的归属矩阵作废**（"`direct(must)` → 内核直连 → dpd 加速"这一格没有实测支持）。
  实测是：**honk 一开，`br-lan` 上的加速层就让位给 honk 的 TCX redirect 管线**；
  "代理 + 加速"在**当前挂法**下不是按流分区，而是**整体让位**。
* 用户最初那句话（"加速就不能代理、代理就不能加速"）**比我们文档读出来的结论更接近事实**，
  尽管原因不是"honk 把一切都送进用户态"。
* **O-8（不要在 honk 前面插我们自己的 TCX）依然成立且更必要了**：dpd 抢在 honk 前判定会破坏
  honk 的域名/终局性判定（它需要看到流才能决定 direct/proxy）。**在 honk 之前插入是不安全的**。
* 真正可走的只有两条，且都要实测：
  * **B（接受现状）**：honk 在跑时，`br-lan` 上的加速归 honk 的内核直连路径；dpd 只在 honk
    不在（或不在它挂的设备上）时生效。代价：我们自己的加速在有代理时等于不存在。
  * **C（换方向：WAN 入口）**：`eth1`/`pppoe-wan` 的 **ingress** 上 honk 没有钩子（实测
    `bpftool net show` 只有 `eth1 clsact/egress acl_egress`，那是我们的 ACL），einat 的 TCX 与
    我们的 classic 过滤器在 TCX 之后可以并存。下载方向的加速（WAN→LAN）**不经过 honk 的判定**
    （回程包的目的地是内网，不属于 honk 的策略域），这条路上 dpd 有可能真正常驻。代价：这是
    **另一个功能**（下载侧加速），要重新设计门禁与自证，且必须证明它不会碰代理流的回程。
* **下一轮最小实验**（能一次定论的）：
  1. 在 `eth1`/`pppoe-wan` ingress 挂一个**只计数**的探针（`tc filter ... bpf da`，或
     `bpftool` 的 tracepoint 统计），跑 P0–P4，看**下载方向的回程包**有多少能到达 classic 链；
  2. 对照 `bpftool net show` + `honk /connections`（这次 API 登录没拿到 token，
     `login token: <none>`，需要先修 `system.dae` 的 `password_auth` 口径）；
  3. 只在 1 有正结果时，才谈 C 方案的实现。

## 9. p1 实现：把 direct 判决交回 classic（2026-10-27）

§8.3 给出 B（接受现状）/ C（WAN 入口下载方向）。最终没有走 C，而是走了更小的改动：
**不改变 honk 的代理/block 判决，只把 direct 判决从“终止整条链”改成“交回 classic 链”**。

### 9.1 具体改动（构建期补丁，不改上游仓库）

位置：`kwrum1/openwrt-honk` 的 `ci/patches/honk-direct-unspec.py`，打在 pinned upstream commit 上。

- `crates/honk-ebpf-common/src/lib.rs`：新增 `DIRECT_UNSPEC_MARK = 0x2000_0000`
  （避开 TPROXY `0x0800_0000`、CLASSIFIED `0x4000_0000`、NFQUEUE `0x8000_0000`）。
- `crates/honk-ebpf/src/ingress.rs`：
  - 4 个 direct 出口（UDP 缓存直连、TCP 缓存直连、TCP conn-state 满、首包 direct/offload）：
    `set_mark(mark | CLASSIFIED_MARK | DIRECT_UNSPEC_MARK)` + `return TC_ACT_UNSPEC`；
  - bridge master/slave 第二次遍历：看到 `DIRECT_UNSPEC_MARK` 直接返回 `TC_ACT_UNSPEC`
    （不重新分类，也不终止 classic）；
  - `pass_through_classified`、proxy redirect、block shot 不动。
- 构建：`ci/build-core.sh` 在 checkout 后调用脚本；资产名带 `-p1`；发布到 `core-p1`
  （x86_64 / aarch64 / armv7 + sha256）。
- 包：`honk/Makefile` 安装 `/usr/share/honk/direct-unspec` 作为能力 marker；
  `system.dae` 默认 `nfqueue_enable: false`；`control.sh` 在 false 时不要求
  `nft_queue`/`nfnetlink_queue` 模块。

### 9.2 为什么这样能工作

TCX 先于 classic，且“非 UNSPEC 终止整条链”。direct 返回 UNSPEC 后：

```
客户端 → br-lan/eth0 TCX(honk)
          ├─ proxy  → redirect 到 dae0（用户态），永不进 classic
          ├─ block  → SHOT
          └─ direct → UNSPEC + DIRECT_UNSPEC_MARK
                        ↓
                     classic tc_run
                        ├─ router-acl（WAN，pref 90）
                        └─ dpd（pref 100）：学流、按 WAN 选路、重定向
```

- direct 包继续走 classic，dpd 在 pref 100 看到它，按 stateful 学流/重定向；
- proxy 包仍在 TCX 里 redirect 到 `dae0`，**不会**落到 classic；
- block 仍 `SHOT`；
- 二次遍历用 marker 位避免重复分类，同时仍放行到 classic。

NAT 不受影响：einat 的 TCX 在 WAN 上（`ingress_rev_snat`/`egress_snat`），dpd 只做转发重定向，
不碰 NAT；代理流的出口仍由 honk 自己的 socket 走 einat。

### 9.3 实测（2026-10-27，x86_64 实验台）

| 项 | 结果 |
|---|---|
| 直连 4 流 | 3.77–4.18 Gbit/s，dpd `redirect_ok` +141,559 |
| 直连 64 流 | eth2/eth3 = 1.85:1（自动权重 2:1） |
| `ifdown wan` | 切到 eth3，模式仍 `stateful`，8 流 `redirect_ok` +123,643 |
| 显式 `-> proxy` 目标 | sender 324 MB / receiver 0（无节点，按预期失败）；dpd observe 下只 +14 包 |
| 显式 `-> block` 目标 | 连接被丢弃（iperf 控制连接失败） |
| 同目标直连端口 | 3.6 Gbit/s，正常加速 |
| NAT（honk 开） | 源地址/端口仍是 einat：`198.18.0.1:21772/25787/27041`、`198.19.0.1:35334/37939/39782` |

对照：未打补丁时 honk 开、64 流全部走 eth2（`eth2 +885 MB / eth3 +238 B`）；
打补丁后同一测试是 `eth2 +1.669 GB / eth3 +0.901 GB`（1.85:1）。

### 9.4 边界与门禁

- dpd 用 `/usr/share/honk/direct-unspec` 判断 p1；上游原版 core（direct 返回 `OK`）仍降 `observe`。
  实测强行 stateful + 原版 core 会在第一个反向测试打断 TCP（`unable to receive parameters`），
  所以这个 marker 不是装饰。
- 代理流本身仍由 honk 的 `wan_interface` 单接口出口，不参与多 WAN；要代理也分流，
  需要改 honk 自己的出口选择。
- 首包仍走 honk 的策略（`direct(must)` 在内核；非 must 的 fallback direct 可能先经用户态嗅探一次），
  之后 dpd 接管。
- 没有真实节点/外网时只能验证“代理流不进 classic”（显式 proxy/block 规则 + dpd 计数器），
  实际节点转发仍需真机。
- RK 与 X86 同源：aarch64 core 在 `core-p1`，ROCKCHIP 的 `Config` 使用 `GENERAL.txt`
  （dpd + honk + ACL + QoS），没有单独的 RK 变体。

### 9.5 结论

§8.3 的“整体让位”只在**上游原版 core** 成立。p1 之后：

- **直连保持加速**（含 direct(must)/offload），多 WAN 对直连恢复；
- **代理仍走 honk**（`dae0`），不经过 dpd；
- **NAT 仍是 einat**；
- 代价是 honk 必须用 p1 core（构建补丁，不是 fork），且首包仍过 honk 策略。

