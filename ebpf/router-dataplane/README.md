# router-dataplane (`dpd-fastpath`)

eBPF 数据面快路径。一个 TC-ingress eBPF 程序 + 一个 userspace 控制工具
（`dpdctl`），目的是**把「已经建立连接的家用转发」从内核 netfilter 栈里摘出来**，
走 FIB 查表 + 直接重定向。

> 先说清楚它**不做什么**，因为这决定了它为什么可以安全地挂在一个还在跑 fw4 /
> einat / honk 的系统上：

| 红线 | 原因 |
|---|---|
| **不做 NAT** | NAT 只有一个归属：`einat-ebpf`。两处做 NAT 必然打架。 |
| **不读 einat 的 map** | 不共享 ABI 就不会随 einat 版本腐烂，也不产生启动顺序依赖。 |
| **不依赖 conntrack** | 这正是本项目的初衷之一 —— 绕开 nf_conntrack 的建流延迟。只自学（Mode B）。 |
| **只在 TC ingress** | XDP 被否决（见 `工作计划.md` §3）；TC 是唯一在 ppp / veth / bridge 上都通用的钩子。 |
| **不接管时必须让路** | 任何「不处理这个包」的分支都返回 `TC_ACT_UNSPEC`，永远让给链上后续程序。 |
| **必须是 classic `tc` 过滤器，不能是 TCX** | 见 §1：TCX 在 classic 之前跑。本项目要**排在代理之后**，所以必须留在 classic 链上。 |
| **有总开关** | `dpd_cfg.enable = 0` 时程序对一切返回 `TC_ACT_UNSPEC`，等效于不存在。 |

---

## 1. 钩子顺序（全部为实测，不是推断）

2026-10-17 在 QEMU x86_64 上，用真实镜像 + 真实 VLESS/REALITY 节点跑
`qemu-honk5.sh`，`bpftool net show` 与 `tc filter show` 的原始输出：

```
br-lan ingress :  honk TCX lan_ingress_l2         ->  dpd_fastpath (classic, pref 100)
br-lan egress  :  honk TCX lan_egress_l2
eth0  ingress  :  honk TCX lan_ingress_l2 (桥成员) ->  dpd_fastpath (classic, pref 100)
eth1  ingress  :  honk TCX wan_ingress_l2
                  einat TCX ingress_rev_snat
                  router-acl (classic, pref 90)   ->  dpd_fastpath (classic, pref 100)
eth1  egress   :  honk TCX wan_egress_l2
                  einat TCX egress_snat
                  router-acl (classic, pref 90)
dae0  ingress  :  honk TCX dae0_ingress
```

两条**互相独立**的排序事实，级联的安全性就建立在它们上面：

1. **`sch_handle_ingress()` / `sch_handle_egress()` 先跑 `tcx_run()`，再跑
   `tc_run()`。** 所以所有 TCX 程序（honk 的、einat 的）都在所有 classic
   `cls_bpf` 过滤器（router-acl 的、我们的）之前看到包。
   → **dpd 在结构上就排在拦截层后面**：honk 决定的代理流被它 `bpf_redirect` 到
   `dae0`，根本到不了我们；honk 不接的流才会落到我们手上。这就是「透明代理和
   加速层能共存」的全部原因，也是本文件最需要记住的一句话。
2. **classic 链内部按 pref 排序：** router-acl 90 < dpd 100，策略层先表态。

由此推出两条硬约束：

* **dpd 永远不能改成 TCX 程序**，否则它会跳到 honk 前面开始偷代理流。
  `/usr/libexec/dpd-fastpath.sh` 的 `dpd_chain_guard()` 在挂载时检查
  「classic 链上有没有别人的 pref 比我们大」，有就降到 observe 并记日志。
* **`TC_ACT_REDIRECT` 会终止整条链。** 所以模式设计上必须把「重定向」当成
  「我接管了」而不是「我顺手做一下」。

历史注记：早期文档（`工作计划.md` §13.16 的一部分）把 einat 写成
「pref 1 的 cls_bpf 过滤器」。**那是错的**，2026-10-17 的实测是 TCX：
`eth1(3) tcx/ingress ingress_rev_snat prog_id 88 link_id 22`。同一个错误还让
einat 的自证探针（`grep 'ifindex eth1(3) attach_type'`，只匹配**一个**空格，
而 bpftool 打的是**两个**）从来没匹配上，于是每个启动都把**正常工作的** einat
停掉了。两处都已按实测修好。

---

## 2. 模式、门禁与策略

### 2.1 模式（`option mode`）

| 模式 | 值 | 行为 | 用途 |
|---|---|---|---|
| `off` | 0 | 只看计数，不改包 | 挂上但不介入 |
| `observe` | 1 | 做 `bpf_fib_lookup`，只计数，绝不碰包 | 排障第一步；门禁不满足时的兜底 |
| `stateless` | 2 | 每个可转发包：减 TTL 后重定向 | 每包都重跑 `bpf_fib_lookup`；`downlink` 在此模式下被拒绝 |
| `stateful` | 3 | 首包学习、后续命中直接重定向（每方向前两个包仍过栈） | **默认**：每包成本最低，且是 `downlink` 唯一允许的模式 |
| `neigh-probe` | 9 | 专门回答「`bpf_redirect_neigh()` 在本机/本链路到底能不能用」 | `#14` 的运行时验证 |

### 2.2 门禁：`mode` 只是**请求**，不是结论

接管一个包 = 让包**绕过 netfilter**。所以加速能不能开，取决于环境是否支持，
而这件事在**启动时由脚本判定、并把理由写进日志**，不靠用户读文档：

| 门禁 | 判定 | 不满足时 |
|---|---|---|
| **einat 是否已挂上** | 匹配 einat 自己的程序名（`ingress_rev_snat`/`egress_snat`），**不是**「WAN 上有没有 TCX」—— honk 的 `wan_ingress_l2` 也是 TCX | 降级为 `observe`，日志说明「加速流的回程会被 fw4 丢掉」 |
| **classic 链上有没有人排在我们后面** | `dpd_chain_guard()` | 降级为 `observe` |
| **是不是上行口** | 与 netifd 的 wan/wan6 设备比对；配置里写了也不挂（`downlink=1` + `stateful` 时例外，由 `dpd_reconcile_uplink()` 显式挂载） | 跳过该口并记日志 |
| **IPv6** | BPF 程序内判定（`dpd_may_accelerate()`） | 返回 `TC_ACT_UNSPEC`，计 `v6_skip` |
| **端口 53** | BPF 程序内判定（`dpd_is_dns()`） | 返回 `TC_ACT_UNSPEC`，计 `dns_skip` |
| **IPv4 分片** | BPF 程序内判定（`frag_off`） | 返回 `TC_ACT_UNSPEC`，计 `frag_skip` |

**为什么 :53 一定不能加速**：镜像默认 `option dns_redirect '1'`，fw4 会把
LAN→WAN 的 :53 **DNAT 到路由器自己**，让 dnsmasq/SmartDNS 回答，这样客户端即使
硬编码了 8.8.8.8 也照样拿到路由器（带 SmartDNS 规则）的答案。这个改写发生在
netfilter 里，也就是**我们这个钩子后面**。2026-10-17 在 QEMU 实测：客户端
`resolv.conf` 指向 223.5.5.5 时，加速开启 → `curl (28) Resolving timed out`，
后续所有 HTTPS 全失败；把 dpd 切回 `observe`，同一个客户端立刻正常。**一个只在
DNS 上发生的静默故障是不能发布的**，而 DNS 在加速收益里本来就是噪声，所以让路。
同一窗口内也不会有任何包被接管（闭包脚本会断言这一点）。

**为什么分片也一律不加速**：L4 头只存在于第一个分片，所以既没有诚实的流键
（Mode B 会拿到假端口），也没有可用于 :53 判定的端口。整串分片交给内核栈，
这也正是 einat 建立绑定所需要的。

为什么加速**必须**依赖 einat：接管包的流没有 conntrack 记录，回程之所以还能
被接受，全靠 einat（无 conntrack 的 NAT，挂在 WAN 的 TCX 钩子上）在启动时往
fw4 里注入的那条**兜底 WAN→LAN accept**。einat 不在，回程必丢。所以
**einat 一旦起来或停掉，会立刻跑 `/usr/libexec/dpd-gate-refresh`
重新判定**，而不是等下次重启。

IPv6 同理：本基线没有 NAT66（有意），回程没有 conntrack 状态会被 fw4 拒掉，
所以 v6 一律不加速，直接让内核栈处理。

### 2.2.1 与 honk 共存的真实形态（实测，2026-10-17）

**结论：honk 在跑的时候，datapath 是 honk 的；dpd 原地待命，一包不漏地让开，honk
一停就自动接管。**

依据是内核机制，不是优先级约定：`sch_handle_ingress()` / `sch_handle_egress()` 先跑
`tcx_run()`、再跑 `tc_run()`，所以**所有 TCX 程序（honk 的）都在所有 classic
过滤器（我们的）之前**；而返回 `TC_ACT_REDIRECT` 会**直接终止整条链**。honk/dae 的
`lan_ingress_l2`/`lan_egress_l2` 恰恰就是这种程序——它自己就做内核态转发（direct 流
直接改写 L2 发出，proxied 流重定向进 `dae0`）。于是：

| 状态 | 实测 |
|---|---|
| honk 未运行 | LAN 客户端直连被 dpd 接管：`neigh_ok +13`、`eth1 tx +1040`、`curl` 拿到公网 IP（闭包 C 段） |
| honk 运行中 | 同一客户端三条流：`pkt_total 144401 → 144401`（**一条都没进到我们**），而流量本身完全正常（honk 里 direct/proxied 都是对的，闭包 E 段 `113.194.4.185` vs `37.123.192.246`） |
| honk 运行中，我们还在吗 | 在。`bpftool net show` 里 `br-lan(5) clsact/ingress dpd_fastpath.bpf.o:[classifier] id 10` 一直都在（**没有人偷偷把我们摘掉**），只是 classic 链轮不到执行 |

所以 `pkt_total` 在 honk 起来后**不涨是正常的**，不是故障。`dpd status` 现在会直接把
这点打出来（`TCX ahead of us: …`），不需要有人再去读这段内核源码。

**这是「note」而不是「gate」，是刻意的**：门禁（`mode` 从 `stateless` 降到
`observe`）需要**事件**才能重判，einat 有这个事件（我们给它加了
`/usr/libexec/dpd-gate-refresh` 回调），honk 没有。把它做成门禁就意味着「honk 来过
一次之后 dpd 永远停在 observe」——比不加速更糟。所以只报告事实、不改变行为。

### 2.2.2 honk p1：把直连判决交回 classic（2026-10-27）

上游 core 的 direct 出口返回 `TC_ACT_OK`，所以上面那张表是准确的：直连也进不了
classic。honk 包 **p1** 把 direct 出口改成 `TC_ACT_UNSPEC` + 专用 mark
（`ci/patches/honk-direct-unspec.py`，不改上游仓库，只作为构建补丁）：

| 流 | 判决 | dpd |
|---|---|---|
| direct（含 must/offload） | `UNSPEC` + `DIRECT_UNSPEC_MARK` | **进入 classic，正常加速** |
| proxy | redirect 到 `dae0` | 不进 classic |
| block | `SHOT` | 不进 classic |

门控用 `/usr/share/honk/direct-unspec` 识别 p1；没有这个 marker（上游原版 core）
仍然降为 `observe`，避免用不完整的流表去加速 WAN 回程（实测强制 stateful 会把
TCP 控制连接打断）。

实测（实验台，honk 运行中，p1）：直连 4 流 3.77 Gbit/s，`redirect_ok` +141,559；
64 流 eth2/eth3 = 1.85:1；`ifdown wan` 切到 eth3 且保持 stateful；显式
`-> proxy` 的目标在 dpd observe 下只 +14 包（不进 classic）；同目标直连端口
3.6 Gbit/s 正常加速；NAT 仍是 einat。

代理流本身仍由 honk 的 `wan_interface` 单接口出去，不参与多 WAN。

### 2.3 策略：哪些段允许被加速（`option policy` + `option vlans`）

| policy | 含义 |
|---|---|
| `allow_all`（默认） | 所有 IPv4 转发包都可以接管 |
| `vlans_only` | 只有 `vlans` 列表里的 VLAN id 可以；**未打标的包一律不加速**（fail-closed） |

`vlans_only` 的用处是多段/多 zone 的机器：那里「LAN→LAN 跨区转发」如果被加速，
就会绕过区内防火墙规则。单 LAN 的基线不需要它。

```sh
# 例：只加速 VLAN 10 和 20
uci set dpd_fastpath.global.policy='vlans_only'
uci add_list dpd_fastpath.global.vlans='10'
uci add_list dpd_fastpath.global.vlans='20'
uci commit dpd_fastpath; /etc/init.d/dpd-fastpath restart
dpdctl show           # 打印 policy 与当前 vlan 列表
```

VLAN 列表每次启动都**从 uci 重建**（先 `vlan flush`），不会留下没人看得见的
残留条目。

### 2.4 `redirect` 策略（`option redirect`）

* `auto`（默认）：**以太网出口上用 `bpf_redirect()`**，直接把 `bpf_fib_lookup()`
  已经给出的 `dmac`/`smac` 写进以太头，然后 `bpf_redirect(ifindex, 0)`；其余情况
  （ppp/隧道/VLAN 子接口/无邻居）退化到 `bpf_redirect_neigh()`。
* `neigh`：一律 `bpf_redirect_neigh()`（ABI 6 之前的行为，留作逃生口）。
* `dev`：一律 `bpf_redirect(ifindex, 0)`，不改写 L2 头（ppp/veth 专用）。

**为什么 `auto` 不再每包 `redirect_neigh`**：`bpf_redirect_neigh()` 只是把包收下
（立刻返回 `TC_ACT_REDIRECT`），真正的路由查找和邻居解析发生在之后的
`skb_do_redirect() -> __bpf_redirect_neigh() -> bpf_out_neigh_v4()` 里，也就是**每个包
再做一次 `ip_route_output_flow()` + 邻居查表**，然后用邻居表里的 `ha` 和出口设备的
`dev_addr` 拼 L2 头。而这两样东西 `bpf_fib_lookup()` 刚刚已经填在 `fib.dmac` /
`fib.smac` 里了（实测确认非零，见 §5）。所以以太网出口上完全可以把同样 12 字节拷进
以太头，再 `bpf_redirect(ifindex, 0)` —— 丢掉的是**每包一次 FIB + 一次邻居查找**，
得到的是同一帧。这是内核数据面的工作量，和网卡/平台无关，x86 与 ARM64 同等受益。

不适用（自动回落 `redirect_neigh`，都是"这一帧不该由我们拼头"的情形）：

| 情形 | 原因 |
|---|---|
| 入向帧带 VLAN tag | tag 在帧里；若出口本身是 VLAN 子接口，`dev_hard_header()` 会再压一个 |
| 出口设备是叠层设备（`DPD_IF_F_LOWER`：vlan/veth/macvlan/隧道，`iflink != ifindex`） | `dev_hard_header()` 不只是拷 12 字节 |
| `bpf_fib_lookup` 只靠 `BPF_FIB_LOOKUP_SKIP_NEIGH` 才成功（ppp/隧道） | 根本没有邻居可写 |
| `dmac`/`smac` 为全零 | 不可信，不猜 |

`auto` 的退化路径是**刻意的**：`bpf_redirect_neigh()` 需要邻居子系统解析下一跳，
而 ppp 口没有 ARP，理论上不适用。

### 2.5 回程方向（`option downlink`）

**2026-10-27 起默认开**，但只对 `mode=stateful` 生效（其他模式下初始化脚本和热插拔都会
把它当 `0` 并写日志）。打开后初始化脚本会把**同一个对象**也挂到上行口（`wan`/`wan6`
解析出的设备）的 ingress 钩子，于是 WAN→LAN 方向已学到的流也能直接重定向回 LAN，不再
走 netfilter。

实测（§5，n=3 交错）：下载 2931 → 3410 Mbit/s（+16%，CPU 64%→66%），上传 4921 →
5233 Mbit/s（+6%，对端的 ACK 流也被接管）；9 秒下载里 netfilter forward 钩子从
148302 个 skb 降到 6 个。

#### 为什么可以默认开（三条实测事实，不是推断）

1. **"新建入站连接"根本轮不到我们。** einat 的 `ingress_rev_snat` 是 TCX，跑在
   netfilter 之前；它没有映射的 WAN→LAN 包在 **prerouting 之前就被丢掉**。实测
   （2026-10-27）：einat 挂着时，从 WAN 侧向 LAN 主机发 SYN，`prerouting priority
   -350` 的探针计数为 0，连接超时；把 einat 停掉，同一个 SYN 立刻被转发（对端回 RST）。
   所以这条钩子**只可能看到 einat 已经 SNAT 过的那条流的回程**，不存在"WAN 上的陌生
   包被 dpd 直接塞进 LAN"的路径。（顺带说明：带 einat 的盒子上，fw4 的端口转发 /
   DNAT 本来就不工作，与 dpd 无关。）
2. **发往路由器自己的包不受影响。** 转发钩子只在目的地址要经 br-lan 出去时命中；
   `bpf_fib_lookup` 对本地地址返回的区域被 `fib.ifindex == skb->ifindex` 挡住。
3. **快路径中断不会断流。** 实测：34 秒下载，第 10 秒 `dpdctl set mode off`（等价于
   重启/看门狗接管），下载继续完成（11 次重传，无停顿）。原因是 einat 在 netfilter
   之前就改好地址，而 fw4 里 einat 注入的 WAN→LAN 全量 accept 还在。

#### 风险边界（哪些东西看不到被接管的回程包）

被接管的包在 eth1 ingress 的 classic 链之后直接 `bpf_redirect()` 到 br-lan，因此它们
**不经过**：

* `nf_conntrack` 的记账和状态机（`/proc/net/netfilter/nf_conntrack` 里那条流的
  `packets/bytes` 不再增长；`nf_conntrack_count` 不会因为大流量增长，这是好事）；
* fw4 的 `forward` 链：包括 `ct state` 之外的**用户规则**、`mangle_forward`（MSS
  clamp，但只对 SYN 生效，而 SYN 是首包，仍会走栈）、以及 fw4 的每 zone 计数器；
* 任何 nft 的 `limit` / 每流 `counter` / 动态黑名单：它们只看到一条流的头几个包。

**仍然能看到**：einat 的 TCX（NAT）、router-acl（pref 90，在我们之前）、桥/邻居层。
所以 ACL 和 NAT 语义不变，丢的是"逐包记账/逐包限速"。

需要逐包统计下载方向（例如用 nft counter 做流量配额、或按流限速）的盒子，把
`option downlink '0'` 关掉 —— 这是该选项唯一的取舍。

#### conntrack 与 `flow_ttl_ms` 的关系（ABI 7 的 priming）

`flow_ttl_ms`（默认 5000）只管**我们自己**的流表新鲜度，与 conntrack 超时无关。ABI 7
之前有一个真实窗口：stateful 模式在**第二个**包就开始接管，于是 TCP 三步握手的最后一个
ACK 也被接管，conntrack 永远停在 `SYN_RECV`（实测一条 12.4 GB 的下载在表里就是
`packets=1 bytes=60`），并在 120 秒的 `syn_recv` 超时后**在流还活着的时候被删掉**。

ABI 7 起每个方向先"喂" `DPD_FLOW_PRIME`（1）个包给栈，即一条流的前两个包（SYN、
ACK）仍然过 netfilter：握手完成、条目进入 `ESTABLISHED`（超时 7440 秒），
`nf_conntrack_count`、`ct state` 规则、以及"快路径停掉后回退到慢路径"都保持有意义。
代价是每条流两个包，不改变 value 布局（计数器放在 `dpd_flow_val.flags` 的高字节）。

UDP 没有握手，`nf_conntrack_udp_timeout_stream`（180 秒）在加速流上不会被子刷新，
条目会过期；这对转发无影响（见上面第 3 点），但意味着 UDP 的 conntrack 记账必然失真。

热插拔（`90-dpd-fastpath`）在 `downlink=1` 时也会在 pppoe 重拨后补挂，否则新设备
出现后回程会悄悄失去加速。`dpd_reconcile_uplink()` 在 `downlink=1` 时是"挂载 + 链
检查"，否则保持原来的"强制卸载"；`dpd_wait_for_dev()` 里晚到的上行口也走同一个决定。


**实测结论（2026-10-17，x86_64 QEMU，`build/qemu-dpd-diag.sh`）**：以太网 WAN 上
`bpf_redirect_neigh(ifindex, NULL, 0, 0)` 的 NULL-params 路径**确实能用** —— 出厂
`stateless` 下 LAN 客户端 `ping 10.0.2.2`（WAN 直连邻居，无网关）与 `ping 8.8.8.8`
（经网关）都是 2/2 0% loss，同期 eth1 `tx_dropped` 0 → 0。它内部会自己做
`ip_route_output_flow()`，**不依赖 `skb_rtable`**（见 §5 关于「`neigh_ok` 不算证据」
那一段）。ppp 链路仍未实测，`auto` 仍按 `IFF_NOARP|IFF_POINTOPOINT` 退化到
`bpf_redirect()`。

---

### 2.6 ABI 9：每包成本与缓存失效（2026-10-28）

评审（`ebpf-honk-深度优化与风险修补方案`）的 P0/P2 项落在这一版。原则没变：
**先证明哪些包可以安全加速，再降低这些包的处理成本**；没有为了跑分而放宽任何门禁。

#### 2.6.1 命中路径的 map 查询次数

| 版本 | 每包 map 查询 | 说明 |
|---|---|---|
| ABI 8 | `dpd_cfg` + 每计数器各一次 `dpd_stats`（2–5 次）+ `dpd_flows` + 多 WAN 时 `dpd_wans` + `dpd_iface` | 计数器越多越贵；每次都重新判断出口能力 |
| ABI 9 | `dpd_cfg` + `dpd_stats`（1 次，块结构）+ `dpd_flows` | 出口方式、epoch 都在流表项里 |

* `dpd_stats` 从「每个计数器一个 array key」改成 **每 CPU 一个整块**
  （`struct dpd_stat_val`），一次查询后连续自增；`dpdctl stats` 负责跨 CPU 求和。
* 出口方式（`L2` 写头 + `bpf_redirect` / `DEV` 直接 redirect / `neigh`
  回落）在**学习时判定一次**并写进 `dpd_flow_val.flags`，命中路径不再查
  `dpd_iface`、不再重跑 AUTO 决策。
* 多 WAN 命中不再逐包校验 `dpd_wans`（那不是热路径该做的事，见下）。

#### 2.6.2 代际号（`dpd_cfg.epoch`）与事件驱动失效

「流空闲超时没过」并不等于「缓存里的出口/邻居还有效」。ABI 9 给每条流记录
**学习时的代际号**（存在 `dpd_flow_val.wan` 的高字节），命中时只比一个字节；
不一致就当作 miss，回慢路径重新学习。

谁推进代际号（`dpdctl bump`）：

| 事件 | 调用点 |
|---|---|
| 接口 up/down/地址变化（含 PPPoE 重拨） | `/etc/hotplug.d/iface/90-dpd-fastpath` |
| 多 WAN 表被重写（增删 WAN、权重/健康变化） | `ebpf-mwan` 写完 `dpd_wans` 之后 |
| 运维手动 | `dpdctl bump` |

代价是「一次全家失效」：代际号一变，所有流各多走 1–2 个慢包。相比逐包重校验
（每包多两次 map 查询），这个交换在所有已测场景里都是赚的；真要定向失效，
需要把路由/邻居事件映射到具体流，留作后续（评审 §3.2 的 P2）。

#### 2.6.3 时间戳限频（`option flow_refresh_ms`，默认 250）

命中路径只在距上次刷新超过 `flow_refresh_ms` 时写 `last_seen_ms`，省掉每包一次
脏 cacheline 写。语义影响只有一个方向：**entry 最多比 `flow_ttl_ms` 多活
`flow_refresh_ms`**（即"缓存得久一点"），绝不会让活跃流提前失效。设 0 恢复逐包刷新。

#### 2.6.4 GSO/MTU：按"一个分段"的真实长度判断

`skb->gso_size` 是**负载**长度，不含 IP/L4 头。ABI 8 直接拿它当分段长度，
比真实分段短 28–60 字节，可能放行一个实际超过 MTU 的分段。ABI 9 按协议计算：

```
TCP: iph->ihl*4 + th->doff*4 + gso_size
UDP: iph->ihl*4 + 8          + gso_size
```

分片、`:53`、DHCP、非单播、IPv6 这些门禁提前到 `bpf_fib_lookup()` **之前**：
它们永远不可能被加速，就不该付一次路由查询。

#### 2.6.5 已做的验证

* CI `BPF-CHECK` 在 Ubuntu 上编译同一份源码（clang -target bpf），ABI 读出 9。
* 实验机（x86_64，内核 6.18）`:  新对象通过 verifier（`tc filter add` 成功），
  `bpftool map dump dpd_cfg` 显示新字段，`dpd_stats` 块结构与 20 个计数器对应。
* 功能：172k 包命中、54 条流学习、`redirect_ok == flow_hit`；代际号 +1 后
  同一批流被重新学习（`flow_write` 增长）再命中。
* 吞吐 A/B：本实验机是共享 ESXi（1–2 vCPU，跨轮波动 ±40%），ABI 8 与 ABI 9 的
  差值落在噪声里，**不作为收益证据**；能确证的是上表的每包工作量减少。
* `/usr/libexec/dpd-regress.sh`（随包安装）：ABI 对齐、observe/off 仍转发、
  门禁计数、epoch 失效、MTU 1500/1492/1400 矩阵、钩子清单。实验机上一次跑通
  （`RESULT: pass`，ABI 8 上跳过 bump/abi 两项，ABI 9 镜像会全跑）。

#### 2.6.6 多 WAN、mark 与策略路由的边界（评审 §3.4）

* 流键包含 `ingress ifindex + family + proto + saddr + daddr + sport + dport`，即
  "同一源/目的" 在内核里必然命中同一条 `ip rule`，所以缓存出口与首包一致。
* 我们只写 `fwmark` 规则和每 WAN 的路由表（`ebpf-mwan`），不改别的策略。
  如果运维另加了基于源地址/接口的 `ip rule`，而那条规则在第一包之后才变化，
  缓存会短暂落后——`ifupdate`/`ifdown` 都会 bump 代际号，把这类情况收敛到
  "最多错一个事件周期"。
* 多 WAN 表每次重写后 `dpdctl bump`：旧表里选中的 WAN index 和 MAC 对不会再被
  用来发包（宁可多两个慢包，也不把包发到错的口）。

#### 2.6.7 流表布局（评审 §4.5，暂无动作）

`dpd_flow_val` 保持 24 字节、`dpd_flow_key` 保持 48 字节：两者都是 pinned-map
ABI 的一部分，改大小会让升级后的 `tc filter add` 直接失败。ABI 9 已经用"高字节
放代际号"把新信息塞进现有布局；继续压缩（例如 v4 用 32 字节键）要等 §10 的
高并发流表测试给出 hit/miss 与内存曲线，先不做。

#### 2.6.8 相关但不是数据面的两个旋钮

* `router-tuning` 新增 `option mode 'throughput|balanced|latency'`：只影响
  coalescing 与 `txqueuelen` 的取向（ring 保持驱动最大值），默认 `balanced`；
  `router-tuning report` 会打印它实际会写什么。
* `router-qos` 新增 `option profile 'auto|throughput|latency'`：`auto` 仍是按链路
  速率选 cake/fq_codel；`latency` 固定 cake 并用 `rtt 10ms` 缩短 AQM 目标，
  `throughput` 固定 fq_codel。默认路径没变。

#### 2.6.9 IPv6（ABI 10，默认开启，上下行都加速）

`option ipv6 '0'` 可关闭（6rd/6to4、v6 隧道、首包后改策略路由的环境）。

**范围**：只接管 **TCP/UDP**；扩展头（hop-by-hop/routing/dest-opts/fragment）、
分片、组播 `ff00::/8`、link-local `fe80::/10`、未指定地址、端口 53、
DHCPv6（546/547）、hop_limit<=1 一律拒绝。只加速**出站发起**的流：从 WAN 侧
主动进来的 v6 连接留在栈上（与 v4 一致——v4 的入站 SYN 在 einat 那层就被丢了）。

**为什么上下行都能加速，而且不靠 WAN 侧 FIB**：

v4 的回程靠 einat：它在自己的 TCX 钩子上把回包的 L3/L2 改写好了，dpd 在 WAN
入口学到的就是"已经翻译过"的流，所以下行条目自然正确。

v6 没有 NAT66，回包是普通路由包。如果让 WAN 入口自己去 FIB 学这条回程，就依赖
那一刻的邻居/路由状态（早期实测就学到过 `ingress=wan egress=wan` 的坏条目，把
会话打死）。所以改成**在学上行流的那一瞬间，用手里这一帧的 L2 直接种下反向条目**：

```
上行帧（LAN→WAN）：dmac = 路由器 LAN MAC，smac = 客户端 MAC
反向条目：        ingress = 上行出口（WAN 设备）
                  egress  = 上行入口（LAN 设备，即 skb->ifindex）
                  dmac    = 上行帧的 smac（客户端）
                  smac    = 上行帧的 dmac（路由器 LAN MAC）
```

两个方向都是普通以太网、MAC 就在帧里，不需要邻居表、不需要第二次 FIB，也不存在
"反向条目指向错的设备"这一整类问题。反向条目从 `prime=0` 开始，所以回程的前 1 个
包仍然过栈——conntrack 先看到回包，之后才由快路径接手。

**不做的情况**：带 802.1Q 标签的帧（需要重新压标签，交给栈）、入站主动发起的
连接、非 TCP/UDP、以及上面列的所有拒绝项。多 WAN 选路只对 v4 生效，v6 跟随 FIB
选出的路由（`mydist-mwan` 的 fwmark 表是 v4 的）。

**2026-10-28 的两条实测结论，以及对应改动**：

| 现象 | 改动 |
|---|---|
| honk 运行时 v6 TCP **完全不通**（停 honk 恢复 2.2 Gbit/s） | `router-dns` 的 honk 补丁块新增 `dip('::/0') -> direct(must)`：v6 一律直连，不进代理 |
| 让 WAN 入口自己学回程，出现 `ingress=eth2 egress=eth2` 的坏条目，会话中断 | 回程改为"学上行时用帧内 MAC 预置"，WAN 入口不再学 v6 流 |

## 3. 文件

```
ebpf/router-dataplane/
├── Makefile                      # OpenWrt 包定义；不用 CompileBPF（宿主缺 llc/opt/llvm-*）
├── src/
│   ├── dpd_common.h              # BPF ↔ dpdctl 的共享 ABI、红线、钩子布局
│   ├── dpd_fastpath.bpf.c        # 全部模式 + neigh-probe，单次 clang -target bpf -O2 -g
│   └── dpdctl.c                  # userspace 控制/观测工具（libbpf）
└── files/
    ├── dpd_fastpath.init         # procd 服务 + 门禁（gate 逻辑在共享库里）
    ├── dpd-gate-refresh          # 重跑门禁（einat 起/停时调用）
    ├── dpd_fastpath.sh           # tc 挂/卸 + 接口解析 + 门禁/链检查
    ├── dpd_fastpath.config       # /etc/config/dpd_fastpath 默认值
    └── 90-dpd-fastpath           # hotplug：WAN 设备名出来后补挂（同样过门禁）
```

BPF map（全部 `LIBBPF_PIN_BY_NAME`，ABI 版本 `dpd_common.h` 的
`DPD_ABI_VERSION`）：

| map | 类型 | 用途 |
|---|---|---|
| `dpd_cfg` | ARRAY(1) | mode / enable / redirect / ttl / **policy** |
| `dpd_stats` | PERCPU_ARRAY | 计数（含 `v6_skip` / `vlan_skip`） |
| `dpd_flows` | LRU_HASH | Mode B 自学习表 |
| `dpd_iface` | HASH(64) | 接口 L2 能力（NOARP / POINTOPOINT） |
| `dpd_vlans` | HASH(64) | `vlans_only` 的段白名单 |

### 为什么不用 `CompileBPF`

`include $(INCLUDE_DIR)/bpf.mk` 只用来拿 `$(CLANG)` / `$(BPF_DEPENDS)`。
`CompileBPF` 需要宿主的 `llc` / `opt` / `llvm-dis` / `llvm-strip`，本机没有，
且 `staging_dir/host/llvm-bpf` 不存在。所以编译是单步的：

```
clang -target bpf -g -O2 -c dpd_fastpath.bpf.c -o dpd_fastpath.bpf.o
```

宿主已有 `CONFIG_USE_LLVM_HOST=y` + `CONFIG_HAS_BPF_TOOLCHAIN=y`，用系统
`clang`（20.1.8，BPF backend 正常），**不构建也不下载 `llvm-bpf`**。

### 为什么头文件从 staging 取

`bpf-headers` 包会把 Linux 钉在 6.12，而本机 `dl/` 里只有
`linux-6.18.55.tar.xz`（`linux-6.12.tar.xz` 未缓存）。所以：

* libbpf 侧：`$(STAGING_DIR)/usr/include`（`bpf/bpf_helpers.h` 等，libbpf 装好的）
* UAPI 侧：`$(TOOLCHAIN_DIR)/include`（`linux/bpf.h`、`linux/pkt_cls.h`）

### 为什么必须是 classic `tc` 而不是 TCX

**这是架构决定，不是偏好**：TCX 在 classic 之前跑（§1），而本项目要求排在拦截层
**之后**。所以：

```
tc filter add dev <if> ingress pref 100 handle 100 bpf da obj dpd_fastpath.bpf.o sec classifier
```

（本机 libbpf 也没有 `bpf_tc.h`，走 classic 反而少一层依赖。）

`sec classifier` 是对的：iproute2 的 `bpf_prog_to_default_section(BPF_PROG_TYPE_SCHED_CLS)`
就是 `classifier`（源码里确认过）。因此镜像里加的是 **`tc-bpf`**，
不是 `tc-full`（后者会把 `libxtables` 一起拖回来，与裁剪目标冲突）。

---

## 4. 编译期自检

```sh
# 编译产物应包含这些 section
llvm-readelf -S dpd_fastpath.bpf.o | grep -E 'classifier|\.maps|\.BTF'
# 期望 map：dpd_cfg dpd_stats dpd_flows dpd_iface dpd_vlans
strings -a dpd_fastpath.bpf.o | grep -E '^dpd_' | sort -u
```

`dpdctl` 应只依赖 `libbpf.so.1 libelf.so.1 libz.so.1 libgcc_s.so.1 libc.so`。

已踩过的坑（都在源码里留了注释）：

* `__section()` 在本机头文件组合下不可用 → 用 `SEC()`。
* `struct vlan_hdr` 在 6.18 的 `linux/if_vlan.h` 里已经没了 → 本包自带 `struct dpd_vlan_hdr`。
* `AF_INET` / `AF_INET6` 不会被 `linux/bpf.h` 带进来 → 自己 `#define` 守卫。
* `bpf_l3_csum_replace()` 的语义是 `sum += from - to`，`offset` 指向**校验和字段**；
  改 TTL 时要用 `bpf_htons(ttl << 8)` 作为 old/new。
* userspace 里不要调 `bpf_ktime_get_ns()`（那是 BPF helper）→ `clock_gettime(CLOCK_MONOTONIC)`。

---

## 5. 运行时验证状态

已实测（QEMU x86_64，2026-10-17，真实镜像）：

| 项 | 证据 |
|---|---|
| FIB 判定可用 | `fib_ok` 随流量增长，`fib_fail` 只在本地目的上出现 |
| **L2 直发（ABI 6）真的在用** | `redirect auto` 下 10 秒 iperf3：`redirect_ok +243872`、`neigh_ok +0`、`fib_ok +243872`（即每个包都走了"自己拼 L2 头 + `bpf_redirect`"，没有一次 `redirect_neigh`）；同一窗口客户端 `ping` 0% loss、吞吐 4.8 Gbit/s。`dpd_flows` 的原始值里 `smac` 等于出口设备 `dev_addr`（eth1 `00:50:56:3f:c3:02`），`dmac` 等于下一跳 `ip neigh` 里的 lladdr |
| **L2 直发的收益** | 同一实验台背靠背 A/B（n=5，中位数）：`auto` 4611 vs `neigh` 4680 Mbit/s（上行吞吐已在 VM 天花板，分辨不出来）；改用**固定发流**（UDP 900 Mbit/s / 260 B，两边同负载）后 CPU 24%/44% vs 27%/47%（总/最忙核，中位数 n=5），即每包成本降了约 10% |
| **回程钩子 + L2 的收益** | 下载方向（`stateful`，iperf3 -P4 -R，n=3 中位数）：只挂 br-lan 2.72 Gbit/s → 再挂 eth1 `auto` **3.44 Gbit/s**（+26%），同条件 `neigh` 2.98 Gbit/s（L2 直发再贡献 +16%）；CPU 61%→65%/75%（总/核）|
| **加速真的把包送到对端**（ICMP 端到端） | 出厂态 `stateless` 下，LAN 客户端 `ping 10.0.2.2`（WAN 直连邻居）**2/2 0% loss**；`ping 8.8.8.8`（经网关）**2/2 0% loss**；同期 eth1 `tx_dropped` 0 → 0 |
| 与 honk 共存 | honk 的 TCX 生效期间 dpd 计数仍在涨（`pkt_total` 持续 +），且 honk 仍然代理成功（§4.11） |
| 观察模式零风险 | `mode=observe` 时 `redirect_ok 0`，流量不受影响 |
| **:53 不被接管** | 客户端 `resolv.conf=223.5.5.5` 仍能解析（`dns_redirect=1` 的 DNAT 仍生效），`dns_skip` 增长，同窗口 `redirect_ok+neigh_ok` 零增长 |
| **分片不被接管** | 2500 字节 UDP 打散后 `frag_skip` 增长 |

**`neigh_ok` / `redirect_ok` 不是「发出去了」的证据**：`bpf_redirect_neigh()` 只要
参数合法就立刻返回 `TC_ACT_REDIRECT`，FIB 与邻居解析都发生在程序返回之后，失败是
静默 `kfree_skb`（`net/core/filter.c` 6.18.55 原文）。这两个计数只表示「内核接受了
请求」。**唯一诚实的证据是流量本身**：设备计数器（`eth1 tx_packets` 增长、
`tx_dropped` 不动）或对端真的回了包。闭包脚本按此断言。

**尚未实测**：ppp 链路上的 `neigh` vs `dev`（§2.4 的已知风险）仍需真机；
RK / IPQ 未做真机验证。

---

## 6. 安全开关

| 开关 | 位置 | 作用 |
|---|---|---|
| `option attach '0'` | `/etc/config/dpd_fastpath` | 完全卸载：没有任何 map 存在，`dpdctl` 无事可做 |
| `option enabled '0'` | `/etc/config/dpd_fastpath` | BPF 程序读 `dpd_cfg.enable`，对一切返回 `TC_ACT_UNSPEC` |
| `mode='off'` | `/etc/config/dpd_fastpath` | 挂载但只计数 |
| `mode='observe'` | 同上 | 做完整判定与计数，但不碰任何包 |
| `/usr/libexec/dpd-gate-refresh` | 运行期 | 手动重跑门禁（einat 起停时会自动调用） |
| `/etc/init.d/dpd-fastpath status` | 运行期 | 打印「谁占着 TC 钩子 + 门禁结论 + 配置 + 计数」 |

排障期推荐 `attach=1` + `enabled=1` + `mode='observe'`：能看到全部计数，
但对流量零影响。
