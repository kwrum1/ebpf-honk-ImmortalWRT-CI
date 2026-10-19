# router-dataplane (`dpd-fastpath`)

`mydist` 的数据面快路径。一个 TC-ingress eBPF 程序 + 一个 userspace 控制工具
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
| `stateless` | 2 | 每个可转发包：减 TTL 后重定向 | **默认**（LAN 侧） |
| `stateful` | 3 | 首包学习，后续命中直接重定向 | 需要回程也在同一张表里时用 |
| `neigh-probe` | 9 | 专门回答「`bpf_redirect_neigh()` 在本机/本链路到底能不能用」 | `#14` 的运行时验证 |

### 2.2 门禁：`mode` 只是**请求**，不是结论

接管一个包 = 让包**绕过 netfilter**。所以加速能不能开，取决于环境是否支持，
而这件事在**启动时由脚本判定、并把理由写进日志**，不靠用户读文档：

| 门禁 | 判定 | 不满足时 |
|---|---|---|
| **einat 是否已挂上** | 匹配 einat 自己的程序名（`ingress_rev_snat`/`egress_snat`），**不是**「WAN 上有没有 TCX」—— honk 的 `wan_ingress_l2` 也是 TCX | 降级为 `observe`，日志说明「加速流的回程会被 fw4 丢掉」 |
| **classic 链上有没有人排在我们后面** | `dpd_chain_guard()` | 降级为 `observe` |
| **是不是上行口** | 与 netifd 的 wan/wan6 设备比对；配置里写了也不挂 | 跳过该口并记日志 |
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

* `auto`（默认）：以太网走 `bpf_redirect_neigh()`；若目标接口
  `IFF_NOARP`（ppp 就是 `IFF_POINTOPOINT|IFF_NOARP`）则退化为
  `bpf_redirect(ifindex, 0)`。
* `neigh`：一律 `bpf_redirect_neigh()`。
* `dev`：一律 `bpf_redirect(ifindex, 0)`。

`auto` 的退化路径是**刻意的**：`bpf_redirect_neigh()` 需要邻居子系统解析下一跳，
而 ppp 口没有 ARP，理论上不适用。

**实测结论（2026-10-17，x86_64 QEMU，`build/qemu-dpd-diag.sh`）**：以太网 WAN 上
`bpf_redirect_neigh(ifindex, NULL, 0, 0)` 的 NULL-params 路径**确实能用** —— 出厂
`stateless` 下 LAN 客户端 `ping 10.0.2.2`（WAN 直连邻居，无网关）与 `ping 8.8.8.8`
（经网关）都是 2/2 0% loss，同期 eth1 `tx_dropped` 0 → 0。它内部会自己做
`ip_route_output_flow()`，**不依赖 `skb_rtable`**（见 §5 关于「`neigh_ok` 不算证据」
那一段）。ppp 链路仍未实测，`auto` 仍按 `IFF_NOARP|IFF_POINTOPOINT` 退化到
`bpf_redirect()`。

---

## 3. 文件

```
mydist/router-dataplane/
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
