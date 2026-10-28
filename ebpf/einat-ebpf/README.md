# einat-ebpf —— eBPF Full Cone NAT（NAT44 的替代品）

## 这个包解决什么

基线里 NAT 一直由 **netfilter conntrack + masquerade**（fw4 生成 nft 规则）承担。
那套东西的问题不是「能不能用」，而是：

* 它把 NAT 状态放在 conntrack 里，**和 eBPF 数据面互相看不见**；
* 它的映射行为是 **Address-and-Port-Dependent**，不是 full cone；
* 每个包都要过 nft 规则链，延迟和规则复杂度都随规则数增长。

`einat` 用 eBPF 在 TC hook 上**从零实现** Endpoint-Independent Mapping +
Endpoint-Independent Filtering，也就是 full cone NAT，不碰 conntrack。

## 关键设计约束（来自 einat 官方文档 + 本项目的红线）

| 约束 | 出处 | 本项目的处理 |
| --- | --- | --- |
| 必须先关掉一切硬件/软件 offload | einat README 的 IMPORTANT | `kmod-nft-offload` 砍不掉（firewall4 写死 DEPENDS），但默认 `/etc/config/firewall` 里没有 `flow_offloading` 行 → offload 默认关闭。彻底去掉挂账到 einat 启用那一步 |
| 必须关掉 nftables/iptables masquerade | einat README | init 用 **procd data** 往 fw4 注入一条 `type nat target ACCEPT` 规则，**不改** `/etc/config/firewall` |
| 必须允许 WAN→LAN 转发 einat 的端口段 | einat README | 同上，procd data 注入一条 `type rule target ACCEPT` |
| PPPoE / 隧道接口需要 TCP MSS clamping | einat README（issue #19） | fw4 的 `option mtu_fix` 必须保留 —— 工作计划.md §8 的 H2 |
| 内核需要 BPF + BTF + BPF-to-BPF calls | einat docs/guide/openwrt.md | x86_64 / aarch64 都满足；`DEBUG_INFO_BTF=y`、`BPF_SYSCALL=y`、`BPF_JIT=y`、`NET_ACT_BPF=m`、`NET_SCH_INGRESS=m` |
| 需要 `CAP_SYS_ADMIN` + `CAP_NET_ADMIN` | einat README | 以 root 运行（`files/capabilities.json` 也装上了，将来要降权直接启用那一行） |

## 为什么是「预编译二进制包」而不是从源码编译

上游自己的 OpenWrt 打包（`muink/openwrt-einat-ebpf`）是源码编译：

```make
PKG_BUILD_DEPENDS:=rust/host libbpf HAS_BPF_TOOLCHAIN:bpf-headers
```

这三样在我们的环境里都是纯成本：

* `rust/host` —— 要在构建主机上 bootstrap 一整套 Rust 工具链；
* `HAS_BPF_TOOLCHAIN` —— 会去下 `llvm-bpf` 工具链；
* `bpf-headers` —— 它**钉死 linux-6.12**，而 `linux-6.12.tar.xz` 不在 dl 缓存里。

而 einat 上游的 release 里已经有**完全静态**的二进制，而且用的是 `aya` loader，
**运行时不需要 libbpf/elf/zlib 任何一个**。所以直接装二进制：

* 体积 ~2.4 MB；
* 构建依赖为零；
* 不需要 rust/host。

代价：架构必须逐个列（见 Makefile 里的 `ifeq ($(ARCH),...)`），
`PKG_HASH` 必须钉死（两个哈希都是实测出来的，见 §「哈希来源」）。

## 哈希来源

```sh
curl -sLO https://github.com/EHfive/einat-ebpf/releases/download/v0.1.11/einat-static-x86_64-unknown-linux-musl
sha256sum einat-static-x86_64-unknown-linux-musl
#   d3c33347ba958f35d9ea6c81ec01b035cc2a41ac5cda074ae4589282d23981be   (2471584 B, static-pie)
curl -sLO https://github.com/EHfive/einat-ebpf/releases/download/v0.1.11/einat-static-aarch64-unknown-linux-musl
sha256sum einat-static-aarch64-unknown-linux-musl
#   93df51fd9d02c8ba651daa359a5bf05d6728650806df67ea9a35fdd43b422f76   (2102376 B, static)
```

## 为什么 `--bpf-log` / `--bpf-loader` 不写进 init

* `--bpf-log`：**解析器接受，但 `--help` 的用法文本里没有它**。
  上游 muink 的 init 无条件传 `--bpf-log "$bpf_log_level"`，那是按更新的
  einat 写的。v0.1.11 传未知选项会让服务直接起不来，所以这里不传，
  日志级别保持默认（关）。
* `--bpf-loader`：本包装的是 `aya` 那个构建产物，传 `libbpf` 会在加载阶段失败。

## 与 router-dataplane 的 hook 顺序

```
WAN ingress:  einat (pref 1)  ->  dpd_fastpath (pref 100)
LAN ingress:                      dpd_fastpath (pref 100)
```

einat 固定占用 **pref 1 / handle 1**，并且**永远不会返回 `TC_ACT_OK`**
（没接管的包返回 `TC_ACT_UNSPEC`），所以它之后的程序（我们，pref 100）
一定会看到包。这个顺序是靠 pref 决定的，不是靠插入顺序。

## 启用步骤

默认 `enabled='0'`（和 honk、router-dataplane 一致：先把已知good的
fw4 masquerade 留着，等 einat 单独验证过再切）。

```sh
uci set einat.config.enabled='1'
uci commit einat
/etc/init.d/einat restart
/etc/init.d/firewall reload      # 让 fw4 收下 procd 注入的两条规则
```

验证 full cone（在内网机器上，不是路由器上）：

* `stunclient`（stuntman）
* `NatTypeTester`（Windows）
* `go-stun`

注意：只有当外网本身是 full cone 或你有公网 IP 时，才能测出 full cone。

## 已验证 / 未验证

* 已：上游 release 资产存在、大小与 SHA256 实测、二进制是静态的（`readelf -d` 无 NEEDED）、
  `--help` 的选项集合与源码 `lexopt` 解析分支逐条核对过。
* 未：在真机/固件里跑起来（要等这一轮镜像出来之后单独验证）。
