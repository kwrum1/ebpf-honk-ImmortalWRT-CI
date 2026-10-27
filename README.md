# OWRT-CI（ebpf 版）

本仓库是 [VIKINGYFY](https://github.com/VIKINGYFY) 的 OpenWRT 云编译 CI 的二次开发版：

- **X86 / ROCKCHIP**：使用带 eBPF 数据面的新源码（[`kwrum1/immortalwrt`](https://github.com/kwrum1/immortalwrt)，分支 `mydist`）构建，honk 使用 `mydist` 分支。
- **IPQ60XX / IPQ807X / MTK**：完全保持原版逻辑 —— 源码仍是 `VIKINGYFY/immortalwrt`，honk 仍是 `main`，高通平台继续用 **NSS**，不注入任何 eBPF 数据面。

### 我该刷哪个？

| 设备 | 选这个 | 说明 |
|---|---|---|
| x86 软路由 / 虚拟机 | `OWRT-ALL` → `X86` | eBPF 数据面 + pingora 前端（本文档的主体） |
| RK3399 / RK3568 等 ARM64 | `OWRT-ALL` → `ROCKCHIP` | 同上，aarch64 版 |
| 高通 IPQ / MTK 路由器 | `QCA-ALL` / `QCA-PPE` / `MTK-ALL` | 原版 NSS，硬件加速更强，**不要**刷 X86 那套 |

### 实测速览（2026-10-27，ESXi + vmxnet3，2 vCPU）

| 指标 | 原版无加速 | eBPF 优化前 | eBPF 优化后 |
|---|---|---|---|
| TCP 单流 | 2.68 Gbit/s | 3.91 Gbit/s | **4.85 Gbit/s** |
| TCP 4 流 | 4.47 Gbit/s | 4.25 Gbit/s | **5.37 Gbit/s** |
| 64 字节小包 | 279 018 pps | 350 446 pps | **390 625 pps** |
| 固定 3 Gbit/s 路由 CPU | 53 % | 48 % | **41 %** |
| 满载 RTT | 12.73 ms | 12.38 ms | **5.24 ms** |

> 优化后吞吐、小包 pps、满载延迟三项均优于原版；低负载 CPU 三者接近，3 G 以上优化后更省。
> 方法、原始数据、噪声范围和复现脚本见 [`docs/BENCHMARK.md`](docs/BENCHMARK.md)。

---

## 1. 产物矩阵

| 工作流 | 配置 | 源码 | 分支 | honk | 数据面 | Web 前端 |
|---|---|---|---|---|---|---|
| OWRT-ALL | `X86` | `kwrum1/immortalwrt` | `mydist` | `mydist` | einat + dpd + ACL + CAKE + SmartDNS | pingora（x86_64） |
| OWRT-ALL | `ROCKCHIP` | `kwrum1/immortalwrt` | `mydist` | `mydist` | 同上 | pingora（aarch64） |
| OWRT-ALL | `IPQ60XX` | `VIKINGYFY/immortalwrt` | `main` | `main` | 原版（NSS） | uhttpd |
| QCA-ALL | `IPQ60XX-WIFI-*`、`IPQ807X-WIFI-*` | `VIKINGYFY/immortalwrt` | `main` | `main` | 原版（NSS） | uhttpd |
| QCA-PPE | `IPQ60XX-WIFI-NO`、`IPQ807X-WIFI-NO` | `VIKINGYFY/immortalwrt` | `main` | `main` | 原版（NSS/PPE） | uhttpd |
| MTK-ALL | `MEDIATEK-WIFI-*` | `VIKINGYFY/immortalwrt` | `owrt` | `main` | 原版 | uhttpd |
| WRT-TEST | 手动输入 | 手动输入 | 手动输入 | 按配置 | 按配置 | 按配置 |

发布 tag 形如：

```
X86-kwrum1-mydist-26.10.20-15.41.39
ROCKCHIP-kwrum1-mydist-26.10.20-15.40.32
IPQ807X-WIFI-YES-VIKINGYFY-main-26.10.20-15.41.33
MEDIATEK-WIFI-NO-VIKINGYFY-owrt-26.10.20-15.40.30
```

`CONFIG-源码所有者-分支-构建时间`，源码与分支一眼可查。

---

## 2. 触发方式

| 方式 | 行为 |
|---|---|
| 定时 | `Auto-Clean` 每天 22:00 UTC 清理旧 Release |
| 自动 | `Auto-Clean` 完成后，`OWRT-ALL` / `QCA-ALL` / `MTK-ALL` / `QCA-PPE` 四个工作流通过 `workflow_run` **同时**触发 |
| 手动 | Actions → 选工作流 → Run workflow（`WRT-TEST` 只输出 `.config`，不编译） |

四个工作流共用 `WRT-CORE.yml`，矩阵在各自文件里定义；改源码/分支只改对应工作流的 `matrix`。

---

## 3. 目录

```
.github/workflows/   OWRT-ALL / QCA-ALL / QCA-PPE / MTK-ALL / WRT-TEST / WRT-CORE
Config/              每个目标的 .config 片段
  GENERAL.txt          X86 / ROCKCHIP 专用（mydist 数据面 + 魔改 UI/DNS）
  GENERAL-STOCK.txt    IPQ / MTK 专用（原版包集，逐字恢复）
  X86.txt / ROCKCHIP.txt / IPQ*.txt / MEDIATEK*.txt
Scripts/
  Packages.sh          第三方包、honk 分支选择、honk 资产获取、mydist 拷贝
  Settings.sh          .config 生成、LAN IP/WiFi/主机名、内核尺寸
  Handles.sh           构建期源码修补（mydist 部分只对 X86/RK 生效）
  verify-packages.sh   固件包清单闸门（手动运行）
```

---

## 4. 构建流水线（`WRT-CORE.yml`）

| 步骤 | 做的事 |
|---|---|
| Initialization Environment | 安装 ImmortalWrt 官方构建依赖，`/mnt/build_wrt` 软链到 `./wrt` |
| Initialization Values | 解析 `WRT_TARGET` / `WRT_INFO` / 日期 |
| Clone Code | `git clone --depth=1 --branch $WRT_BRANCH $WRT_REPO ./wrt`，并去掉国内源 |
| Check Caches | 缓存 `ccache` + `staging_dir/host*`、`tool*`（key 含 `WRT_CONFIG-WRT_INFO-WRT_HASH`） |
| Update Feeds | `feeds update -a && install -a` |
| Custom Packages | `Packages.sh` + `Handles.sh`（cwd 为 `wrt/package`） |
| Custom Settings | `Settings.sh` 生成 `.config`，`make defconfig && make clean` |
| Download Packages | `make download -j` |
| Compile Firmware | `make -j || make -j1 V=s` |
| Package Firmware | 收集 `bin/targets`，按 `CONFIG-OWNER-BRANCH-DATE` 重命名 |
| Release Firmware | `softprops/action-gh-release` 发布 |

---

## 5. X86 / ROCKCHIP 的加速栈

### 5.1 为什么不是“开个 offload”

ImmortalWrt 自带的软件/硬件 flow offload 会把首个包之后的流量交给 netfilter flowtable，**绕过 TC**；而本方案的 NAT 与快路径都在 TC/eBPF 上。两者互斥，所以 X86/RK 的镜像里：

- `/etc/config/firewall` 默认 `flow_offloading=0`、`flow_offloading_hw=0`；
- `kmod-nft-offload` 从 `DEFAULT_PACKAGES` 与 firewall4 的依赖里移除；
- 这属于 **源码/构建期默认值**，不是运行期覆盖。

### 5.2 钩子顺序（实测）

```
WAN ingress :  honk TCX(wan_ingress) → einat TCX(reverse SNAT) → router-acl (classic, pref 90) → dpd_fastpath (classic, pref 100)
LAN ingress :                                                     router-acl?               → dpd_fastpath (classic, pref 100)
WAN egress  :  honk TCX(wan_egress) → einat TCX(SNAT)          → router-acl (classic, pref 90) → CAKE root qdisc
```

两条关键事实：

1. **TCX 先于 classic `cls_bpf` 执行**。honk 用 TCX，einat 用 TCX；router-acl / dpd 用 classic。因此 honk 决定代理的流根本到不了 dpd，dpd 只加速 honk 放行的直连流。
2. **classic 链内按 pref 排序**：router-acl（90）先表态，dpd（100）在后。dpd 在挂载时会检查“有没有别人的 pref 比我大”，有就自动降级为 `observe`。

### 5.3 组件清单

| 组件 | 来源 | 功能 | 替换 / 对比 | 默认 |
|---|---|---|---|---|
| **einat-ebpf** | `EHfive/einat-ebpf` v0.1.11，上游 release 的静态 musl 二进制（x86_64 / aarch64） | 在 TC 上实现 **Full Cone NAT44**（EIM + EIF），不依赖 conntrack | 替换 `fw4` 生成的 `MASQUERADE`（conntrack + 端口受限映射）；与普通 NAT 相比外网可主动回连 | `enabled=1`，端口段 `20000-29999`，hairpin 开 |
| **dpd-fastpath** | 本仓库：`src/dpd_fastpath.bpf.c` + `dpdctl`，构建时用 host clang 编 BPF | TC **ingress** 快路径：已建立连接的家用转发走 `bpf_fib_lookup` 直接重定向；`downlink=1` 时 WAN→LAN 回程也加速 | 替换“每个包都走 netfilter 规则链”的路径；**不做 NAT**（NAT 唯一归属 einat），**不共享 einat 的 map/ABI** | `mode=stateful`（2026-10-27 起默认），有 uplink 才启用；无 WAN/无 einat 时自动降级 `observe` |
| **honk** | `kwrum1/openwrt-honk`：固定上游 `Glassyiris/honk` commit，构建时打 **p1** 补丁（core-p1 release，x86_64/aarch64/armv7） | TCX 透明代理；p1 core 把 **direct** 判决交回 classic（`TC_ACT_UNSPEC` + `DIRECT_UNSPEC_MARK`） | 代理流 redirect 进 `dae0`，**不进 dpd**；直连流进 classic，由 dpd 继续加速；NAT 仍是 einat | 默认不启用；启用时需要 p1 core（`/usr/share/honk/direct-unspec`），否则门控保持 `observe` |
| **router-acl** | 本仓库：`src/acl.bpf.c` + `aclctl` | WAN 侧 eBPF ACL/guard：丢弃无主入站；`bypass` 模式加 mark + notrack，把 NAT 流从 conntrack 摘出 | 叠加在 fw4 之上（fw4 仍是兜底）；比 stock 更严：真正挡住无主入站的是这里 | `enabled=1`，`mode=guard`，`import_firewall=1` |
| **router-qos** | 本仓库（纯脚本包） | WAN 上一条 `root qdisc`，**无限速**（逐流公平 + AQM）：≤1 Gbit/s 用 `cake diffserv4 nat`，更快的链路自动用 `fq_codel` | 替换默认 qdisc；无速率参数、无 UI、默认开启（`cake` 在多 G 链路上代价太大，所以按链路速率自动选） | `enabled=1`，`wan` 可列多条（多 WAN 参与负载的链路自动纳入） |
| **router-tuning** | 本仓库（纯脚本包） | 首启按 CPU/内存/网卡选档：BBR、`fq`、sysctl、ring/coalescing、XPS、governor | 不替换 qdisc（`router-qos` 仍接管 WAN）；只调内核/网卡参数 | `profile=auto` |
| **router-dns** | 本仓库（纯脚本包） | **SmartDNS 独占 :53**；dnsmasq 端口 0、停用；`router-dns-sync` 从 DHCP 租约派生真实上游（过滤本机地址）并写 `hosts.lan`；`/tmp/resolv.conf` → `127.0.0.1`；honk 的 DNS 交接 | 替换 dnsmasq 的解析角色；dnsmasq 不再是解析器 | SmartDNS `:53`，dnsmasq `:0`，上游来自租约而不是写死 |
| **luci-front** | 本仓库；Rust + pingora 0.9，静态 musl（x86_64 / aarch64 各一份预编译） | 接管 :80/:443：HTTP/2、TLS、HSTS/CSP 等安全头、静态文件 ETag/304；`/cgi-bin`、`/ubus` 反代到 uhttpd | 替换 uhttpd 的对外监听；uhttpd 退到 `127.0.0.1:8080`，只保留 Lua CGI 与 ubus 桥 | 两个架构自动选二进制 |
| **luci-app-mydist** | 本仓库 | 菜单（DNS/代理/防火墙/多 WAN 负载）、端口控制（五元组单行表格）、多 WAN 负载页、`mydist-posture` | 替换原版 firewall/smartdns/honk 菜单入口 | `rule 999` 默认开启且不在 UI 显示；QoS 没有页面（默认开启、无需配置） |

### 5.4 DNS 上游与自租约（round 10）

- **上游不再写死**：`/usr/libexec/router-dns-sync` 在 S18 和每次 `ifup/ifupdate` 从 netifd/ubus 与 `resolv.conf.auto` 取真实 nameserver，过滤掉本机地址，写成显式 `config server` 段；DoT 保留为并行上游。
- **自身解析**：`/tmp/resolv.conf` 固定为 `nameserver 127.0.0.1` + `search lan`（`/etc/resolv.conf` 覆盖同一内容），路由器像 LAN 客户端一样走自己。
- **`.lan` 名字**：`/var/etc/router-dns/hosts.lan`（本机名 + odhcpd 租约名），smartdns 用 `hosts-file` 读取。
- **DHCP 自租约守卫**：`mydist-posture` 把本机各接口 MAC 注册成 `dhcp.mydist_self_<iface>`（`option ip 'ignore'`），odhcpd 不再给本机发租约；单网卡/同广播域拓扑下不会再出现“默认路由指向自己”。


### 5.6 代理 + 加速共存（honk p1）

**机制**：内核 `sch_handle_ingress()` 先跑 `tcx_run()` 再跑 `tc_run()`；honk 的 `lan_ingress_l2` 是 TCX，dpd 是 classic。TCX 只要返回非 `TC_ACT_UNSPEC`，整条 classic 链就被跳过。

上游 honk 的 direct 出口返回 `TC_ACT_OK`，所以 honk 一开，直连也进不了 dpd（实测 `pkt_total` 不涨），只能 `observe`。honk 包 **p1** 的补丁（`ci/patches/honk-direct-unspec.py`，不改上游仓库）做了三件事：

1. 4 个 direct 出口返回 `TC_ACT_UNSPEC`，并打上 `DIRECT_UNSPEC_MARK`（`0x2000_0000`）；
2. bridge master/slave 二次遍历看到这个 mark 时，跳过 honk 的分类、仍然返回 `UNSPEC`；
3. 代理/block 判决不变：proxy 仍然 redirect 到 `dae0`，block 仍然 `SHOT`，两者都不进 classic。

dpd 通过 `/usr/share/honk/direct-unspec` 判断 core 是否带 p1；没有这个 marker（上游原版 core）就保持 `observe`，避免用不完整的流表去加速 WAN 回程（实测强制 stateful 会把 TCP 控制连接打断）。

**分流结果**：

| 流 | honk 判决 | dpd |
|---|---|---|
| direct（含 `direct(must)`、offload） | `UNSPEC` + `DIRECT_UNSPEC_MARK` | 进入 classic，正常加速；多 WAN 正常按权重选路 |
| proxy | redirect 到 `dae0` | 不进 classic，不参与多 WAN（仍由 honk 的 `wan_interface` 单接口出去） |
| block | `SHOT` | 不进 classic |

**实测（2026-10-27，x86_64 实验台，honk p1 运行中）**：

| 场景 | 结果 |
|---|---|
| 直连 4 流 | 3.77–4.18 Gbit/s，dpd `redirect_ok` +141,559 |
| 直连 64 流 | eth2/eth3 = 1.85:1（自动权重 2:1） |
| `ifdown wan` | 切到 eth3，模式仍 `stateful`，8 流 `redirect_ok` +123,643 |
| 显式 `-> proxy` 目标 | sender 324 MB / receiver 0（无节点，按预期失败）；dpd observe 下只 +14 包 |
| 显式 `-> block` 目标 | 连接被丢弃 |
| 同目标直连端口 | 3.6 Gbit/s，正常加速 |

**与上游 honk 的关系**：数据面共存不依赖修改 honk 源码——p1 是构建期补丁，产物是 `core-p1` release（三架构 + sha256）。用上游原版 core 仍可运行，但直连不会加速；要用“直连加速 + 代理”必须用 p1 core。RK（ROCKCHIP/aarch64）与 X86 走同一套配置和同一个 p1 core。

---

## 6. 配置分层

| 文件 | 使用者 | 内容 |
|---|---|---|
| `Config/GENERAL.txt` | X86 / ROCKCHIP | einat/dpd/ACL/QoS/DNS/luci-front/luci-app-mydist、SmartDNS、关闭 docker/upnp/iptables、关 offload、odhcpd 接管 |
| `Config/GENERAL-STOCK.txt` | IPQ / MTK | 原版 CI 的 GENERAL（逐字恢复）：保留 `kmod-nft-offload`、`kmod-nft-queue`、upnp、coremark 等 |

选择逻辑在 `Scripts/Settings.sh`：

```sh
X86 / ROCKCHIP  -> Config/<CONFIG>.txt + Config/GENERAL.txt
其它            -> Config/<CONFIG>.txt + Config/GENERAL-STOCK.txt
*TEST*          -> 只用 Config/<TEST>.txt
```

---

## 7. 脚本要点

### 7.1 `Packages.sh`

- **第三方包**：只保留 aurora / aurora-config / honk / v2ray-geodata / partexp（其余插件在基线的固件清单里本就不存在）。
- **honk 分支**：

  ```sh
  case "$WRT_CONFIG" in
  	X86|ROCKCHIP) UPDATE_PACKAGE "honk" "kwrum1/openwrt-honk" "mydist" "pkg" ;;
  	*)            UPDATE_PACKAGE "honk" "kwrum1/openwrt-honk" "main" "pkg" ;;
  esac
  ```

- **honk 资产**：`honk/generated-stage.mk`、`generated-provenance.json`、`luci-app-honk/generated-doona-stage.mk` 都是 `.gitignore` 的 release asset。脚本按 `CORE_COMMIT` 找到对应 release，下载三个文件，把里面写死的 `kenzok8` URL 改写成实际 release 目录，并对 x86_64 资产做 HEAD 预检（早失败，不等编译 1.5 小时）。
- **mydist**：只在 `X86|ROCKCHIP` 拷贝；优先用源码树里的 `wrt/mydist`（fork），回落到本仓库的 `mydist/`；找不到直接失败。

### 7.2 `Settings.sh`

- `.config` 唯一生成点（WRT-CORE 不再自己 cat）。
- `WRT_IP` 为空时保留上游默认，并断言 LAN 默认地址不为空。
- qualcommax 的 `KERNEL_SIZE` 只在该目录存在时修改。
- WiFi SSID/密码/国家、主机名按工作流输入写入。

### 7.3 `Handles.sh`

- 前半段是原版逻辑：homeproxy 规则、argon/aurora 主题、mini-diskmanager、tailscale、rust。
- 后半段（x86 DRM 裁剪、flow offload、`kmod-nft-offload`、odhcpd 接管、dnsmasq `ignore 1`、honk NFQUEUE 裁剪）**整段包在 `if [[ "$WRT_CONFIG" == "X86" || "$WRT_CONFIG" == "ROCKCHIP" ]]` 里**。
- 这些 sed 全部幂等，重复执行不会叠加。

---

## 8. 与上游 CI 的差异

1. 矩阵按目标指定源码/分支（`include` 矩阵），不再所有配置共用一份源码。
2. 新增 `mydist/` 分发（8 个包）与按目标的拷贝开关。
3. 新增 honk 分支选择与 `generated-*` 资产获取（上游没有这套包）。
4. 新增 `Config/GENERAL-STOCK.txt`，`GENERAL.txt` 变为 X86/RK 专用。
5. `Settings.sh` 按目标选配置、修复 `WRT_IP` 为空导致 LAN 无地址的问题。
6. `Handles.sh` 增加 mydist 补丁块并对目标门控。
7. `.config` 只在 `Settings.sh` 生成一次。
8. 发布 tag 带源码所有者与分支，便于区分 `kwrum1` 与 `VIKINGYFY`。
9. 第 10 轮：DHCP 自租约守卫、router-dns-sync 上游派生、resolv.conf/.lan 修复、accept-full.sh 断言加强（62 项）。

---

## 9. 已知限制

- **IPQ-MTK 没有 einat**：einat 只发布 x86_64 / RK；其他机型按原版 加速 逻辑构建。
- **honk 直连加速依赖 p1 core**：本 fork 的 `core-p1` 把 direct 判决交回 classic；用上游原版 core（direct 返回 `OK`）时 dpd 门控会自动 `observe`，直连不会加速。两个包必须一起升级（honk p1 + `dpd-fastpath` 的 marker 门控）。

---

## 10. 排障

| 现象 | 原因 / 处理 |
|---|---|
| `package/honk: Cannot find appropriate hash command` | `generated-stage.mk` 没取到；看 `Custom Packages` 日志里的 `honk:` 行 |
| honk 资产 404/403 | 本 fork 的 `PKG_SOURCE_URL` 应指向 `kwrum1/openwrt-honk` 的 `core-p1`；确认 `honk/generated-stage.mk` 已提交且三架构 sha256 匹配 |
| 改了源码但镜像没变 | 缓存 key 是 `CONFIG-OWNER-HASH`；确认分支 hash 变了，或删对应缓存 |
| X86/RK 镜像里没有 `luci-front` | 检查是否用了 `GENERAL.txt`；RK 需要 aarch64 二进制 |
| IPQ/MTK 里出现 einat | 检查 `Packages.sh` 的 `case` 与 `Handles.sh` 的门控是否被改动 |

---

## 11. 来源与许可

- CI 框架：`VIKINGYFY`（MIT）。
- einat：`EHfive/einat-ebpf`（GPL-2.0）。
- honk：`Glassyiris/honk`，打包与 Doona 集成见 `kwrum1/openwrt-honk`。
- 其余 `mydist` 组件为本仓库原创（GPL-2.0-only）。
