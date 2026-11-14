# linux-ipvs — Linux IPVS 的完整 netlink 机制层

## 背景：为什么存在这份文档（分层模型与术语）

> 本段是**自包含的上下文**，供首次阅读者（包括新会话中的 AI agent / 新协作者）理解本项目在整个 Rust 生态中的位置。后文的 "Layer 2 / 机制层 / 政策层 / 止步点" 等术语全部由本节定义，不需要任何外部对话背景。

### 问题背景：一类反复出现的生态缺口

Rust 生态中存在一类反复出现的缺口：很多领域已经有"能调用系统接口"的 crate，但缺少一个把该领域**协议 / 解析 / 正确性**做完整做正确的 crate——使用者被迫在自己的应用里反复实现同一份困难逻辑，而且很容易做错（嵌套属性、字节序、对齐填充、多部分消息、错误透传）。本 crate 就是为了填补这类缺口而设计。

### 四层模型

- **Layer 0 — 裸绑定**：`libc`、`libxcb` 等，直接暴露 syscall / C 接口。零安全、无错误语义。
- **Layer 1 — 薄安全封装**：`nix` 风格。把 syscall 包成安全函数（`Result`、RAII），但**没有解决领域问题**。
- **Layer 2 — 完整机制层（本 crate 的目标）**：把该领域的协议、解析、状态管理、类型化访问、错误语义做完整做正确。这是**正确性问题**。
- **Layer 3 — 政策 / 运行时 / 框架层**：事件循环、线程与异步模型、缓存策略、对象建模、业务决策。这是**偏好问题**。

### 核心原则（本 crate 的设计红线）

- **机制层必须做完整**：正确性问题不能甩给用户。
- **政策层必须留白**：不替用户决定偏好问题。"止步点"就是这两层的分界——再往前做一步，就是替用户做有分歧的决定，即"无端揣测约束用户行为"。
- **保留逃生舱**：提供 `as_fd()` / 原始访问等途径，让用户能接入自己的事件循环、缓存、策略。

### 参照系：fanotify-fid 之于 fanotify（本模式的原型）

`fanotify-fid`（Layer 2）把 fanotify 的协议层做完整：变长事件遍历、FID 记录解析、句柄回路径、可插拔缓存、RAII、带 man-page 级语义的错误类型。它刻意停在 Layer 2：不内置事件循环、不做 mount 自动发现、不强制缓存策略。本 crate 与 IPVS 的关系同构：内核给的是"嵌套属性 + 多命令 + 统计计数"的 netlink 协议，正确编解码就是 Layer 2 的价值。

### 缺口分类（本 crate 的由来）

本 crate 属于 **B 类（机制锁在应用里）**：`keepalived`、`ipvsadm` 等真实工具各自维护一份 C 实现，Rust 侧无完整 crate；`nlrs` 自称 "minimal"。本 crate 要做的就是把 IPVS netlink 机制抽出来，形成独立、完整、正确的机制层。

### 术语速查

- **机制层** = Layer 2 = 本 crate 的"范围 / 必须做"。
- **政策层** = Layer 3 = 本 crate 的"非目标 / 必须不做"。
- **止步点** = 机制层与政策层的分界。
- **Layer 1** = 现有的薄封装（可能不存在，也可能存在但不顶用）。

## 定位

**一句话**：把 Linux IPVS 的 netlink 协议（服务/真实服务器/统计/同步守护进程管理）做成完整、类型化的机制库，供负载均衡控制面直接使用，而不是每个工具重写 netlink 编解码。**netlink 消息层（nlmsghdr/genlmsghdr/nla 编解码 + 家族解析 + ack/extack）是机制组成部分，完整实现。**

**现状：为何缺少 Layer 2（机制层）**：

| 层 | 现状 | 问题 |
|---|---|---|
| Layer 1 | 裸 `NETLINK_GENERIC` socket + 手写 `IPVS_CMD_*`/`IPVS_ATTR_*` | 嵌套属性、对齐填充、统计计数、字节序、家族解析、extack 错误全要自己处理 |
| Layer 2 | **缺失** | `nlrs` 自称 "minimal"；`keepalived`、`ipvsadm` 等真实工具各自维护一份 C 实现；Rust 侧无完整 crate |
| Layer 3 | keepalived / 云 LB 控制面 | 健康检查、调度策略、配置格式——应用的事 |

## 范围（机制层 · 必须做）

1. **generic netlink 传输封装**：`NETLINK_GENERIC` socket 的 RAII 包装、家族解析（`CTRL_CMD_GETFAMILY` 取 "IPVS" 家族 id）、消息收发、ack + extack 错误透传。
2. **netlink 消息层**：`nlmsghdr`/`genlmsghdr`/`nlattr`（含 `NLA_F_NESTED` 嵌套、4 字节对齐填充）的编解码——纯函数，可独立测试，未来可抽成共享模块。
3. **服务管理**：`IPVS_CMD_NEW/SET/DEL/GET_SERVICE`——虚拟服务（AF、协议、地址、端口、fwmark、调度器、标志、持久性配置）。
4. **真实服务器管理**：`IPVS_CMD_NEW/SET/DEL/GET_DEST`——RS（地址、端口、转发方式、权重、阈值、隧道类型）。
5. **统计**：`IPVS_CMD_GET_INFO`、GET_SERVICE/GET_DEST 的统计属性（`STATS` 与 `STATS64` 两套容器：连接数、入/出包、入/出字节、速率；64 位容器优先）。
6. **守护进程状态**：`IPVS_CMD_NEW/DEL/GET_DAEMON`（同步守护进程 master/backup、多播配置）。
7. **超时**：`IPVS_CMD_GET/SET_CONFIG` 与 `IPVS_CMD_ATTR_TIMEOUT_*`（TCP/TCP_FIN/UDP 超时）。
8. **全量转储**：`IPVS_CMD_GET_SERVICE` 带 `NLM_F_DUMP` → 服务+RS+统计的树形结果。
9. **错误语义**：netlink 错误码（`NLMSG_ERROR`）+ extack 扩展消息（`NLMSGERR_ATTR_MSG`/`OFFS`）透传为带上下文的类型化错误。

## 非目标（政策层 · 必须不做）

- **不**实现负载均衡调度算法（`rr`/`wrr`/`lc`/`sh`… 是内核侧，选择它们是上层策略）。
- **不**做健康检查/探活（那是 keepalived 的活）。
- **不**解析 keepalived.conf / 配置格式。
- **不**绑定异步运行时：同步 API + `AsFd`，用户自选。
- **不**做高可用状态机（VRRP 等）。
- **不**做 legacy setsockopt 接口（`IP_VS_SO_*`，老工具用的旧路径；本 crate 只做 netlink）。

## 止步点：最大化替上层做事，同时不约束上层

这条线不按"做多做少"划，而按**问题类型**划：

- **必须做（机制层）**：正确性问题 —— 协议编解码、嵌套属性、状态管理、RAII、错误语义、容错降级。不做，上层每个使用者都要重复实现同一份困难逻辑，且容易做错。
- **必须不做（政策层）**：偏好问题 —— 事件循环/异步运行时、线程模型、缓存/记忆策略、资源发现策略、健康检查策略、业务语义约定。没有唯一正确答案，做了就是在替上层做决定，导致"因为这个库我不得不这么写"。
- **留逃生舱**：`AsFd` / 原始字节 / 裸函数入口，机制不满足时上层可绕过，不必改库。
- **可插拔**：用 trait / 回调让上层注入策略，不写死唯一默认方案。
- **破坏性操作显式化**：清除/删除/修改绝不隐式发生，只有显式调用才执行。
- **数据不因"不识别"而丢失**：解析失败降级保留（原始数据 + Unknown 标记），而非报错丢弃。

**反面自检**（写每个 API 前问自己）：

1. 这个 API 是不是在替上层决定"它怎么跑"（循环/线程/时机）？→ 是则不做。
2. 是否隐含了只适用部分场景的假设（"总是自动发现""总是缓存"）？→ 是则做成可选/可插拔。
3. 上层是否必须付出代价才能绕过我（改源码 / 开 unsafe / 重新解析我吞掉的信息）？→ 是则留逃生舱。
4. 破坏性行为是否可能在用户不知情时发生？→ 是则改为显式。

**本项目具体的止步点**：

- 负载均衡调度算法、健康检查/探活、keepalived 配置格式、高可用状态机 → 政策，不做。
- IPVS netlink 机制（消息层 + 服务/真实服务器/统计/同步守护进程/超时）→ 机制，必须做。
- 逃生舱：`AsFd`；原始 netlink 消息收发接口（`send_raw`/`recv_raw`）。

**正面参照（linux-pstore 已实现）**：

- 数据永远给原始字节（`Record.data`），压缩记录同时给 `is_compressed()` 与 `decompressed()`，上层可以选择不解压。
- 解析失败的文件**仍被枚举和读取**（Unknown 类型），绝不丢数据。
- `clear()` 是唯一清除入口，完全显式，无任何"读完即清"的隐式行为。
- 系统相关探测抽成可注入函数（`open_inner`），既让系统分支（NotMounted）可单测，也让 API 保持单一职责。→ 本项目扩展到 netlink：**消息层纯函数 + socket 传输可注入**，见"设计决策"。

## 命名

`linux-ipvs`：`ipvs` 已被占用；`linux-` 前缀明确指内核 IPVS 子系统，与同名 C 项目/其他语义区分，并与 `linux-iio`/`linux-nfc`/`linux-pstore` 系列一致。

## API 草案

```rust
// —— 传输 ——
pub struct Ipvs { /* RAII: NETLINK_GENERIC socket + 已解析的家族 id */ }
impl Ipvs {
    pub fn new() -> Result<Self>;              // 建 socket + CTRL_CMD_GETFAMILY("IPVS")
    pub fn new_with_sock(sock: NetlinkSocket) -> Result<Self>; // 可注入（测试）
    pub fn as_fd(&self) -> BorrowedFd<'_>;     // 逃生舱
    pub fn send_raw(&self, msg: &[u8]) -> Result<()>;   // 逃生舱
    pub fn recv_raw(&self) -> Result<Vec<u8>>;          // 逃生舱
}

// —— 服务 ——
pub struct ServiceSpec { /* af, protocol, addr, port, fwmark, sched_name, flags, timeout, netmask, pe_name */ }
pub struct Service { pub spec: ServiceSpec, pub stats: Option<ServiceStats> }
impl Ipvs {
    pub fn add_service(&self, spec: &ServiceSpec) -> Result<()>;      // NEW_SERVICE
    pub fn set_service(&self, spec: &ServiceSpec) -> Result<()>;      // SET_SERVICE
    pub fn del_service(&self, spec: &ServiceSpec) -> Result<()>;      // DEL_SERVICE
    pub fn get_service(&self, spec: &ServiceSpec) -> Result<Service>; // GET_SERVICE
    pub fn list_services(&self) -> Result<Vec<Service>>;              // GET_SERVICE + DUMP
    pub fn zero_services(&self) -> Result<()>;                        // ZERO
    pub fn flush(&self) -> Result<()>;                                // FLUSH
}

// —— 真实服务器 ——
pub struct DestSpec { /* addr, port, fwd_method, weight, u_thresh, l_thresh, tun_type, tun_port, tun_flags */ }
pub struct Dest { pub spec: DestSpec, pub active_conns: u32, pub inact_conns: u32, pub persist_conns: u32, pub stats: Option<DestStats> }
impl Ipvs {
    pub fn add_dest(&self, svc: &ServiceSpec, d: &DestSpec) -> Result<()>;
    pub fn set_dest(&self, svc: &ServiceSpec, d: &DestSpec) -> Result<()>;
    pub fn del_dest(&self, svc: &ServiceSpec, d: &DestSpec) -> Result<()>;
    pub fn get_dest(&self, svc: &ServiceSpec, d: &DestSpec) -> Result<Dest>;
    pub fn list_dests(&self, svc: &ServiceSpec) -> Result<Vec<Dest>>; // GET_DEST + DUMP
}

// —— 统计 / 信息 / 守护进程 / 超时 ——
pub struct ServiceStats { pub conns: u64, pub inpkts: u64, pub outpkts: u64, pub inbytes: u64, pub outbytes: u64, pub cps: u64, pub inpps: u64, pub outpps: u64, pub inbps: u64, pub outbps: u64 }
pub struct Info { pub version: u32, pub conn_tab_size: u32 }
pub enum DaemonState { None, Master, Backup }
pub struct DaemonConfig { /* state, mcast_ifn, sync_id, sync_maxlen, mcast_group(_6), mcast_port, mcast_ttl */ }
pub struct Timeouts { pub tcp: u32, pub tcp_fin: u32, pub udp: u32 }

impl Ipvs {
    pub fn info(&self) -> Result<Info>;                              // GET_INFO
    pub fn set_daemon(&self, d: &DaemonConfig) -> Result<()>;        // NEW_DAEMON
    pub fn del_daemon(&self, d: &DaemonConfig) -> Result<()>;        // DEL_DAEMON
    pub fn get_daemon(&self) -> Result<Vec<DaemonConfig>>;          // GET_DAEMON + DUMP
    pub fn timeouts(&self) -> Result<Timeouts>;                      // GET_CONFIG
    pub fn set_timeouts(&self, t: &Timeouts) -> Result<()>;          // SET_CONFIG
}

// —— netlink 消息层（纯函数，内部模块，可抽成共享） ——
//   src/nl.rs     nlmsghdr/genlmsghdr/nlattr 编解码 + 对齐 + 家族解析消息
// 模块划分
//   src/nl.rs        netlink 消息层（纯函数）
//   src/ipvs.rs      传输封装 + 家族解析 + ack/extack
//   src/service.rs   服务管理
//   src/dest.rs      真实服务器管理
//   src/stats.rs     统计/信息
//   src/daemon.rs    同步守护进程
//   src/timeout.rs   超时配置
//   src/error.rs     类型化错误
```

## 内核事实（已核实 · 2026-08-04，实现前无需重查）

> 全部逐条对照本机 `/usr/include/linux/ip_vs.h`、`genetlink.h`、`netlink.h`（与内核 7.1.5 一致）逐字核实。

### F1. 传输与家族

| 事实 | 出处 |
|---|---|
| **现代内核 IPVS netlink 走 Generic Netlink**（`NETLINK_GENERIC`=16），家族名 `"IPVS"`、版本 `0x1`（`IPVS_GENL_NAME`/`IPVS_GENL_VERSION`）；旧内核（<3.5）用 nfnetlink（`NETLINK_NETFILTER`、`NFNL_SUBSYS_IPVS`）——本 crate 只做 generic netlink 路径 | `ip_vs.h` + 历史 |
| 家族 id 需先 `CTRL_CMD_GETFAMILY` 向 controller（`GENL_ID_CTRL`=0x10）查询（带 `CTRL_ATTR_FAMILY_NAME="IPVS"`），从回复的 `CTRL_ATTR_FAMILY_ID` 取 id | `genetlink.h` |
| `struct nlmsghdr { u32 nlmsg_len; u16 nlmsg_type, nlmsg_flags; u32 nlmsg_seq, nlmsg_pid; }`；`NLMSG_ERROR`=2、`NLMSG_DONE`=3、`NLMSG_MIN_TYPE`=0x10 | `netlink.h` |
| `struct genlmsghdr { u8 cmd, version; u16 reserved; }`（紧跟 nlmsghdr 之后） | `genetlink.h` |
| `struct nlattr { u16 nla_len; u16 nla_type; }`；`NLA_F_NESTED(1<<15)`、`NLA_F_NET_BYTEORDER(1<<14)`、`NLA_TYPE_MASK`；`NLA_ALIGNTO=4`、`NLA_HDRLEN=4` | `netlink.h` |
| extack：`NETLINK_EXT_ACK` 开启后错误回复可带 `NLMSGERR_ATTR_MSG`（字符串）/`NLMSGERR_ATTR_OFFS`（偏移） | `netlink.h` |
| dump：`NLM_F_DUMP`（=`ROOT|MATCH`），回复多段以 `NLMSG_DONE` 结束；`NLM_F_ACK` 请求确认 | `netlink.h` |

### F2. 命令集（`enum` 逐字核实）

| 事实 | 出处 |
|---|---|
| 服务：`IPVS_CMD_NEW_SERVICE`、`SET_SERVICE`、`DEL_SERVICE`、`GET_SERVICE` | `ip_vs.h` |
| 真实服务器：`IPVS_CMD_NEW_DEST`、`SET_DEST`、`DEL_DEST`、`GET_DEST` | `ip_vs.h` |
| 守护进程：`IPVS_CMD_NEW_DAEMON`、`DEL_DAEMON`、`GET_DAEMON` | `ip_vs.h` |
| 配置/信息/操作：`IPVS_CMD_SET_CONFIG`、`GET_CONFIG`、`SET_INFO`、`GET_INFO`、`IPVS_CMD_ZERO`（清零计数）、`IPVS_CMD_FLUSH`（清空服务与 RS） | `ip_vs.h` |
| 命令级属性 `IPVS_CMD_ATTR_*`：`SERVICE`(嵌套)、`DEST`(嵌套)、`DAEMON`(嵌套)、`TIMEOUT_TCP`、`TIMEOUT_TCP_FIN`、`TIMEOUT_UDP` | `ip_vs.h` |

### F3. 服务属性（`IPVS_SVC_ATTR_*` 逐字核实）

| 事实 | 出处 |
|---|---|
| `AF`（地址族，AF_INET/AF_INET6）、`PROTOCOL`（tcp/udp…）、`ADDR`（网络序：请求 IPv4 4 字节 / IPv6 16 字节；**回复恒为 16 字节** `sizeof(union nf_inet_addr)`，IPv4 值在前 4 字节）、`PORT`（`__be16`，网络字节序）、`FWMARK`（u32） | `ip_vs.h` + `ip_vs_ctl.c` |
| `SCHED_NAME`（NUL 字符串，payload ≤15 字节）、`FLAGS`（`struct ip_vs_flags { u32 flags; u32 mask; }`，8 字节主机序）、`TIMEOUT`（持久性超时秒，u32 主机序）、`NETMASK`（4 字节：IPv4=be32 掩码；IPv6=**主机序前缀长度** 1..=128）、`PE_NAME`（NUL 字符串，payload ≤16 字节） | `ip_vs.h` + `ip_vs_ctl.c` |
| `STATS`（嵌套：计数/速率为 u32，INBYTES/OUTBYTES 为 u64）与 `STATS64`（嵌套全 u64；均**主机序**，64 位值前可能插入 `PAD` 属性） | `ip_vs.h` + `ip_vs_ctl.c` |

### F4. 真实服务器属性（`IPVS_DEST_ATTR_*` 逐字核实）

| 事实 | 出处 |
|---|---|
| `ADDR`（网络序；请求 v4 4 字节 / v6 16 字节，**回复恒 16 字节**）、`PORT`（be16）、`ADDR_FAMILY`（u16；回复必带）、`FWD_METHOD`（u32：`IP_VS_CONN_F_MASQ`=0 / `LOCALNODE`=1 / `TUNNEL`=2 / `DROUTE`=3 / `BYPASS`=4）、`WEIGHT`（u32 编码的 i32） | `ip_vs.h` + `ip_vs_ctl.c` |
| `U_THRESH`/`L_THRESH`（u32）、`ACTIVE_CONNS`/`INACT_CONNS`/`PERSIST_CONNS`（u32）、`STATS`/`STATS64`（嵌套，主机序） | `ip_vs.h` + `ip_vs_ctl.c` |
| 隧道：`TUN_TYPE`（IPIP/GUE/GRE）、`TUN_PORT`、`TUN_FLAGS`（NOCSUM/CSUM/REMCSUM） | `ip_vs.h` |

### F5. 守护进程 / 统计 / 信息属性（逐字核实）

| 事实 | 出处 |
|---|---|
| `IPVS_DAEMON_ATTR_*`：`STATE`（NONE=0/MASTER=1/BACKUP=2）、`MCAST_IFN`、`SYNC_ID`、`SYNC_MAXLEN`、`MCAST_GROUP`(IPv4)/`MCAST_GROUP6`(IPv6)、`MCAST_PORT`、`MCAST_TTL` | `ip_vs.h` |
| `IPVS_STATS_ATTR_*`：`CONNS`、`INPKTS`、`OUTPKTS`、`INBYTES`、`OUTBYTES`、`CPS`、`INPPS`、`OUTPPS`、`INBPS`、`OUTBPS`（+`PAD`）——`STATS` 中仅 INBYTES/OUTBYTES 为 u64，`STATS64` 全 u64，均主机序 | `ip_vs.h` + `ip_vs_ctl.c` |
| `IPVS_INFO_ATTR_*`：`VERSION`（`IP_VS_VERSION_CODE`=0x010201）、`CONN_TAB_SIZE` | `ip_vs.h` |
| 服务标志：`IP_VS_SVC_F_PERSISTENT`、`HASHED`、`ONEPACKET`、`SCHED1-3`；RS 状态标志：`IP_VS_DEST_F_AVAILABLE`、`OVERLOAD`（在连接标志里） | `ip_vs.h` |

### F6. 生态现状（Layer 1 边界核实）

| 事实 | 出处 |
|---|---|
| `nlrs`（crates.io）自称 "minimal" netlink 库，不提供 IPVS 协议 | crates.io 调查 |
| `keepalived`/`ipvsadm` 各自维护一份 C 实现，未抽成库 | 项目事实 |

## 设计决策（已定，不要推翻重来）

1. **netlink 消息层是纯函数 + 独立可测**：`nlmsghdr`/`genlmsghdr`/`nlattr`（嵌套、对齐、字节序）编解码全部纯函数，用**预期字节序列**做单测（构造→字节→解析==原值 + 对齐断言）。它同时服务于 linux-nfc 的 generic netlink 部分——本 crate 内保持模块独立，未来可抽成共享模块，但 v1 不抽（避免跨 crate 协调）。
2. **传输可注入（不回避内核交互）**：socket 创建与 send/recv 抽成可注入边界（默认真 socket；测试注入假实现返回构造好的字节流）。消息构建/解析全纯测，**成功路径与错误路径都在本机测**，只留最终 syscall 命中给真机。真实用法给 `no_run` doctest + 可选 example。
3. **家族解析缓存**：`Ipvs::new()` 解析 "IPVS" 家族 id 并缓存；解析失败报 `Error::FamilyNotFound`（内核未编译 IPVS）；提供 `new_with_sock` 注入。家族 id 在 socket 生命周期内稳定。
4. **dump 处理**：`list_services`/`list_dests` 处理 `NLM_F_MULTI` 多段回复直到 `NLMSG_DONE`；每段独立解析、失败降级（Unknown 保留原文），不因单段坏掉整个 dump。
5. **地址/端口字节序**：`ADDR`/`PORT` 是网络字节序（`NLA_F_NET_BYTEORDER` 语义），`addr`/`port` 字段类型化（`Ipv4Addr`/`Ipv6Addr`/`u16`），编解码负责转换——用户不碰字节序。
6. **破坏性操作显式**：`del_service`/`del_dest`/`flush`/`zero_services`/`del_daemon` 都是显式调用；RAII drop 里绝不隐式删除。
7. **零依赖核心**：消息层 + IPVS 协议零依赖；只用 `libc`（socket/字节序）与 `std`；`default-features = false` 必须可构建。

## 正确性要点（实现时逐条验证）

- nla 对齐：每个属性长度 `NLA_ALIGN`（4 字节），编码嵌套属性时设置 `NLA_F_NESTED`（解析时容忍内核 `nla_nest_start_noflag` 不带该标志）；解析时 `nla_len` 校验（>=4、不越界）。
- 多部分消息：dump 回复 `NLM_F_MULTI`，`NLMSG_DONE` 结束；seq 匹配校验（请求的 `nlmsg_seq` 与回复一致）。
- ack/extack：`NLM_F_ACK` 请求确认；`NLMSG_ERROR` 的 `error` 字段负数=失败；`NETLINK_EXT_ACK` 开启后解析 `NLMSGERR_ATTR_MSG` 透传。
- 字节序：`ADDR`/`PORT`/`TUN_PORT` 网络序；`STATS`/`STATS64` 全部**主机序**（`nla_put_u64_64bit`，不是网络序）；`NETMASK` 在 IPv4 下是 be32 掩码、IPv6 下是主机序前缀长度；其余标量主机序。
- 地址族：请求的 `ADDR` 长度由 `SVC_ATTR_AF` 决定（4 vs 16 字节）；回复恒为 16 字节，IPv4 取前 4 字节；`DEST_ATTR_ADDR_FAMILY` 同理；解析按长度容错。
- 回复命令号：`GET_SERVICE` → `IPVS_CMD_NEW_SERVICE`，`GET_INFO` → `IPVS_CMD_SET_INFO`，`GET_CONFIG` → `IPVS_CMD_SET_CONFIG`；单查询回复不带 `NLM_F_MULTI`。
- `GET_DEST` 只有 dumpit（无 doit），因此单条真实服务器只能通过 dump 获取；`IPVS_CMD_ZERO` 带 service 属性时只清零该服务，不带时清零全部。
- dump 一致性：`NLMSG_DONE` 上的 `NLM_F_DUMP_INTR` 必须向上暴露，不能静默返回残缺快照。
- 空 dump：GET + DUMP 无结果时只有 `NLMSG_DONE`，返回空 Vec 而非错误。
- 权限：`EPERM`/`EACCES`（无 CAP_NET_ADMIN）透传为类型化错误。

## 实现交付清单（一次性完成）

> 本清单来自 linux-pstore 的完整实现与事后审查：实现时**一次性**完成以下各项，避免完成后再返工。

### A. 内核事实核实（实现前 · 最优先）

- [x] 已核实 F1–F6（本机 `ip_vs.h`/`genetlink.h`/`netlink.h` 逐字核对）。
- [x] 剩余核实项（已完成 · 2026-11-14，对照内核 7.4-rc2 `net/netfilter/ipvs/ip_vs_ctl.c`）：
  - `SET_CONFIG` 只接受 `IPVS_CMD_ATTR_TIMEOUT_TCP`/`TIMEOUT_TCP_FIN`/`TIMEOUT_UDP`（u32 主机序）；`SET_INFO` 不是请求，只作为 `GET_INFO` 的回复命令号；
  - `GET_SERVICE` 单查询回复命令号是 `IPVS_CMD_NEW_SERVICE`，带一个嵌套 `IPVS_CMD_ATTR_SERVICE`，不带 `NLM_F_MULTI`；服务不存在时返回 `-ESRCH`；
  - 本机内核带 `ip_vs.ko` 但未加载、无 `CAP_NET_ADMIN`（`/proc/net/ip_vs` 不存在），无法 e2e，全部用注入测试；
  - 对 `ip_vs_ctl.c` 的核实还纠正了三处原假设：回复 `ADDR` 恒为 16 字节；`STATS64` 是主机序；`NETMASK` 的 IPv4/IPv6 语义不同。
- [x] `SVC_ATTR_ADDR` 在 IPv6 下为 16 字节网络序；请求 IPv4 可只发 4 字节（`nla_memcpy` 零填充），回复统一 16 字节。

### B. API 文档（随实现一起写）

- [x] 每个公开项（类型/变体/字段/方法/常量）都有文档注释；`#![warn(missing_docs)]` 常驻，CI 以 `RUSTFLAGS=-D warnings` 强制。
- [x] 主要公开 API 有**可运行的 doctest**（合成 netlink 字节流 / 注入传输），在 CI 中编译运行；真实系统用法用 `no_run`（仍编译校验）+ 可选 example；其余访问器由单测/集成测试覆盖。
- [x] README 只写总览 + 一个主示例；用法细节由各 API 的 doctest 承载。
- [x] 错误类型每个变体的字段都有文档；`Display` / `Error::source` 链完整。

### C. 测试覆盖

- [x] 单元测试覆盖解析/编解码的每条分支（含容错分支）。
- [x] 集成测试覆盖公开 API 的 happy path + **每个错误变体**（EPERM / 家族不存在 / 非法属性 / dump 半途失败）。
- [x] 系统相关分支可测：消息层纯测（预期字节序列）；传输注入测成功与错误路径；家族解析失败路径（注入返回空家族）。
- [x] 特性矩阵：`cargo test`（默认）与 `cargo test --no-default-features` 都绿。
- [x] 本项目测试重点：nla 编解码（嵌套/对齐/字节序）往返；dump 多段拼接与 NLMSG_DONE；extack 解析；地址族/字节序转换；空 dump 返回空 Vec。

### D. 仓库卫生（对齐 fanotify-fid 约定）

- [x] `Cargo.lock` 不提交（库 crate），加入 `.gitignore`（含 `/target`、编辑器杂项）。
- [x] DESIGN.md 是过程文件：README 不引用、Cargo.toml 的 `include` 不含 DESIGN.md。
- [x] LICENSE 文本对齐同系列：MIT 全文 + 版权行 `Copyright (c) 2026 linux-ipvs contributors`。只要求文本内容一致，行尾格式（LF/CRLF）不做要求。
- [x] CI（`.github/workflows/ci.yml`）：test（特性矩阵 + doctest）/ fmt / clippy（双特性）/ doc 四 job，`RUSTFLAGS="-D warnings"`。
- [x] 提交前本地全绿：`cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`。

### E. 特性设计

- [x] 可选依赖用 feature 门控、默认开启；`default-features = false` 必须能零依赖构建（核心只用 `libc` + `std`）。
- [x] 特性矩阵进 CI（默认 + 无默认）。

## 实现结论（0.1.0 · 2026-11-14）

> 实现已完成并全部通过质量门；本节记录实际形态与设计草案的差异，供后续维护者对照。

### 实际模块

`src/nl.rs`（纯消息层）、`src/ipvs.rs`（传输 + 家族解析 + 请求/回复状态机 + `Dump`）、`src/service.rs`、`src/dest.rs`、`src/stats.rs`、`src/daemon.rs`、`src/timeout.rs`、`src/error.rs`、`src/proto.rs`（公开的 IPVS 常量与地址族/协议枚举，供裸消息逃生舱使用）。

### 与 API 草案的差异（均为机制层正确性所需）

- **身份与完整规格分离**：`ServiceId`（地址/端口/协议或 fwmark）用于 `del`/`get`/`zero`/dest 命令；`ServiceSpec` 用于 `NEW`/`SET`。`DestId`/`DestSpec` 同理。
- **没有 `get_dest`**：内核 `GET_DEST` 只有 dumpit，没有 doit；单条 RS 只能通过 `list_dests` 获取（文档已注明），不伪造一个会返回 `EOPNOTSUPP` 的 API。
- **没有 `set_daemon`**：按内核命令命名 `add_daemon`/`del_daemon`/`list_daemons`（`NEW_DAEMON` 启动、`DEL_DAEMON` 停止）。
- **`Dump<T>`**：`entries` + `rejected`（原始字节 + 解析错误）+ `interrupted`（`NLM_F_DUMP_INTR`），实现"单条坏消息不毁掉整个 dump"与"不静默返回残缺快照"。
- **`Stats`**：32/64 位容器合并为一个全 `u64` 类型，优先 `STATS64`，`STATS` 作为回退；未知统计成员忽略（含 `PAD`）。
- **`Netmask`**：`Mask(Ipv4Addr)` / `Prefix(u8)` / `Raw([u8;4])`，编码时按地址族校验（IPv6 前缀 1..=128），避免把内核的两种语义混成一个数字。
- **`Timeouts` 字段为 `Option<u32>`**：`SET_CONFIG` 的语义就是部分更新（只发送 `Some`），`GET_CONFIG` 在协议未编译时可能缺字段。
- **未知属性**：`Service`/`Dest`/`DaemonConfig` 的 `unknown: Vec<RawAttr>` 原样保留；`KernelError.extack` 保留未识别的 extack 属性。
- **`Ipvs` 全程 `&mut self`**：单个 netlink socket 的 seq 匹配需要串行化，线程/并发策略留给上层；注入点 `with_transport(Box<dyn NetlinkTransport>)`，`new`/`new_with_sock` 仅 `std` 特性。

### 测试形态

- `src/nl.rs` 内联 14 个单测：头部/属性预期字节、对齐、嵌套、截断、多消息、`NLMSG_DONE`、GETFAMILY 请求逐字节。
- `tests/protocol.rs`：11 个请求形状测试（含 IPv4/6/fwmark 服务、dest、daemon、超时；`add_service` 有完整逐字节期望）。
- `tests/control.rs`：27 个行为测试（家族失败、extack、EPERM/ESRCH、单查询与 dump、多 datagram 拼接、空/中断/降级 dump、seq 停放、裸收发、字符串/掩码校验、stats32 回退）。
- 主要公开类型/方法有 doctest（共 61 个）；真实内核用法为 `no_run`，注入传输示例可运行；其余访问器由单测覆盖。
- 本机无 IPVS/CAP_NET_ADMIN，全部测试走注入；`examples/list_services.rs` 供有权限的环境手工验证。

## 参考

- 本机 UAPI 头：`/usr/include/linux/ip_vs.h`、`genetlink.h`、`netlink.h`（内核 7.1.5，逐字核实）。
- 内核实现：`net/netfilter/ipvs/ip_vs_ctl.c`、`ip_vs_netlink.c`（对照核实清单 A 项）。
- 生态：`nlrs`（Layer 1 参照）、`keepalived`/`ipvsadm`（C 工具参照）。
- 对标：`fanotify-fid` 的"与既有库分工、不重复造轮子、政策留白"；`linux-nfc` 的 netlink 消息层可共用。

## 实现前核实结论（已完成 · 2026-08-04）

> 本节是本项目开工前的调查结论，供新会话直接使用，避免重新调查。

### 环境约束（本机验证）

- 本机无 `/proc/net/ip_vs`（IPVS 内核模块未加载/未编译）、无 root、无 sudo、无 CAP_NET_ADMIN。
- **结论**：实现与测试**不能依赖真实 IPVS 内核交互**。全部走可注入路径：netlink 消息层纯测（预期字节序列）、传输注入模拟成功/错误、家族解析失败路径注入。真实系统验证留给有 root + IPVS 的用户（`no_run` doctest + example）。
- 本机有 `/usr/include/linux/ip_vs.h`、`genetlink.h`、`netlink.h`（内核 7.1.5）——**命令/属性/标志/家族名已逐字核实**。

### 已核实结论速查

- 传输：Generic Netlink（`NETLINK_GENERIC`=16），家族 "IPVS" v1；id 经 `CTRL_CMD_GETFAMILY` 解析。
- 命令：服务 4 + 真实服务器 4 + 守护进程 3 + 配置 4 + ZERO/FLUSH。
- 属性：`CMD_ATTR`（SERVICE/DEST/DAEMON 嵌套 + 3 超时）、`SVC_ATTR`（12 项）、`DEST_ATTR`（15 项）、`DAEMON_ATTR`（8 项）、`STATS_ATTR`（11 项）、`INFO_ATTR`（2 项）。
- 字节序：`ADDR` 网络序（请求 4/16 字节，回复 16 字节）、`PORT` be16、`STATS`/`STATS64` 主机序、`NETMASK` IPv4=be32/掩码、IPv6=主机序前缀长度；其余标量主机序。
- 标志：`NLA_F_NESTED`/`NET_BYTEORDER`；dump 用 `NLM_F_DUMP`、`NLM_F_ACK` + extack。
- **清单 A 复核结论（2026-11-14）**：见上文“A. 内核事实核实”与“实现结论”；原先三处假设已被内核源码纠正。

### 已定的 API 决策（不要推翻）

- 见"设计决策"1–7：消息层纯函数 + 传输注入；家族解析缓存；dump 多段处理；字节序类型化；破坏性显式；零依赖核心。
- 模块划分：nl / ipvs / service / dest / stats / daemon / timeout / error。

### 开工流程（本节为历史记录；0.1.0 已按此流程完成）

1. 通读本 DESIGN.md 全文 + 同目录 `AGENTS.md`。
2. 完成清单 A 剩余 4 项核实（对照 `net/netfilter/ipvs/` 源码；本机无 IPVS 则注入代替）。
3. 从 `src/nl.rs`（纯函数消息层 + 预期字节单测）起步，再 ipvs（传输/家族）→ service/dest → stats/daemon/timeout。
4. 全部绿后一次性写入正式目录并单次提交（`--amend` 合并后续修改）。
