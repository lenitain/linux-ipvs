# AGENTS.md — linux-ipvs 实现指南

> 本文件是给（重新）开始实现 linux-ipvs 的 AI agent 的操作指南，来自同系列已完成的 `linux-pstore` 与 `apparmor-policy` 的实现复盘，并针对本项目的领域特化。它与 `DESIGN.md` 配合：DESIGN.md 讲"做什么、为什么"（背景/范围/止步点/已核实的内核事实 F1–F6/设计决策/交付清单），本文件讲"怎么做、别踩什么坑、本项目怎么验证"。**新会话必须先通读 DESIGN.md 全文（重点：背景、内核事实 F1–F6、设计决策 1–7、实现前核实结论），再读本文件。**

## 1. 项目定位（一句话）

本系列 crate 都是 **Layer 2 机制层**：把某个 Linux 子系统/协议的正确性问题一次做对（编解码、嵌套属性、状态管理、RAII、错误语义、容错降级），把偏好问题（事件循环、线程、策略、缓存）留给上层。linux-ipvs 就是 Linux IPVS 的 netlink 机制层：generic netlink 消息层、服务/真实服务器/统计/守护进程/超时管理的完整类型化封装。核心红线：**机制层做完整（正确性问题不能甩给用户），政策层留白（不替用户做偏好决定）**。

## 2. 实现流程（按顺序，不要跳步）

1. **核实事实（最优先）**——DESIGN.md 的"内核事实"F1–F6 已核实并带出处（本机 `ip_vs.h`/`genetlink.h`/`netlink.h` 逐字核对），**直接用，不要重新调查**；清单 A 剩 4 项（`SET_INFO`/`SET_CONFIG` 可写属性、`GET_SERVICE` 单回复形状、IPv6 地址长度、本机 IPVS 可用性）开工第一天对照 `net/netfilter/ipvs/ip_vs_netlink.c` 核完——linux-pstore 教训：假设被内核源码推翻，返工一整段。
2. **开工即拿真实样例验证**——本机无 IPVS，用**合成样例**：预期 netlink 字节序列（构建消息 → 断言字节；合成回复 → 解析断言）。消息层的 fixture 开工第一天就建。
3. **在 `/tmp` 开发实现**——按 DESIGN.md 的模块划分，从 `src/nl.rs`（纯函数消息层 + 预期字节单测）起步，再 ipvs（传输/家族）→ service/dest → stats/daemon/timeout，每个模块边写边补单元测试；不在正式目录里磨。
4. **集成测试**——happy path + **每个错误变体** + 容错；dump 多段拼接；extack 解析；空 dump。
5. **doc test 全覆盖**——每个公开 API 有可运行 doctest（合成字节/注入传输）；真实系统用法用 `no_run` doctest + 可选 example。
6. **质量门全绿**——见第 5 节命令；特性矩阵（默认 + `--no-default-features`）都要绿。
7. **仓库卫生**——见第 4 节清单与"当前仓库状态"。
8. **一次干净提交**——/tmp 开发全绿后，一次性写入正式目录并 commit；后续修改用 `--amend` 合并。
9. **对照 DESIGN.md 清单 A–E 最终审计**——逐项给出证据，不是"看起来没问题"。

## 3. 两个 crate 的复盘：没做好的事（别再犯）

### 3.1 事实核实与真实样例
- **内核事实核实太晚 / 假设被推翻**：linux-pstore 的文件名格式、压缩算法两项假设都被内核源码推翻。→ 本项目 F1–F6 已核（头文件逐字），清单 A 剩余 4 项开工第一天核完。
- **真实语法验证太晚**：apparmor-policy 拿真实 profile 才测出漏掉的语法。→ 本项目没有真实 IPVS，**预期字节序列 fixture 就是一切**：每个命令/属性组合都要有构造→字节→解析的往返测试。

### 3.2 解析器的细节坑（apparmor-policy 反复踩，全是真实 bug）
- **对齐/填充**：nla 长度必须 `NLA_ALIGN`（4 字节）；嵌套属性必须带 `NLA_F_NESTED`；解析时校验 `nla_len>=4` 且不越界——最容易踩。
- **字节序**：`ADDR`/`PORT`/`TUN_PORT` 是网络序；`STATS`/`STATS64` 全部主机序（`nla_put_u64_64bit`）；`NETMASK` IPv4 是 be32 掩码、IPv6 是主机序前缀长度（1..=128）。类型化封装后用户不碰，但编解码内部必须分清。
- **多部分消息**：dump 的 `NLM_F_MULTI` + `NLMSG_DONE` 结束；seq 匹配校验——漏掉 `NLMSG_DONE` 会挂起，漏掉 seq 校验会串消息。
- **终止符号双重消费**：属性解析时 `nla_len` 与整体 `nlmsg_len` 都要管——内层循环消费后外层不能再越界。
- **补丁应用必须验证**：改代码后立即构建验证。
- **属性测试优先**：往返（构造→字节→解析==原值）是最强不变量。

### 3.3 仓库卫生（用户逐条指出，一开始就要做）
- `Cargo.lock` 不提交（库 crate），`.gitignore` 要有（`/target`、`/Cargo.lock`、编辑器杂项）。
- `DESIGN.md` 是过程文件：README 不引用、Cargo.toml 的 `include` 不含它。
- `LICENSE` 版权行用 `Copyright (c) 2026 <crate> contributors`（不是个人名），文本与同系列一致。
- `CHANGELOG.md`（Keep a Changelog）从一开始就要有，别等用户提醒。
- `Cargo.toml` 字段补全：`documentation`、`readme`、`authors`、`include`（含 CHANGELOG 与 tests，**不含 DESIGN.md**）、`[lib]`。
- CI 四 job（test 特性矩阵 / fmt / clippy / doc），`RUSTFLAGS="-D warnings"`。
- README 开头：标题 + 四个徽章链接（crates.io / docs.rs / License / CI，每个徽章一行），正文只写总览 + 一个主示例；`Cargo.toml` description 与 README 副标题保持精简一致。
- `.md` 格式：无意义硬换行一律去掉（段落/列表项各一行）；代码块、表格、标题、徽章等结构性换行必须保留。

## 4. linux-ipvs 本项目要点（实现前必读）

### 4.1 本项目的核心难点与应对
1. **netlink 消息层（最难也是最有价值的部分）**：`nlmsghdr`（16 字节，`nlmsg_len` 含头部）+ `genlmsghdr`（4 字节）+ `nlattr`（4 字节头 + 对齐载荷）的编解码。**先写 `src/nl.rs` 并用预期字节序列做往返测试**（构造→字节断言→解析==原值 + 对齐断言）。嵌套属性（`NLA_F_NESTED`）是本项目属性结构的基础（CMD_ATTR→SVC_ATTR 两层）。
2. **家族解析**：先 `CTRL_CMD_GETFAMILY`（nlmsg_type=0x10，带 `CTRL_ATTR_FAMILY_NAME="IPVS"`）取家族 id，缓存进 `Ipvs`。解析失败（家族不存在）→ `Error::FamilyNotFound`（内核未编译 IPVS）。`new_with_sock` 让测试注入。
3. **传输可注入（不回避内核交互）**：socket 创建/send/recv 抽成可注入边界。消息构建/解析全纯测，**成功路径与错误路径都在本机测**，只留最终 syscall 命中给真机。真实用法给 `no_run` doctest + example。
4. **dump 多段处理**：`NLM_F_MULTI` 多段回复直到 `NLMSG_DONE`；每段独立解析，失败降级保留原文，不因单段坏掉整个 dump；空 dump 返回空 Vec。
5. **字节序类型化**：`Ipv4Addr`/`Ipv6Addr`/`u16` 端口，编解码内部做网络序转换；`STATS`/`STATS64` 是主机序；`NETMASK` 按地址族有掩码/前缀两种语义（`Netmask` 枚举）。

### 4.2 无 root 验证受限 → 测试策略（本机实测）
- 本机无 `/proc/net/ip_vs`（IPVS 未加载）、无 root、无 sudo、无 CAP_NET_ADMIN。**任何测试都不要依赖真实 IPVS 内核交互**。
- 全走可注入：消息层纯测（预期字节序列）、传输注入模拟成功/错误、家族解析失败路径注入。CI 不碰内核。
- 真实系统验证留给有 root + IPVS 的用户：`no_run` doctest + 可选 `examples/`（列出服务）编译校验。
- 本机有 `/usr/include/linux/ip_vs.h`、`genetlink.h`、`netlink.h`（内核 7.1.5）——命令/属性/标志/家族名已逐字核实，实现时直接对照，不用联网。

### 4.3 止步点红线（本项目特有，写每个 API 前对照）
- **做**：消息层、家族解析、服务/RS/统计/守护进程/超时类型化、dump、extack 透传、错误类型化、`AsFd` + 原始收发逃生舱。
- **不做**：调度算法、健康检查、keepalived 配置、高可用状态机、legacy setsockopt 接口、线程/异步。
- **逃生舱**：`as_fd`、`send_raw`/`recv_raw`（原始 netlink 消息）。
- **别做过头**：不要在 `add_service` 里自动带统计请求；不要在 drop 里隐式 del；不要替用户决定 dump 还是单查。

### 4.4 当前仓库状态（0.1.0 已完成 · 2026-11-14）
- 实现已完成并一次性提交：`nl` / `ipvs` / `service` / `dest` / `stats` / `daemon` / `timeout` / `error` / `proto`，约 4000 行含测试。
- 测试：`tests/protocol.rs`（11 个请求形状测试）+ `tests/control.rs`（25 个行为测试）+ `nl` 内联单测 + 全部公开 API 的 doctest；注入传输在 `tests/common/mod.rs`。
- 仓库卫生已就绪：README（四徽章、无 DESIGN 引用）、CHANGELOG、CI（test/fmt/clippy/doc，双特性）、LICENSE contributors、`Cargo.lock` 不提交、`include` 不含 DESIGN.md。
- **后续修改请保持 DESIGN.md 的“实现结论”与源码一致**；内核事实以 F1–F6 与“实现结论”中的三处纠正为准（回复 `ADDR` 恒 16 字节；`STATS64` 主机序；`NETMASK` 双语义）。
- 尚未在真机验证：本机无 IPVS/CAP_NET_ADMIN；`examples/list_services.rs` 留给有权限环境。

## 5. 仓库卫生清单（提交前逐项勾）

- [ ] `cargo fmt --all -- --check` 绿
- [ ] `cargo clippy --all-targets -- -D warnings` 绿
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` 绿（缺文档即红）
- [ ] `cargo test` 与 `cargo test --no-default-features` 都绿
- [ ] `#![warn(missing_docs)]` 常驻；每个公开 API 有可运行 doctest
- [ ] Cargo.toml：description/documentation/repository/readme/keywords/categories/authors/include/[lib]（include 含 CHANGELOG 与 tests，**不含 DESIGN.md**）
- [ ] CHANGELOG.md、LICENSE（contributors）、.gitignore（Cargo.lock 不提交）、CI 四 job
- [ ] README 开头有四个徽章链接（crates.io / docs.rs / License / CI，各一行）；正文只写总览 + 一个主示例；DESIGN.md 不进发布包、不被 README 引用
- [ ] .md 无意义硬换行已去除（段落/列表项各一行；代码块/表格/标题/徽章结构保留）
- [ ] 系统相关分支可测：消息层预期字节 fixture、传输注入、家族解析失败注入（linux-pstore 的 `open_inner` 教训）
- [ ] 特性矩阵进 CI（默认 + 无默认）

## 6. 止步点自检（写每个 API 前问自己）

1. 这个 API 是不是在替上层决定"它怎么跑"（循环/线程/时机）？→ 是则不做。
2. 是否隐含了只适用部分场景的假设（"总是自动发现"、"总是缓存"）？→ 是则做成可选/可插拔。
3. 上层必须付出代价才能绕过我（改源码 / 开 unsafe / 重新解析我吞掉的信息）？→ 是则留逃生舱（`as_fd` / `send_raw` / `recv_raw`）。
4. 破坏性行为是否可能在用户不知情时发生？→ 是则改为显式（`del_service`/`del_dest`/`flush`/`zero_services` 都只显式调用）。

正面参照（已完成 crate 的做法）：
- 数据永远给原始字节/原文；解析失败的内容降级保留，绝不丢数据。
- 清除/删除/修改绝不隐式发生，只有显式调用才执行。
- 系统相关探测抽成可注入函数，让系统分支也能单测（本项目扩展到传输注入）。

## 7. 红线

- 机制层做完整：正确性问题不能甩给用户。
- 政策层留白：不做偏好决定（事件循环、线程模型、缓存策略、资源发现策略、健康检查策略、业务语义）。
- 数据不因"不识别"而丢失：未知属性/未知命令降级保留，绝不整体失败。
- 解析阶段不展开、不吞信息：属性完整映射到类型化结果；原始消息可回溯。
- 用往返不变量作为核心不变量：消息层构造→字节→解析==原值；dump 拼接大范围测试。
- 零依赖可用：`default-features = false` 必须能构建（核心只用 `libc` + `std`）。
- **本领域特有**：nla 对齐/嵌套/字节序（ADDR/PORT/TUN_PORT 网络序，STATS 主机序）；dump 的 `NLM_F_MULTI`+`NLMSG_DONE`+seq 匹配；extack（`NETLINK_EXT_ACK`+`NLMSGERR_ATTR_MSG`）透传；家族解析失败=内核未编译 IPVS；内核交互不回避——传输注入让成功/错误都能测。
