# 独立设计与实现审查

日期：2026-11-06；范围：`0.1.0-preview.1` 的 C CLI、bubblewrap 参数、可信初始化器、seccomp 与 CONNECT 代理。审查由负责设计/安全的独立 Agent 完成，实现和集成验证由其他 Agent 负责。本报告记录代码级发现与修正核对；不等同于第三方渗透测试或安全认证。

## 发现及处理

| 发现 | 影响 | 代码修正核对 | 验证方式 |
|---|---|---|---|
| 用户环境在可信 init 执行前应用 | `LD_PRELOAD` 可先于 seccomp 注入可信进程 | 用户环境改为 init argv，seccomp 安装后仅在目标子进程应用 | `ld_preload_target_only`，构造共享库确认仅目标加载 |
| 同 UID 的可信 init/relay 可被 procfs 间接访问 | 禁止 ptrace syscall 仍不能单独阻止 `/proc/PID/mem` 注入或重开控制 FD | 可信 init、代理和 relay 设置 `PR_SET_DUMPABLE=0`；fork 后代继承 | `control` payload 必须实际执行，检查可信父进程存在再检查 mem/fd 拒绝 |
| bubblewrap 默认 PID 1 是额外未过滤进程 | 仅保护自有 init 仍留下对 bwrap PID 1 的 procfs 攻击面 | 使用 `--as-pid-1`，由非 dumpable 的 Tegum init 直接充当 namespace PID 1 | 代码核对；集成 `control`、后代清理和故障测试 |
| ioctl 请求号的高 32 位与内核语义不一致 | 仅完整值 EQ 比较可能漏掉低 32 位相同的 TIOCSTI/TIOCLINUX | 改成低 32 位 `MASKED_EQ` | seccomp 实现核对；探针应包含普通/高位 request |
| 命令信号被内层 init 转成普通退出码 | JSON signal 字段丢失，调用方无法区分退出与信号 | 控制通道另传命令终止信号，不能根据 `exit_code >= 128` 猜测 | `target_signal` 与普通 `exit 143` 应分别断言 |
| PDEATHSIG 安装与父进程退出存在竞态 | 只检查 `getppid() == 1` 漏掉 subreaper 接管 | fork 前记录父 PID，子进程设置 PDEATHSIG 后核对精确父 PID | 代码核对；调用方/监督器死亡与后代清理测试 |
| 结果文件放在授权 workspace 内 | payload 可改写调用方依赖的执行结果 | 规范化父目录/既有文件路径，拒绝 workspace 内目标；拒绝 symlink 和多硬链接文件 | `result_outside_workspace`，应补符号链接父目录/硬链接变体 |
| 非标准 IPv4 字面量穿过域名语法检查 | `0x08080808` 等被 libc 直接解释，违反“仅 DNS 名”契约 | 在纯语法检查后用 `AI_NUMERICHOST` 识别并拒绝 libc 数字地址格式 | proxy unit 覆盖十六进制和 loopback legacy literal |

表中“代码修正核对”只表示审查时看到了对应实现，真实运行通过/失败/阻断以 `validation.md` 和原始 evidence 为准；未出现的测试不能据此推断通过。

## 核对的主要边界

- 网络路径使用独立 netns；AF_INET/AF_INET6 socket 允许访问 namespace loopback，不代表允许宿主网络。删除代理变量、绕过 relay 连接同一 UNIX socket 都不能绕过宿主策略。
- CONNECT 只接受精确 host 和 443；Host 冲突、请求体长度/分块编码、畸形 authority 拒绝。隧道成功后转发任意 TCP 字节，不做 TLS/SNI/URL 检查。
- DNS 的每个返回地址先检查，任一不合规则拒绝。连接使用已校验 sockaddr，无二次 DNS 查询；混合公网/私网解析不会只挑公网掩盖其余结果。
- 代理/relay worker 各自有计数上限、时限与 PDEATHSIG，监听 socket 不传给目标。宿主代理不提供 SCM_RIGHTS 控制协议。
- 执行不经隐式 shell；继承环境/额外 FD 清除；根挂载从空视图构造，系统运行时只读；默认不暴露宿主 home、run 或整个 etc。
- seccomp 使用 native ABI、坏架构 kill 动作和 no_new_privs；clone namespace flags 拒绝，clone3 返回 ENOSYS，禁止 io_uring 等替代入口。它仍是默认允许未知 syscall 的拒绝清单。

## 尚需持续验证的内容

1. VM 与 Docker 的实际结果分别记录；被外层策略拒绝启动记 BLOCKED。宿主 macOS 的编译或代理单元测试不构成 Linux 沙箱证据。
2. `ptrace_scope=0` 下的全部可信进程 procfs 攻击、更多兼容 ABI 和内核新 syscall，仍需额外平台和针对性测试。non-dumpable 与 `--as-pid-1` 的静态修正不能替代所有负例。
3. DNS 混合结果、DNS 失败、上游连接失败、请求头慢速/洪泛、worker 上限、半关闭与大双向流应加入持续回归；公网一次成功不覆盖这些行为。
4. SIGKILL 监督器、调用方退出、relay/宿主 proxy 突然死亡，以及多任务并发中的后代/worker/临时目录清理需要分别验证。SIGKILL 无法写结果；临时目录可能遗留，不能把该限制隐藏在“完全清理”宣称里。
5. 不包含 cgroup 资源隔离、磁盘/输出配额、允许服务数据外传防护或内核漏洞防护。授权目录中的硬链接、宿主 UNIX 控制 socket 和子挂载必须由调用方审查。
6. 仅有本机 ARM64 VM/容器证据不能宣布 amd64 或其他发行版已支持。稳定版还需要独立人工审查与压力/模糊测试闭环。

若验证发现上述修正失效或新的边界绕过，应阻断预览版包的发布并记录复现；不能以普通功能正常或另一平台通过抵消。
