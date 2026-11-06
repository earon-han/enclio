# Tegum 首版设计与安全模型

状态：`0.1.0-preview.1` 设计基线；真实平台验证结果见 `validation.md`，未实测的平台不构成支持承诺。对应实施计划 A00、A02、A03、A06—A09。

## 范围与语言决策

Tegum 面向需要启动不可信命令的通用 Agent、构建脚本和命令行调用方。首版以普通用户启动，提供单任务 CLI、显式可写工作目录、默认无外网、按目标授权的 TCP 代理、超时/取消和机器可读结果。运行平台为 Linux；macOS 仅可作为 Linux 虚拟机开发宿主。

采用 C11/POSIX 与 libseccomp。C 能直接表达 `fork`、`exec`、FD、信号、socket 和 seccomp 的生命周期，适合本项目规模，也符合维护者的语言偏好。协议解析采用固定上限、受限语法与明确错误路径，避免引入通用 HTTP 服务器。代价是内存安全依赖审查、编译器加固和测试；后续代理协议若明显扩张，应重新评估 Rust。Go 的交付体验很好，但在此范围引入运行时和 seccomp 集成层的收益不明显。

交付物是独立 CLI 可执行文件，不需要 Python/Node/Go 运行时；并不意味着完全没有外部依赖：发行包仍依赖 bubblewrap、libseccomp、libc、Linux 内核及宿主安全策略。默认动态链接便于发行版提供库更新。若另行制作静态包，必须同时处理 libc/DNS 兼容和 libseccomp 许可证义务，不能仅把 `-static` 当成可移植性保证。

首版不实现 OCI、Jiuwen 专有适配、TLS 解密、URL/HTTP 方法级策略、流量审计平台、cgroup 资源隔离、Windows/macOS 原生执行或任意 rootfs。版本为预览版，不作为敌对多租户执行服务的完整隔离层。

## 信任边界

可信计算基包含宿主 Linux 内核、bubblewrap、Tegum 启动器/代理/初始化器、系统动态加载器和只读挂载的工具链。命令、其后代、命令参数、工作目录内容和代理请求均视为不可信。调用方选择策略和工作目录，属于授权者；拥有同一宿主 UID 的其他进程可修改授权目录、终止进程或调试宿主代理，不在本边界内。

命令可以读写授权工作目录，读取暴露的系统运行时，向允许目标传输其可读数据。该设计不阻止利用允许服务进行数据外传，也不阻止内核漏洞、侧信道或拒绝服务。磁盘、进程数、CPU、内存和输出量的完整配额需由外层 cgroup/VM/服务执行。

只读系统目录是有意暴露的运行时，并非“只允许读取工作目录”。不要把机密放在 `/usr` 等运行时目录，或授权工作目录本身。挂载工作目录也会暴露其中已存在的硬链接和 socket；不要授权包含 Docker、SSH、D-Bus 或宿主服务 socket 的目录。只读挂载不能阻止通过 UNIX socket 的控制消息。

## 三层职责与数据流

```text
可信宿主                         bubblewrap 沙箱
Tegum supervisor                user/mount/pid/ipc/uts/net namespace
  ├─ UNIX CONNECT proxy  <────  UNIX socket <── loopback relay
  │    └─ 已授权公网 TCP                          ↑ 127.0.0.1:18080
  └─ bubblewrap                  init ── seccomp ── command + descendants
```

1. **bubblewrap** 建立新的文件系统视图和命名空间，限制可见文件、进程及直接网络；清除 capabilities，提供最小 `/dev` 和独立 `/proc`，建立新 session，配置父进程死亡关联。使用 `--as-pid-1`，由 Tegum 可信 init 充当 namespace PID 1 并回收子进程，不另外保留一个可被同 UID procfs 攻击的 bwrap PID 1。
2. **宿主代理** 是唯一跨网络命名空间的受控出口。它解析受限 CONNECT 协议、检查精确域名与端口、解析 DNS、过滤非公网目标，并连接已校验地址。
3. **seccomp** 在执行命令前安装、由后代继承，减少高风险内核接口。它是 syscall 拒绝清单，不是 syscall 允许清单，不能独立保证路径或网络策略。[内核文档](https://docs.kernel.org/6.12/userspace-api/seccomp_filter.html)也明确区分 syscall 过滤与完整沙箱。

## 文件、环境与 FD

从空根目录构造文件系统，只读挂载运行命令必需的系统目录；宿主整个 `/`、`/home`、`/run`、`/sys` 和 `/etc` 不整体挂入。仅挂载选择的配置/CA 文件。`/tmp` 与沙箱 home 是独立临时目录。唯一持久可写挂载为调用方指定的工作目录，沙箱内固定为 `/workspace`。

工作目录启动前规范化并验证；工作目录到挂载完成期间要求调用方不被同 UID 并发恶意修改。工作目录中的绝对符号链接在沙箱根解析，相对 `..` 不能越过该根访问未挂载宿主路径。测试覆盖指向宿主机密路径的符号链接。已经存在的硬链接、子挂载、UNIX socket 和授权目录内的机密仍属于调用方授权范围，不能靠字符串路径检查消除。

继承环境全部清空后重建固定 `PATH`、`HOME`、工作目录和区域设置；仅显式传入的用户环境保留。用户环境经 argv 传至可信初始化器，直到 seccomp 已安装、命令子进程已 fork 后才应用，因此 `LD_PRELOAD`、`LD_LIBRARY_PATH` 等只能影响已经受限的目标命令，不能提前注入可信初始化器/relay。代理变量由启动器生成，不能从宿主继承。`HTTP_PROXY`/`HTTPS_PROXY` 只是客户端配置，安全边界是 netns 与宿主代理策略。

关闭所有继承 FD，除 stdin/stdout/stderr 和内部控制通道；目标子进程在执行不可信命令前关闭控制通道，可信 init 留存直到报告退出信号。可信 init、relay 与宿主代理均设置 non-dumpable，阻止 payload 通过 procfs 打开其内存或控制 FD；只禁止 ptrace syscall 不足以覆盖该路径。stdio 是调用方显式授权的数据通道，socket 类型 stdio 被拒绝；不要把敏感宿主文件作为 stdio 传入。标准输出/错误还可含任意终端序列，消费方应按不可信数据处理。

## 网络契约

默认任务无代理、无外部接口、无宿主路由。开启代理仍使用独立 netns，只有 loopback；命令可建立 AF_INET/AF_INET6 socket 以连接本地 relay，删除代理环境变量不会获得宿主网络。工作负载不能创建 raw、packet、netlink 或 vsock socket。这里不依赖 seccomp 解析 `connect()` 指向的内存。

宿主 socket 位于每任务私有目录，沙箱仅看见该任务代理入口，不能通过该 socket 获得通用宿主 FD。允许绕过 loopback relay 直接连接同一 UNIX socket，因为它执行相同策略。

首版仅接受 `CONNECT hostname:443 HTTP/1.1` 或 `HTTP/1.0` 隧道请求；策略为精确 DNS 名，端口固定 443，无通配符、后缀匹配、URL、用户信息或 IP 字面量。域名比较不区分 ASCII 大小写。空策略拒绝所有出口。CONNECT 建立后转发原始字节，因此实际授权单位是“目标主机:443 上的 TCP 服务”，通常用于 HTTPS，但不强制 TLS、不检查证书/SNI、不限制隧道内容。普通 HTTP 的 absolute-form GET 代理、SOCKS、UDP、QUIC 不支持。

宿主按每次连接解析 DNS，检查全部返回地址；只要其中一个不符合地址策略就拒绝该次解析。IPv4 拒绝 loopback、私有、链路本地、组播、保留及文档/基准网段；IPv6 仅接受 global-unicast 范围，并排除实现中列明的协议、转换及文档网段。IPv4-mapped IPv6 直接拒绝。默认禁止 IP literal，包括 libc 接受的十六进制等 legacy 表示。连接使用已经检查过的 `sockaddr`，不得再次以 hostname 解析连接。DNS 失败或代理断开立即失败，不回退直连。地址策略是代码中的固定规则，不是动态下载的 IANA 注册表；新特殊分配需要随项目更新。它也不能抵御宿主特殊路由/NAT 把公网地址映射到内网；网络管理员须保证宿主路由可信。

协议解析拒绝多余 token、非法 authority、畸形控制字符、请求体长度/分块编码及非 443 端口；出现 Host 头时必须与 CONNECT authority 一致且不可重复。隧道建立前不向上游发送不可信请求体。当前上限：每个代理/relay 各 32 个 worker，请求头缓冲 8192 字节、头部接收/单地址连接 10 秒、DNS 与上游建立阶段共用 alarm 20 秒、隧道空闲 30 秒、单隧道阶段最长 300 秒；超限连接关闭。这是明确的协议限制，长连接需要重建。拒绝行为不能把请求原文或潜在凭据写进日志。

## seccomp 策略

使用 libseccomp 生成原生 ABI 过滤器，设置 `PR_SET_NO_NEW_PRIVS` 后加载；任何加载失败均拒绝执行。异 ABI syscall 使用 kill 动作，避免 x86 compat ABI 绕过原生 syscall 规则。首版仅声明原生 64 位 Linux ABI；不支持 32 位兼容命令。

拒绝 mount/新挂载 API、切换/创建 namespace、ptrace、跨进程内存访问、pidfd_getfd、BPF、perf、userfaultfd、keyring、模块/kexec、文件句柄式打开、io_uring 和危险设备/系统管理接口。保留普通 fork/clone 用于命令及线程，但过滤 clone namespace flags；clone3 返回 ENOSYS 允许支持的 libc 回退到 clone。过滤 ioctl 的 TIOCSTI/TIOCLINUX，并使用新 session 限制终端注入。规则随新内核 syscall 更新，默认允许的未知 syscall 是本拒绝清单策略的已知边界。

## 生命周期与结果

宿主 supervisor 持有每任务进程和临时目录。正常退出、命令失败、超时、SIGINT/SIGTERM/SIGHUP 取消、代理故障、初始化失败都汇入同一清理路径。supervisor 对调用方设置 PDEATHSIG(SIGTERM)，调用方死亡触发取消；首版不提供脱离调用方后台运行。bubblewrap PID namespace 与父进程死亡关联负责终止后代；仅向 process group 发送信号不够，因为后代可以 `setsid()`。每次 fork 后设置 PDEATHSIG 都核对预先记录的精确父 PID，避免安装前父已退出被 subreaper 接管。

执行前的可信初始化器安装 seccomp、完成 relay 准备，并用 close-on-exec pipe 检查命令 exec 失败，然后报告启动结果。执行失败与正常业务退出以独立状态区分。业务 stdout/stderr 直接传递；结构化结果使用独立文件，避免混入业务 stdout。结果文件必须位于 workspace 外，禁止符号链接或多硬链接目标，并在启动前打开。超时和取消由 supervisor 的 monotonic clock/信号决定，完成后等候被管理子进程退出再移除临时 socket/目录。

`SIGKILL` 下 supervisor 无法保证写结果文件；父进程死亡链必须仍终止代理和命令。宿主临时目录可能遗留，需要人工删除；目录权限限制其暴露范围。调用方死亡和直接终止 supervisor 是不同测试，不能仅依赖命令 timeout 或 kill supervisor 推断调用方死亡路径通过。

公共 CLI 契约：

```text
tegum run --workspace DIR [--timeout SEC] [--result FILE]
  [--cwd /workspace/subdir] [--env NAME=VALUE] [--allow-host DOMAIN]
  -- COMMAND ARG...
tegum doctor
tegum version
```

`--workspace` 是必填的宿主现有目录，映射为 `/workspace`，禁止 `/`；`--cwd` 是沙箱内工作路径；默认 timeout 300 秒，范围 1—86400。`--env`、`--allow-host` 可重复，分别最多 64 项。无策略文件隐式加载，命令参数在 `--` 后原样传递，不隐式经 shell 执行。

结果格式版本 `schema_version: 1`，包含 `status`（`exited`、`timeout`、`cancelled`、`setup_error`）、`exit_code`、`signal`、`duration_ms`、`command_started`。`exited` 包含业务成功、非零和信号终止；初始化、exec 或运行基础设施失败为 `setup_error`，不能把该状态视为安全负例通过。命令自行返回 124/125 也可能与保留 CLI 退出码重合，调用方应组合 JSON status 区分。

`doctor` 真正启动无网络 `/bin/true` 并安装 seccomp，再向 stdout 输出能力探测 JSON；它证明当前基本执行路径可用，不证明所有挂载、代理、上游网络或攻击负例均通过。使用示例见 `user-guide.md` 与 `tegum help`。内部 init 命令不是公共 API，宿主直接调用不能构成沙箱运行。

## 测试和发布门槛

所有安全负例先由 payload 输出执行标记，再断言访问被拒；启动失败必须记 BLOCKED。测试包括工作目录写入、系统只读、宿主机密不可见、符号链接、FD/环境、允许和禁止的 CONNECT、删除代理变量、直连、替代 socket family、危险 syscall、非零退出、exec 失败、超时、信号取消、调用方死亡、后台/脱离 session 后代和重复执行残留。

Linux VM 与 Docker 分开记录：操作系统、内核、架构、bwrap/libseccomp/Docker 版本、UID、capabilities、AppArmor/SELinux/seccomp 配置、命令、源码标识、通过/失败/阻断计数。Docker 默认策略阻断仅能证明 fail closed；还必须在显式可创建 namespace 的非特权容器中完成正向与安全负例。Docker 内层沙箱与 VM 共用一个内核，不能当作两个内核平台。

预览版门槛：这两个环境有真实功能与负例证据、无已知关键边界绕过、依赖明确、报告含未覆盖项、包及校验值可重建。稳定版额外要求 amd64/arm64 原生验证、独立安全审查闭环、可控故障/压力测试、外层资源限制集成和发布流程演练。

性能报告必须附原始样本和失败数。首版预算是观测而非承诺：目标每环境连续 100 次本地无网络 `/bin/true` 运行失败为 0、无进程/socket 残留；建议启动 p95 不超过 200ms，超过时记录原因，不为达预算放松隔离。公网访问受 DNS/互联网影响，不能与离线启动开销混为一项。
