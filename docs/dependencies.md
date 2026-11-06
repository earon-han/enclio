# 外部依赖、内核与平台策略

本文说明能力前提，不替代真实运行证据；已验证版本、VM 与 Docker 各自结果见 `validation.md`。

## 构建与交付

| 依赖 | 用途 | 首版要求 |
|---|---|---|
| C 编译器 | 生成原生二进制 | GCC/Clang，C11 与 Linux/POSIX API |
| make、pkg-config | 构建及 libseccomp 探测 | 发行版常规版本 |
| libseccomp headers/library | syscall 规则生成和加载 | 2.5 系列或更新；测试记录精确版本 |
| libc 和动态加载器 | POSIX、DNS、进程与 socket | 发行目标兼容的 glibc；以包的 `ldd` 输出为准 |
| Python 3 | 集成测试、基准、通用 Agent 示例 | 开发/验证工具，CLI 执行不依赖 Python |
| curl、CA certificates | 网络正向验证 | 仅使用指南示例/网络测试需要 |
| Docker Engine | 独立容器验证 | 开发/验证工具，CLI 本身不依赖 Docker |

运行时需要 `/usr/bin/bwrap`（0.8+，包括 `--disable-userns` 支持）、libseccomp 与 libc。发行产物不包含整个 Linux 用户空间，也不是容器镜像的替代品；用户命令依赖的解释器和共享库需在暴露的系统运行时中存在。Tegum 拒绝 root 或 setuid/setgid 运行，容器内也必须使用普通用户。

Linux 发行版中的依赖应保持安全更新。文档固定版本的引用是设计依据，不表示推荐停留在旧补丁级。安装包、发行版补丁、CPU 架构和 libc ABI 都是兼容性的一部分。

## 内核能力

项目首版以仍接收厂商安全更新的 Linux 5.4+ 作为功能基线，建议使用发行版当前维护的更新内核；这是一项项目支持策略，不是声称每个更旧内核必然不能执行，也不表示所有 5.4+ 组合已经测试。需要以下配置和能力：

- `CONFIG_NAMESPACES`、`CONFIG_USER_NS`、`CONFIG_PID_NS`、`CONFIG_NET_NS`、`CONFIG_IPC_NS`、`CONFIG_UTS_NS`。
- `CONFIG_SECCOMP`、`CONFIG_SECCOMP_FILTER`，且当前 native 架构支持 seccomp BPF。
- mount namespace、procfs、tmpfs、bind mount、UNIX 和 TCP socket；namespace 数量配额未耗尽。
- 普通用户创建 user namespace 被允许，UID/GID 映射可完成；无需 setuid Tegum，不要求特权 `bwrap`。

检查 `user.max_user_namespaces` 以及 user/pid/net/mnt/ipc/uts 对应最大 namespace 数必须非零且有剩余额度。存在发行版 `kernel.unprivileged_userns_clone` 时需允许目标用户创建 userns。该键并非所有内核都有，缺少该键不等同于不支持。

`PR_SET_NO_NEW_PRIVS` 与 seccomp 过滤必须真正成功，不能用“存在 `/proc/sys/kernel/seccomp`”代替执行探测。Tegum 遇到缺少依赖、namespace 建立失败、映射/挂载拒绝或 seccomp 安装失败时拒绝运行目标，不能回退无隔离模式。

Linux VM 为 ARM64 时只构成 ARM64 运行证据；源码可在 amd64 编译不构成 amd64 已验证。32 位/兼容 ABI 命令不在首版支持范围内。

## AppArmor、SELinux 与宿主策略

发行版可独立限制 userns、mount、procfs、socket 和 seccomp，不应仅凭内核版本判断可用。Ubuntu 24.04 及以后启用的 AppArmor 非特权 user namespace 限制可能要求为 `/usr/bin/bwrap` 配置 scoped 许可；优先使用发行版提供的 bwrap profile 或由管理员添加限定许可，保留全局防护。检查 kernel/audit 日志中的拒绝信息。参见 [Ubuntu AppArmor 文档](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/)。

SELinux enforcing 或自定义 LSM 策略也可能拒绝嵌套 user/mount namespace，需由管理员提供对应策略并验证；不能把停用 SELinux 写成默认安装步骤。Tegum 不自动修改 sysctl、AppArmor、SELinux、Docker daemon 或宿主防火墙。

seccomp 拒绝清单只减少内核接口，并不抵御内核自身漏洞；宿主必须运行仍受支持且已更新的内核。外层服务还应限制 CPU、内存、PID 数、磁盘和输出。内核版本数字本身不能表明所有安全修复均已包含。

## Docker 容器条件

容器共用宿主内核，因此镜像中安装 bubblewrap 不能补足宿主缺失的 namespace/seccomp 能力。需要：

1. 宿主允许非特权 userns 和必要嵌套 namespace。
2. 外层 Docker seccomp profile 允许 bwrap 初始化所需的 clone/unshare、映射和挂载步骤；Tegum 安装的内层过滤仍必须成功。
3. AppArmor/SELinux policy 允许该初始化；外层策略允许 seccomp 不代表 LSM 也允许。
4. 使用容器普通 UID、无 `--privileged`、无 `CAP_SYS_ADMIN`、不挂载 Docker socket/宿主敏感目录，并提供明确的 workspace。

Docker 默认 seccomp 通常会限制创建 namespace 的调用，是否可以直接启动取决于实际 Engine/profile/宿主组合。应同时验证默认配置的 fail-closed 行为和显式支持嵌套 namespace 配置的成功行为。[Docker seccomp 文档](https://docs.docker.com/engine/security/seccomp/)说明可使用 `--security-opt seccomp=profile.json`；推荐在部署中审查限定 profile。

如果验证使用 `seccomp=unconfined` 或 `apparmor=unconfined`，报告必须准确记录：它仅用于验证 Tegum 内层机制，不能称为默认 Docker 安全策略下通过，也不是生产推荐。不要用增加 SYS_ADMIN 或特权容器掩盖“不支持普通用户”的问题。

## 网络与文件系统前提

宿主代理需要可信 DNS、出站 TCP 连接权限与可信路由；白名单域名需要解析为可接受公网地址。默认拒绝私有/链路本地地址也会阻止公司内部 API 和经内部代理重写 DNS 的域名，这是预期策略。仅支持 CONNECT；客户端需要尊重代理配置或自己实现 CONNECT。

授权 workspace 和其父目录应由调用方控制，不可在启动时被宿主恶意同 UID 并发更换。它不应含宿主控制 socket、非预期子挂载、通向敏感内容的硬链接或机密。只读运行时也必须由可信管理员维护；Tegum 不验证整个工具链的完整性。

## 许可证与供应链

本仓库原始实现与许可证见根目录 `LICENSE`。bubblewrap 是独立执行依赖，libseccomp 是链接依赖；二者的来源、固定版本参考与许可证见 `references.md`。默认不把上游源码复制进本仓库。若发行包分发库/bwrap 或静态链接，应随包保留许可证、对应源码获取方式及适用的重链接材料，按实际分发内容维护第三方清单。

发布前记录源码 commit、构建工具和依赖版本、架构、动态库需求与 SHA-256。相同“tegum”文件名不等于相同 ABI/版本，支持报告必须绑定具体产物。
