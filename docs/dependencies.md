# 外部依赖、内核与安全策略

版本`0.2.0-preview.1`。本文列能力前提，真实版本/架构/环境结果以[validation.md](validation.md)为准；不能仅凭“安装成功”或内核版本宣布支持。部署委派见[deployment.md](deployment.md)。

网络/挂载/目标seccomp新增配置见[扩展契约](options-extension-20261111.md)，最终8d387e49输入已通过两环境各174项功能检查，独立原始数据复核和最终HEAD CI另记。host模式共享直接父环境的netns，需要该环境提供实际路由与DNS配置；容器内host模式不等于Docker的--network host。额外目录绑定需要bubblewrap支持`--bind-fd`与`--ro-bind-fd`，来源通过O_PATH预开；不支持时应拒绝该配置，不回退到有重新查找窗口的路径绑定。调用用户仍需具备源路径访问权限，不能授予宿主本来没有的写权限。syscall名称依赖libseccomp的native名称数据库，无法识别时拒绝配置；用户allow不能解除更外层过滤器，可信init/proxy过滤器不接受目标自定义覆盖。

## 构建、测试与运行依赖

| 依赖 | 用途与要求 |
|---|---|
| GCC或Clang、make | Linux C11/POSIX构建；使用编译器加固与严格告警 |
| libseccomp headers/library | 构建需要开发包，运行需要对应动态库；2.5系列或更新，记录精确版本；名称数据库不足不应跳过已明确支持ABI的fchmodat2拒绝 |
| libc、ELF动态加载器 | 本地原生ABI、进程/socket/DNS；发行包以manifest的ldd结果为准 |
| `/usr/bin/bwrap` | 运行依赖；目标发行版应提供支持本项目全部选项的版本，实测0.9.0，建议0.9+ |
| Python 3 | 独立测试、打包、soak和示例；运行已构建CLI不需要 |
| curl、CA certificates | 真实HTTP/HTTPS正例与使用示例；客户端仍负责TLS证书验证 |
| pkg-config | 验证记录libseccomp版本 |
| systemd用户管理器或等价委派服务 | 仅完整cgroup配额/用户测试scope所需；不是所有基础CLI场景的硬依赖 |
| Docker Engine、util-linux的nsenter等管理工具 | 容器集成验证及管理员限定委派引导；CLI本身不依赖Docker |
| ASan/UBSan运行库 | sanitizer测试构建需要对应编译器运行库；正式CLI不链接这些测试库 |

Ubuntu开发包示例为`build-essential pkg-config libseccomp-dev bubblewrap ca-certificates curl python3`。运行程序的shell/编译器/解释器应存在于只读暴露的系统目录。`/etc/alternatives`只读绑定使发行版的cc等标准别名可解析。CLI拒绝root、setuid/setgid执行，容器内也必须是普通用户。

产物是动态链接原生C ELF，不捆绑bubblewrap、libseccomp或完整Linux用户空间。应在兼容libc和CPU架构的环境构建/验证，不能把一个arm64归档直接当成amd64或通用静态包。保留安全更新，不因参考文档固定版本而停留在旧补丁。

## 内核基线与真实能力

基础模式需要可用的`pidfd_open`与`pidfd_send_signal`：其主线联合功能下限为Linux5.3（前者自5.3、后者自5.1）。还必须具备namespace、seccomp和tmpfs等能力，内核/外层策略不得阻止所需pidfd操作。**完整聚合资源模式的主线功能基线为Linux5.14+，并要求实际存在且可用的`cgroup.kill`**；发行版回移植、LSM策略和委派会改变实际可用性。推荐受发行版持续安全维护的6.1+环境，并在部署目标运行真实doctor/测试。这里不表示所有较新内核组合都已实测。

外部调用方用flags=0的进程pidfd监控，不依赖PR_SET_PDEATHSIG的创建线程终止语义，也不需要较新PIDFD_THREAD。guardian经owner进程pidfd发送取消信号。若CLI是容器PID1且外部父PID不可见，不宣称可以监控命名空间外调用方；内部受控单线程子树的PDEATHSIG和容器/PID1边界仍适用。

需要user/mount/pid/ipc/uts/net namespaces、procfs、tmpfs及bind mount、UNIX/TCP socket、`CONFIG_SECCOMP`和`CONFIG_SECCOMP_FILTER`。`user.max_user_namespaces`及各namespace配额必须非零且有剩余；发行版存在`kernel.unprivileged_userns_clone`时须允许目标用户创建userns。键不存在不自动等于不支持。

当前产物目标为x86_64/amd64与aarch64/arm64的64位native ABI；其他架构不声明支持。32位/兼容ABI命令不支持，seccomp坏架构动作会终止。严格profile明确允许所需syscall，未知入口拒绝；新运行时若依赖未列syscall需经审查添加，或由授权者显式选择compat，不自动降级。

完整配额还需要：

- cgroup v2统一层级、普通用户可写的专属委派父目录和必要的cpu/memory/pids控制器，父已启用所需subtree_control。
- `cgroup.procs`迁移权限、创建叶/写控制值/读回权限，以及可用的`cgroup.kill`和`cgroup.events`。
- 内存请求时需要memory.max、memory.swap.max及memory.oom.group；PID和CPU请求分别需要pids.max和cpu.max。
- 委派父不能含违反domain controller结构规则的直接进程；监督程序应放control叶，任务放另一个随机叶。CLI不自动重排其他服务的层级。

请求不能真实实施时为setup_error，不用RLIMIT_NPROC或每进程AS/CPU/FSIZE悄悄替代。memory.peak/pids.peak是可选观察接口，缺失时JSON的available为false。内存按内核memory控制器计费，不是RSS逐进程求和；HugeTLB分配入口被过滤，以减少不参与常规memory.max计费的分配路径。

## 文件系统与I/O

`--tmp-bytes`及`--disk-bytes`依赖bwrap的`--size`/`--tmpfs`，容量必须为系统页大小整数倍。根tmpfs是命名临时写路径的共同容量边界；只读运行时和输入挂载不计入写预算，宿主readwrite挂载不受该总额限制。匿名memfd/SysV内存由memory配额另行限制。

输入和导出父目录应由可信调用方控制，避免宿主同UID并发替换。受管复制拒绝特殊文件、超深/超多节点和超逻辑字节预算；导出不为宿主文件系统设置project quota，也不保证全树事务。输出预算只覆盖目标stdout/stderr；bwrap/可信init的独立诊断最多转写16KiB、超额读取后丢弃，不计目标预算。supervisor自身的少量诊断另计，不受这条16KiB总额约束。stdin通过只读中继。结果路径须在workspace/export之外，读取者应等待CLI退出。

调用方无需预先解除线程信号屏蔽或修复SIGCHLD忽略状态：run/doctor会先建立管理信号策略再清mask，保证取消与wait回收的契约。请求CPU/file rlimit时目标对应SIGXCPU/SIGXFSZ在exec前默认处理，运行后程序仍可自行调整。这是新进程的初始化，不改调用方信号状态。

## AppArmor、SELinux与seccomp

LSM可独立拒绝userns、loopback配置、mount、proc或seccomp；版本足够不代表被允许。Ubuntu非特权userns策略可能需要针对发行版bwrap的限定profile。优先使用发行版/管理员审查后的配置，保留全局防护，检查audit拒绝信息。SELinux enforcing目标需要相应管理员策略并单独验证，不把停用SELinux作为安装步骤。

CLI不自动修改sysctl、AppArmor/SELinux、Docker daemon或防火墙。CI临时VM使用仅绑定`/usr/bin/bwrap`的`enclio-ci-bwrap` userns许可，保留全局限制值、拒绝覆盖已有bwrap profile，记录原文/hash/加载前后状态并在job结束卸载。此profile使用unconfined模式授予应用级userns例外，本身不额外提供AppArmor confinement，也不是生产通用配置。

目标strict/compat过滤、可信init兼容过滤与proxy独立过滤是不同策略。代理权限修改拒绝包含fchmodat2；若libseccomp名称库不能解析它，两种支持的64位native ABI仍按已核对的syscall452拒绝。Linux6.8 UAPI仅用于编号追溯，不把基础运行下限提升到6.8；来源见[references.md](references.md)。proxy还对全部ioctl返回EPERM，包括通过只读文件FD修改元数据的入口及高位request别名；本次不改变目标seccomp策略。

代理依赖可信DNS/NSS配置和模块，允许只读加载及包括NETLINK在内的解析需要，但不声明兼容所有NSS机制。部署方必须验证实际解析配置；若某模块依赖ioctl等被禁调用而不能完成解析，应拒绝连接，不能降低过滤器或直连。地址策略仍由代理代码检查全部DNS结果及实际sockaddr，不能靠seccomp读取connect指针实现。

## Docker条件与外层配额

容器共用宿主内核；镜像安装bwrap不能补足宿主能力。基础沙箱需要外层seccomp/LSM/proc遮罩允许嵌套user/mount/pid/net与proc配置。仓库测试所需的明确例外、授权范围及回滚在[部署评审](deployment-validation-review.md)中记录；它们只作用于指定测试容器，不代表默认Docker策略通过，也不自动成为生产建议。

聚合配额另需委派**该容器自身cgroup子树**。不能把payload迁到宿主外部可写父组，因而逃离Docker外层的memory/pids/CPU安全网。管理员引导操作与普通用户运行分开；不使用privileged、不添加SYS_ADMIN、不挂Docker socket、不暴露整个宿主cgroup树。实际bootstrap入口与本轮状态见[deployment.md](deployment.md)及最终验证报告。

## 许可证与交付

原始实现见根LICENSE；上游来源与许可证见[references.md](references.md)。默认只动态链接libseccomp并执行外部bwrap，不复制二者源码。若另行分发上游二进制/库或静态链接，需按实际版本补许可证、源码获取/重链接材料，不能仅凭本项目MIT许可证覆盖第三方。

最终包应记录源码Git提交/dirty状态、执行输入摘要、工具/库版本、架构和二进制SHA256。未完成的持续运行、外部审计或平台验证必须保留未完成状态。
