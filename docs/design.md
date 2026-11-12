# Enclio 0.2 设计与安全模型

版本 `0.2.0-preview.1`。本轮范围、分工和门槛见 [completion-plan.md](completion-plan.md)，运行证据见 [validation.md](validation.md)。实现能力、模块自测、最终双环境验收及24小时持续运行分别记账，不能互相替代。

当前扩展方案及验收状态见[options-extension-20261111.md](options-extension-20261111.md)。网络共享、挂载和syscall放宽均由调用方显式配置；旧300c结果不替代新增输入；最终8d387e49的双环境各174项功能结果见扩展记录，独立原始数据复核和最终HEAD CI另记。

## 目标与边界

C11 CLI面向普通用户启动的Agent命令，提供文件/进程/网络隔离、受控TCP出口、严格系统调用策略、可请求的资源配额、可取消I/O与故障清理。动态链接产物仍需要bubblewrap、libseccomp、libc和受维护Linux内核，不是完整rootfs或语言运行时分发。

isolated受控代理支持HTTP、CONNECT、自定义TCP端口、SOCKS5域名TCP；该代理不支持UDP/QUIC、TLS解密、URL/HTTP方法级授权。host模式直接网络能力由父环境和有效seccomp决定。项目不提供内核漏洞隔离证明、同宿主UID恶意进程隔离、允许服务数据外传防护、Windows/macOS原生执行、OCI或专有Agent适配，也不将Agent代码审查称为外部人工安全认证。

可信计算基包含内核、bubblewrap、Enclio监督器/guardian/初始化器/代理、系统动态加载器、只读运行时和DNS/NSS配置。命令、参数、工作区数据、导出数据和网络请求均不可信。调用方选择workspace、策略和stdio，是授权者。宿主同UID进程可修改输入或结果、终止可信进程，不在此边界内；启动/导出期间授权目录及其父目录需要由调用方控制。

## 进程与资源结构

```text
宿主调用方
  └─ Enclio supervisor ── 私有控制通道 ── cleanup guardian
       ├─ 受管任务cgroup（配置时启用）
       │    ├─ 宿主策略代理（持有沙箱监听FD） → 已验证的公网TCP端点
       │    │    └─ 连接worker / HTTP uploader
       │    └─ bubblewrap
       │         └─ PID1: Enclio init → 目标 + 后代
       │              创建loopback监听FD → 私有控制通道交给宿主代理
       └─ 结果文件、stdin/stdout/stderr有界中继
```

supervisor与guardian在任务叶之外保留清理能力；外层服务/容器应限制它们。bwrap和宿主proxy在产生后代前进入同一叶，代理/uploader与payload计入同一CPU、内存和PID预算。未配置聚合限制时不假称已建立这些配额。

资源模块只在已委派cgroup v2父下建立自己的随机叶，不自动修改其他服务控制器。请求memory、pids、CPU带宽或显式parent时，检查真实接口、写权限及readback；缺失所需控制器、`cgroup.kill`或委派就失败。memory使用memory.max、swap.max=0和oom.group=1，pids使用pids.max，CPU使用100000微秒周期的cpu.max。100%为一个CPU的带宽。memory遵循内核计费语义，不等于RSS求和或RLIMIT_AS。

CPU seconds、虚拟地址空间、单文件大小和FD数用rlimit，只有目标exec前应用。CPU soft=N/hard=N+1，按内核秒粒度触发。目标exec前恢复SIGPIPE默认处理；请求CPU seconds或file bytes时分别恢复SIGXCPU/SIGXFSZ默认处理，不继承这些信号的忽略设置。目标运行后仍可自行处理信号，CPU hard limit仍由内核实施。RLIMIT_NPROC不作为每任务PID配额替代；单文件FSIZE也不替代总磁盘预算。

## 文件系统与受管工作区

根挂载使用指定容量的tmpfs，默认64MiB。系统目录`/usr /bin /sbin /lib /lib64`存在时只读绑定；选择性提供CA、ld.so.cache、`/etc/alternatives`及生成passwd/group，不整体暴露宿主etc/home/run/sys。

根tmpfs上为tmp、home、run、workspace建立目录；dev只绑定必要的null/zero/random/urandom/full/tty，`/dev/shm`链接到`/tmp/shm`，避免另一个无界dev tmpfs绕过预算。只读运行时/input挂载的数据不计入命名写容量。memfd/SysV匿名内存另由memory控制器约束；磁盘预算不等于所有内核对象的总配额。

- `readwrite`：兼容的宿主workspace可写绑定。宿主内容立即变化，不能自动对任意目录设置精确总quota；请求disk-bytes被拒绝。
- `readonly`：宿主workspace只读，临时根仍有容量上限；disk-bytes可覆盖默认临时容量。
- `tmpfs`：宿主目录只读暴露在/input，可信init复制到根tmpfs的/workspace，所有命名临时写路径共享disk-bytes；初始内容超额会在启动前失败。

input copy与export逐目录FD遍历，不跟随目标symlink，不接受special节点；节点独占创建、剥离setuid/setgid，不保留owner/xattr/硬链接拓扑。65536节点、深度128及全树逻辑内容预算防止无限目录和巨大sparse文件导出稠密化。原地RW目录或授权的只读输入中已有hardlink/socket/子挂载仍属调用方授权，不能靠字符串规范化消除。

export只支持预先存在且为空、与input互不包含的宿主目录。父只给可信init一个预开目录FD；目标关闭它，PID1设non-dumpable，防止payload重开其procfs FD。主命令成功后先杀/回收所有其余后代，再从稳定workspace导出。失败可能留下之前完整复制的条目，不保证整树事务性；导出的symlink应作为不可信数据消费。

额外--mount-ro/--mount-rw合计最多32项，仅授权现有宿主目录，以O_PATH预开并通过bwrap --bind-fd/--ro-bind-fd绑定；可信init关闭保留的挂载句柄后才启动目标，目标不得覆盖默认管理布局或彼此重叠，来源拒绝控制文件系统及其子挂载；可写来源不得包含结果文件；只读/可写来源均不得与导出或cgroup控制目录重叠。额外rw与disk-bytes冲突，因为宿主写入不受根tmpfs预算约束。来源在启动期间须由调用方控制。授权来源和既有workspace一样可能包含Unix socket等IPC端点；依赖isolated出口约束时，调用方不得把其他网络代理、控制服务或可转交网络句柄的IPC入口暴露给目标。目录挂载校验不把这些已授权IPC自动变成受控代理流量。

## 网络策略

默认none使用独立netns，只有loopback、无宿主路由。isolated同样使用独立netns，必须提供合法allow规则；未给模式的旧allow调用推断isolated。显式none/host附带allow时报错。host不传--unshare-net，共享父环境netns，不创建代理；只读提供DNS/NSS配置，不承诺受控出口。isolated授权时可信init创建127.0.0.1:18080的TCP监听socket，通过启动前建立的私有SOCK_SEQPACKET控制通道以SCM_RIGHTS交给宿主proxy。监听socket保持沙箱netns身份，外部proxy直接accept；新建上游socket使用proxy所在的宿主netns。接收者校验消息与唯一监听FD、安装过滤器后确认；init关闭本地监听FD和控制FD6后才启动目标。无relay及文件系统Unix代理入口，目标不继承控制/监听FD。删除代理环境仍不能获得直连；各沙箱独立loopback和监听FD，不以密码认证隔离。详细交付和验证见[listener-fd-handoff.md](listener-fd-handoff.md)。

`--allow-host HOST`仅TCP443；`--allow HOST:PORT`授予精确DNS名与端口。拒绝IP字面量、legacy数字地址、通配符、后缀/URL。每次解析所有地址，混入一个非公网地址就拒绝；connect仅用已验证sockaddr，无二次解析，无失败直连回退。IPv4/IPv6特殊地址策略是固定实现，需要随新分配更新；可信宿主路由/NAT不得把公网地址重定向到未授权内网。

HTTP按absolute http URI生成origin-form，Host一致且无歧义framing，去除hop-by-hop/proxy认证字段，上游Connection:close，一连接一请求。CL或严格chunked正文最多64MiB，固定缓冲流转；拒绝Expect/Upgrade/trailer/extension等未支持语义。辅助上传者与连接worker并发处理早期响应，不因未发完请求体吞掉413。CONNECT要求明确端点，SOCKS5仅NOAUTH+DOMAIN CONNECT；成功后双向原始TCP隧道支持背压和半关闭，不检查TLS/SNI/证书/内容。

proxy最多32连接worker，HTTP每连接可额外一个uploader，pids预算需覆盖这些开销。头缓冲8192字节/128字段，头10秒、DNS/建立阶段20秒、单地址连接10秒、空闲30秒、阶段寿命300秒；过载/超时关闭。更详细协议边界见[network-design-notes.md](network-design-notes.md)。

## syscall、环境和FD

`strict`是默认：将兼容拒绝清单与native syscall允许清单组合；未列出的syscall拒绝。目标自定义--syscall按名称覆盖默认规则，同名最后一项生效；构造有效过滤器时去除对应默认无条件和参数限制，不能靠叠加ALLOW撤销已安装拒绝。`compat`仅显式选择，保留拒绝高风险入口但允许其他syscall。no_new_privs和坏ABI kill保持固定；未被用户同名覆盖的默认规则包含clone namespace参数过滤、clone3 ENOSYS回退、TIOCSTI/TIOCLINUX低32位过滤及HugeTLB分配入口拒绝。32位/兼容ABI不支持。

显式`--memory-bytes`不能与`mmap`、`mmap2`、`shmget`或`memfd_create`的最终有效`allow`覆盖组合使用：这会移除默认HugeTLB参数防护，使某些主机上未纳入memory.max计费的分配入口可达。校验按重复规则的最后一项判断，在启动前拒绝该组合；默认未覆盖这些syscall时仍保留原参数防护。

自定义规则可能阻断启动必需调用。可信init使用私有MAP_SHARED原子错误/尝试阶段状态报告执行准备失败，避免依赖目标已被deny/kill的write来传递错误；父分支检查状态并在失败时终止、回收子进程。显式禁止execve等造成的启动失败报告`setup_error`、`command_started=false`，不为错误报告另开write例外。启动握手仍不是内核exec事件跟踪，不能证明所有异步死亡时序下都已发生exec；安全负例须另有目标执行标记。

目标分支独立安装其strict/compat及用户覆盖后的完整过滤器；可信init在分叉后的父分支安装固定兼容过滤器执行回收与导出，避免目标提前继承无法被用户ALLOW覆盖的拒绝。proxy使用独立过滤器禁止exec、新写open、文件修改及危险接口；保留只读NSS模块/配置和DNS所需NETLINK等。权限修改拒绝项包含fchmodat2；libseccomp名称库不识别该入口时，在两种受支持native ABI按UAPI编号452安装EPERM拒绝规则，不能因名称缺失漏过。

O_RDONLY自有文件FD仍可用于某些元数据修改ioctl，不能把只读open当成元数据不可变证明。transport因此整体拒绝ioctl syscall并返回EPERM，包括FS_IOC_SETFLAGS及高32位request别名，未更改目标strict/compat的ioctl规则。特定NSS模块若依赖ioctl而无法完成解析，连接失败时不放宽过滤或直连；只读模块加载能力不意味着所有NSS机制都兼容，须按实际配置验证。上述UAPI和元数据接口来源见[references.md](references.md)。这些可信C协议实现仍有内存安全边界；过滤器不解析connect指针，也不能代替端点校验。

宿主环境清空后只重建固定PATH/HOME/LANG/TMPDIR及代理变量。用户env作为argv传入init，直到目标过滤器安装后才setenv/exec，LD_PRELOAD不能提前注入可信初始化器。所有额外继承FD关闭；目标不持有guardian控制通道、状态通道、cgroup或export FD。可信进程设non-dumpable，防止仅禁ptrace仍留下的`/proc/PID/mem`和FD重开路径。

stdin经只读管道，目标stdout/stderr经固定有限缓冲回送，预算默认合计16MiB。父使用独立非阻塞FD处理pipe/tty，不能改变调用方原FD flags；背压不能阻断取消和期限检查，取消可能丢弃有限待写队列。

bwrap/可信init的stderr走独立diag pipe；目标stderr经内部私有FD5交给init，在目标分支dup2到FD2替换原诊断写端，然后关闭FD5。目标不持有可信diag写端，因此设施诊断不能消耗目标预算或误确认command_started。diag只转写前16KiB到调用方stderr，继续读取并丢弃超额，不因诊断超额触发output资源限制；supervisor本身的少量参数/设施错误诊断另计，不在这个16KiB总额内。目标stdout/stderr任一路被观察到均可辅助确认exec已开始。

## 生命周期与结果

公开run/doctor入口先暂时屏蔽信号，安装INT/TERM/HUP取消handler、CHLD默认处理（清SA_NOCLDWAIT）和PIPE忽略，再将继承的线程mask清空。顺序保证解除屏蔽的待处理取消信号进入管理handler；不将调用线程的屏蔽或SIGCHLD忽略状态带入可信回收链。SIGCHLD=SIG_IGN可跨exec保留，不能依赖exec隐式恢复。目标信号默认处理在exec前按上一节另设，目标之后仍可自行修改。

guardian先拥有临时目录和cgroup，再通过私有SCM_RIGHTS向父交付资源句柄。父中途退出时没有“已分配但无人持有清理责任”的正常窗口。注册子进程用pidfd固定身份，避免数值PID重用误杀；控制写端不能泄漏给payload，EOF才能可靠表示父死亡。

正常退出、取消、超时、启动失败、代理/guardian故障走同一回收路径。父确认清理成功才发送Q解除守护；启动中止或清理失败关闭通道，让guard继续回收。guard可用cgroup.kill、PID1/PDEATHSIG和pidfd终止注册进程，核验populated后移除叶和内部目录。停止守护有界等待，可恢复SIGSTOP的guard使其收尾；无法确认清理时cleanup_complete=false并报告设施错误。SIGKILL无法保证写JSON，清理依赖内核响应及活着的守护；不提供对宿主同UID攻击者的保证。

外部调用方的生命周期由`pidfd_open(caller_pid, 0)`监控，使用进程语义，不设PIDFD_THREAD。CLI自行检查该pidfd；guardian也保留它，并在调用进程真正终止后通过owner进程pidfd向CLI发送SIGTERM。不能用PR_SET_PDEATHSIG代替该监控：该接口依附于创建线程，Agent的短命工作线程退出时可能误取消仍由存活进程管理的任务。相关区别见[PR_SET_PDEATHSIG手册](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html)与[pidfd_open手册](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)。

PDEATHSIG仍用于由受控单线程管理的proxy/bwrap/init/worker等内部子树，fork后核对精确父PID。namespace PID1是自有non-dumpable init，退出使其后代终止，setsid不能脱离。CLI若作为容器PID1而看不到命名空间外父进程，不能声称监控了外部调用方；此时仍保留容器/PID1、内部子树和guardian的生命周期边界。内部init模式不是公共CLI，要求namespace PID1，不能在宿主直接调用其kill-all路径。

JSON保留schema1原字段并增加command_exit_code、limit_reason、cleanup_complete、output_bytes和资源配置/计数。resources.cgroup_enforced与rlimit请求/应用分开；未知峰值用available标记。memory OOM/pids事件、输出预算、CPU/文件信号用于触限分类；应用处理ENOSPC/ENOMEM等并返回成功时，不必然产生resource_limit状态。完整退出码契约见[usage.md](usage.md)。

## 验收门槛

安全负例必须先证明payload实际执行，设施启动失败单列BLOCKED。独立测试覆盖文件/FD/环境、配额事件、命名路径旁路、export稀疏/符号链接、严格策略与常用程序、stdin/output背压、调用方/执行器死亡、代理故障、DNS混合/失败、smuggling/慢头/worker饱和、4MiB双向半关闭与提前响应。解析器使用ASan/UBSan及可复现变异；测试链接fixture不把私网绕过开关引入正式CLI。

T1将三条公网功能正例的curl/CLI/Python等待预算调整为30/40/60秒，以免原curl 10秒预算在生产允许的20秒DNS/建立或10秒单地址连接阶段内提前截断。报告network_smoke记录预算及零自动重试；其他helper默认等待、负例和30项受控协议时限保持原样。公网连通功能检查不是10秒延迟SLA；本次没有修改生产拨号、过滤器或DNS/NSS实现，亦不据此认定全部旧超时根因。旧失败和后续诊断各按原执行输入保留。

Linux VM和Docker分别保存环境、源码/二进制摘要、每项结果及原始样本。默认容器阻断与显式支持配置分开，容器配额委派不得把任务移出其外层容器子树。持续测试保存requested/observed时长和每轮样本；承诺24小时就必须真实跑满。同源最终包、安装探测和远端双架构CI是交付门槛，具体是否完成以任务和验证记录为准。
