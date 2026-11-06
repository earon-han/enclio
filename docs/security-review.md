# 安全审查与验收边界

2026-11-11更新：CLI已改为私有监听FD交付，无relay或路径型代理挂载。新增交付消息/FD校验、CLOEXEC、ACK启动门槛及双沙箱互斥策略测试；独立检视及双环境各99项通过见[改造记录](listener-fd-handoff.md)。下文relay相关原始审查观察属于先前实现，历史证据保持原样。

日期：2026-11-06；版本`0.2.0-preview.1`。本文件记录实现分工之外的Agent审查发现、代码处理和需要的独立验证，不等同于外部人工渗透测试、安全认证或对所有内核的保证。最终双环境、持续运行和CI状态以[validation.md](validation.md)及原始证据为准。

## 本轮独立代码审查修复

逐项发现、复现、讨论裁决和复核责任见[code-review-20261106.md](code-review-20261106.md)。共五个具体代码问题，归入R1–R4四类；R3分为fchmodat2（R3a）与ioctl元数据修改（R3b）。以下记录实现契约；最终修复输入的双环境完整复验以[validation.md](validation.md)及原始证据为准，旧输入通过项不能直接沿用。

| 发现 | 实现处理与边界 | 独立验证要求 |
|---|---|---|
| R1：调用线程屏蔽TERM导致取消失效 | 先装INT/TERM/HUP handler、CHLD默认和PIPE忽略，再清线程mask | 屏蔽取消信号启动后实际取消，不能只等待timeout |
| R2：继承SIGCHLD=IGN破坏wait回收 | 显式CHLD默认并清SA_NOCLDWAIT；不依赖exec恢复忽略状态 | 继承IGN后业务成功、真实结果及cleanup均正确 |
| R3a：transport遗漏fchmodat2 | proxy/relay显式EPERM拒绝；旧libseccomp名称库在支持ABI按452补规则 | 原始syscall未过滤对照成功，过滤后EPERM且宿主模式不变 |
| R3b：只读FD仍能通过ioctl修改元数据 | transport整体拒绝ioctl syscall，包括FS_IOC_SETFLAGS及高位request别名；目标seccomp不变 | 普通UID/自有文件/O_RDONLY未过滤对照可修改，过滤后EPERM且flags未变 |
| R4：可信诊断耗尽微小目标输出预算 | bwrap/init诊断独立pipe，最多转写16KiB，超额丢弃；不计output_bytes或触发output超限 | 1字节预算下cwd/exec失败仍为设施失败，started=false；真实目标stderr仍计预算 |

R3a/R3b是可信代理受攻陷后的防御层缺口，不是已证实的协议RCE、payload逃逸或内核逃逸。R2中SA_NOCLDWAIT是初始化清理状态，不另行宣称其跨exec继承。目标exec前默认处理SIGPIPE；请求CPU/file限制时对应SIGXCPU/SIGXFSZ也恢复默认，程序之后仍可自行选择处理。R4的16KiB仅指新增诊断管道转写的总额，supervisor自身少量诊断另计。目标不继承可信诊断写端；成功exec握手或目标stdout/stderr观察可确认command_started，设施诊断不能确认它。

旧CBD执行输入的两路24小时测试已主动中断：各136轮、约4080秒、0失败，interrupted=true且complete=false。其后97fb执行输入的两路长稳也因R3b修复而主动中断并保留原始记录；这些均不构成24小时通过，不能作为最终修复输入的结果。最终输入须独立复验并重新满足完整长稳门槛。

### 另行修正的测试预算T1

T1是五个代码问题之外的测试预算问题。经root与独立reviewer讨论并按AST逐项核对，只有三条公网positive使用curl 30秒、CLI 40秒、Python等待60秒；原预算分别为10/15/15秒。报告network_smoke明确记录预算和零自动重试。其他helper默认15秒等待、全部负例、30项受控网络的生产时限、过滤和实际拨号逻辑不变。

生产DNS/建立允许20秒、单地址连接允许10秒，旧客户端10秒可能先行结束；项目未承诺公网10秒延迟SLA。这是调整功能检查预算的依据，不是全部旧失败根因的证明。旧a505公网timeout与后续成功诊断均保留，不据一次后续成功或预算调整排除全部NSS回归，不将其称作生产拨号修复。新执行输入的双平台结果仍按原始证据独立判定。

## 已保留的基础修正

| 边界 | 实现处理 | 验证要求 |
|---|---|---|
| 用户loader环境早于过滤注入可信init | env经参数传递，仅目标过滤器之后应用 | 真实LD_PRELOAD只在受限payload生效 |
| 同UID通过procfs访问可信内存/控制FD | init/proxy/relay/guardian设non-dumpable，关闭目标额外FD | 存在的PID1/relay内存及控制FD拒绝 |
| 额外未过滤bwrap PID1 | `--as-pid-1`，用自有可信init | PID1身份、procfs攻击及后代清理 |
| 目标ioctl高32位别名 | 目标TIOCSTI/TIOCLINUX按低32位MASKED_EQ拒绝；transport现整体拒绝ioctl | 普通和高位request实际执行后拒绝 |
| 信号与普通退出混淆 | 私有控制记录分开上报目标退出码/信号 | SIGTERM与普通exit143分别断言 |
| 内部子树父死亡设置竞态 | 对受控单线程父的fork记录PID，PDEATHSIG后精确核对 | CLI死亡与内部子树清理分别测试 |
| 结果可被工作区或导出覆盖 | 结果必须在两种宿主写授权目录之外，拒绝symlink/多硬链接 | 路径、符号链接父目录和hardlink负例 |
| legacy数字IP穿过DNS名语法 | AI_NUMERICHOST识别并拒绝数字变体 | 地址与host策略单测 |

## 本轮资源、I/O与清理审查

- 外部Agent可能从短命工作线程启动CLI。PR_SET_PDEATHSIG依附创建线程而非整个调用进程，不能用它判断Agent进程已结束。本轮改用flags=0的调用方进程pidfd，CLI/guardian监控其退出，guardian经owner pidfd发SIGTERM；内部受控单线程子树才保留PDEATHSIG。独立回归应分别覆盖“创建线程退出但进程存活不取消”和“调用进程真正退出会取消”，不能互相推断。容器PID1看不到命名空间外父进程时，不宣称能观察该外部进程生命周期。

- 聚合memory/pids/CPU只能由真实cgroup实现，模块校验控制器、读回配置和事件；缺委派不降级。proxy/relay/uploader与payload同叶，supervisor/guardian留在外层。Docker委派必须是容器自身子树，不能逃离外层配额。
- 单文件FSIZE与AS/CPU rlimit不等于总目录/进程树quota。磁盘预算采用共享有界根tmpfs，手工dev节点与`/dev/shm`链接避免额外无界挂载。memfd/SysV匿名内存另由memory计费；HugeTLB分配入口拒绝。
- export的source可能包含巨大的稀疏文件，单纯读取再写出会稠密化到宿主。复制/导出增加总逻辑字节、节点和深度预算，拒绝special与目标碰撞，不追踪symlink；导出前先终止/reap后台后代。失败不承诺整树回滚。
- 输出预算只计目标stdout/stderr。stdin改为只读pipe中继，不能把宿主可写tty/文件FD0直接授予payload，形成输出计数旁路。有限缓冲与非阻塞回送允许慢消费者下仍取消；不能改变调用方原FD flags。
- guardian从资源创建开始持有清理责任，以pidfd而非裸PID注册进程。Q只用于父已确认全部清理后的解除守护；启动中止、未接收资源句柄或父清理失败使用EOF回收，不能误解除责任。
- guardian停止是有界等待，stopped guardian可恢复并收尾。清理未确认必须cleanup_complete=false/设施失败，不能将失败隐藏成业务成功。内部init要求namespace PID1，避免直接宿主调用触发kill-all。
- strict允许清单与兼容拒绝清单求交，未知syscall默认拒绝；compat只能显式选择。常用shell/curl/Python线程/编译器/Git需要正向回归，坏ABI和危险入口需要负例。

这些处理必须结合真实资源事件、payload标记及残留检查验收，不以代码看起来正确代替执行结果。极低memory造成的启动失败与marker后OOM不同；command_started来自exec握手或目标stdout/stderr观察，不单独作为安全负例已运行的证据。

## 本轮网络审查

所有协议共用精确host:port与完整DNS地址检查，不能因HTTP/SOCKS解析路径不同而扩权。SOCKS DOMAIN必须独立验证，不能夹带authority端口。CONNECT/SOCKS隧道允许原始TCP字节；不对TLS/SNI/URL提供未实现承诺。

HTTP检查URI/Host、歧义framing、hop-by-hop提名、请求体上限和单请求语义，支持早期响应的并发上传回收。独立fixture应证明混合/私网DNS没有上游connect、连接失败无回退、流水请求不追加转发；测试半关闭、慢头、worker饱和恢复和多MiB双向流。fixture本身必须正确处理TCP半关闭与RST，不能修改生产代理掩盖夹具丢包。

代理/relay过滤器禁止exec、写open、元数据修改及全部ioctl，同时允许只读配置/模块和受限网络解析能力。这不是对全部DNS/NSS实现的兼容承诺；模块若依赖ioctl而不能完成解析，连接应失败，不放宽策略或直连。它仍有可信配置/模块与C内存安全边界；ASan/UBSan、可复现parser变异和独立协议测试降低风险，不构成漏洞不存在的证明。正式CLI没有allow-private环境变量或测试后门；测试链接wrapper只在fixture中使用。

## 完成门槛和未替代的保证

1. 本地Linux VM与Docker分别执行功能、拒绝、配额、故障、背压和清理；设施拒绝记BLOCKED，不抵消另一环境的失败。
2. 长稳保存真实requested/observed时长、源码/二进制摘要、每轮样本和残留；24小时未跑满不标完成。
3. 默认Docker策略诊断、限定容器例外和完整聚合委派分开记录；用户对一次测试环境的批准不成为生产通用授权。
4. 更广内核、SELinux、compat ABI或新syscall需明确支持矩阵。当前已测组合不能外推到任意Linux或“多租户完全隔离”。
5. 内核漏洞、同UID宿主攻击者、允许服务外传、授权目录机密/host socket、外部人工审计不由本轮软件功能代替。需要这些保证的服务仍应有外层VM/服务边界。

审查发现失效或新边界绕过，应阻断相应交付并保留复现。实际通过项及尚未达到的验收门槛由root在最终报告中更新，不在本文件预先写成已完成。
