# 网络模式、额外挂载和目标 seccomp 扩展

> 公开资料说明：本页验证记录中的证据链接现指向脱敏阶段摘要。机器原始日志、JSON、命令和归档已移出公开工作树并私下保留；历史段落中提及的原始文件不随仓库发布，旧原始校验值不适用于摘要。结果与失败状态未因此改变。

日期：2026-11-11。依据用户本次要求增加显式网络模式、授权目录挂载、按 syscall 覆盖目标策略，以及公网地址过滤注释。当前新增行为已完成功能自验证，独立原始数据复核进行中；最终实际HEAD的CI另行核对。之前的300c监听FD改造结果按其原身份保留；长稳和自动检查继续暂停。

## 分工与实施顺序

| 步骤 | 负责 | 交付与门槛 |
|---|---|---|
| 1 契约与集成 | root | CLI校验、网络/挂载配置、内部参数传递；拒绝组合歧义和静默降级 |
| 2 目标seccomp | seccomp_override | 解析syscall及动作，生成用户优先的有效规则，独立单元检查 |
| 3 文档与地址注释 | options_docs | 更新使用/设计/依赖/状态；只给代理地址分类加注释，不修改其判定 |
| 4 独立检视 | options_review | 检视权限、句柄、初始化过滤继承、挂载重叠与错误路径；root逐项确认并记录修改结论 |
| 5 自验证 | root执行，独立Agent复核 | 新输入在Linux VM及获批委派Docker分别验证；每个拒绝用例证明目标或解析路径实际执行，保留真实政策/源码/二进制和原始失败 |
| 6 提交与CI | root | 仅amend，保持原9提交/合并父和分支；核对最终实际HEAD双架构CI，不替代本地完整Docker |

## 三种网络模式

| `--network` | 网络命名空间和出口 | 规则与环境 |
|---|---|---|
| `none` | 独立netns，只有本地loopback，无外部IP路由 | 不启动代理；与`--allow`/`--allow-host`同时出现时报错 |
| `isolated` | 独立netns，通过监听FD交付给外部代理实现受控TCP出口 | 至少一条合法`--allow`或`--allow-host`，否则报错；设置HTTP/SOCKS代理环境 |
| `host` | 共享启动Enclio时所在的网络命名空间 | 不启动受控代理，不自动设置代理环境，与allow规则同时出现时报错；不提供域名/端口出口授权保证 |

不传网络模式且没有allow规则时默认`none`。为保留现有CLI调用，未显式给模式但给了allow规则时推断为`isolated`；显式模式优先参与组合校验，不能悄悄忽略规则。host指直接父环境的netns：Docker内是该容器的netns，不等于物理宿主网络。host模式将存在且可读取的`/etc/resolv.conf`、`/etc/hosts`和`/etc/nsswitch.conf`只读提供给目标；仍保留文件、进程、capability与默认seccomp限制。代理的UDP/QUIC限制只适用于isolated受控通路，host模式的直接网络能力由共享netns、外层网络政策和有效seccomp共同决定。

isolated继续使用精确DNS名/端口和全部解析地址检查，无直接联网回退；不增加允许私网目标的代理开关。监听FD仍只经可信私有控制通道交付，不泄漏给工具。

## 额外目录挂载

重复使用`--mount-ro SOURCE:DEST`或`--mount-rw SOURCE:DEST`。SOURCE为宿主已有目录（可用相对路径，realpath规范化，禁止根目录），DEST为沙箱内规范绝对路径；两路径以单个冒号分隔，不支持路径内冒号。总计最多32项，DEST不接受空段、`.`、`..`或结尾斜杠；权限表示该绑定挂载的只读/可写属性，不是Unix文件mode设置。原文件owner/mode/ACL仍生效，rw不会自动授予宿主用户原来没有的权限。

校验拒绝：危险的proc/sys/cgroup/device等控制文件系统及子挂载；覆盖/包围默认管理目录；额外挂载彼此的父子路径重叠；可写来源包含结果文件，或只读/可写来源与导出或cgroup控制目录重叠。受保护的默认布局包括`/usr /bin /sbin /lib /lib64 /etc /proc /sys /dev /.enclio /workspace /input /tmp /home /run`，根`/`也不可作为额外目标。来源使用O_PATH目录句柄预先打开，再以bubblewrap的--ro-bind-fd/--bind-fd挂载，不回退到来源字符串重新查找。可信init在启动目标前关闭额外挂载FD，目标不继承这些句柄。调用方仍需控制授权来源及其父路径，防止启动期间替换或改动。额外挂载不扩大--cwd的取值范围，它仍限于/workspace及其子目录。

`--mount-rw`的宿主写入不受临时根tmpfs容量约束，因此与`--disk-bytes`组合时报错；不能把临时文件系统预算说成额外挂载的宿主目录quota。只读挂载不代表同一宿主文件从其他可写授权别名也不可修改。将敏感宿主目录明确挂入目标即授权目标访问其内容。授权来源和既有workspace一样可能包含Unix socket等IPC端点；依赖isolated出口约束时，调用方不得把其他网络代理、控制服务或可转交网络句柄的IPC入口暴露给目标。目录挂载校验不把这些已授权IPC自动变成受控代理流量。

## 自定义目标seccomp

最多64项，重复使用`--syscall NAME=allow|deny|kill|errno:N`，按本机native ABI解析名称；未知/不适用syscall、非法动作和errno值应在启动前拒绝。同一个syscall重复指定时最后一项生效。

| 动作 | 目标系统调用效果 |
|---|---|
| `allow` | 允许该syscall，不再应用本项目对它的默认拒绝和参数条件 |
| `deny` | 返回EPERM |
| `kill` | 终止调用进程（KILL_PROCESS） |
| `errno:N` | 返回指定的合法Linux errno值 |

用户规则只覆盖目标程序策略，不改可信init、proxy或guardian的策略。strict模式中用户allow可加入默认allowlist之外的native syscall；用户deny可覆盖默认允许项，亦可覆盖clone3默认ENOSYS等特殊动作。参数过滤与无条件规则必须按最终有效动作构造，不能先加载默认拒绝后再尝试用ALLOW撤销：seccomp过滤器叠加只能收紧。目标应从没有继承默认拒绝过滤的分支安装其完整有效策略；可信init在独立分支安装自己的固定策略。

no_new_privs和非native ABI拒绝是固定执行约束。用户允许mount/unshare/socket等原先受限入口会主动放宽相应内核攻击面或参数限制，默认威胁模型中的该项承诺随有效策略改变；不会因此获得Linux capabilities或外层容器未提供的权限。外层seccomp已经拒绝的调用无法由Enclio的allow重新放开。拒绝execve/read/write/exit等启动必需调用也可能使加载或工具执行失败，CLI按实际启动/信号状态报告。

显式`--memory-bytes`不能与`mmap`、`mmap2`、`shmget`或`memfd_create`的最终有效`allow`覆盖组合使用：这会移除默认HugeTLB参数防护，使某些主机上未纳入memory.max计费的分配入口可达。校验按重复规则的最后一项判断，在启动前拒绝该组合；默认未覆盖这些syscall时仍保留原参数防护。

自定义规则可能阻断启动必需调用。可信init使用私有MAP_SHARED原子错误/尝试阶段状态报告执行准备失败，避免依赖目标已被deny/kill的write来传递错误；父分支检查状态并在失败时终止、回收子进程。显式禁止execve等造成的启动失败报告`setup_error`、`command_started=false`，不为错误报告另开write例外。启动握手仍不是内核exec事件跟踪，不能证明所有异步死亡时序下都已发生exec；安全负例须另有目标执行标记。

## 公网地址分类注释

`enclio_proxy_address_public`保留原判定行为，逐项说明IPv4的本网络、私网、共享地址、loopback、link-local、文档、基准、多播、保留及6to4地址范围；IPv6限于2000::/3并排除2001::/23、2001:db8::/32、2002::/16、3fff::/20。2001::/23及192.0.0/24是保守整段排除，其中也包含IANA标为可全局到达的例外。固定实现不是完整实时IANA表，也不保证被接受地址在部署网络上的实际可达性或路由去向。

分类来源：[IANA IPv4特殊用途注册表](https://www.iana.org/assignments/iana-ipv4-special-registry/)、[IANA IPv6特殊用途注册表](https://www.iana.org/assignments/iana-ipv6-special-registry/)。

## 自验证结果与审查处理

最终执行输入：`8d387e49acaaba8ce0e915840a437b0f5ad16c12a8ec2977e80e03498c264885`（38文件）。两环境分别在该最终输入的新目录完整执行一次，均无失败或BLOCKED；本轮并未恢复长稳。

| 环境 | 基础集成 | 资源集成 | 受控代理 | 新配置集成 | 单元 | ASan/UBSan |
|---|---|---|---|---|---|---|
| 本地Linux VM | 33 PASS | 36 PASS | 30 PASS | 75 PASS | 5组PASS | 250000次PASS |
| 获批委派Docker | 33 PASS | 36 PASS | 30 PASS | 75 PASS | 5组PASS | 250000次PASS |

每环境总计174 PASS、0 FAIL/BLOCKED，包含真实聚合资源约束。VM binary为`d4c22aadd954ed50e2146054c6112a8c95d511053bc5972c5f8f1b34582b7a5d`，Docker binary为`95df06d292617c320f10c9b02b0c2364532f1e351522fb4a006e081bdbc5377c`。源码、环境、实际容器政策、原件与修复前启动误分类记录已私下归档，公开结果见[阶段摘要](evidence/options-extension-20261111/README.md)。独立原始数据及实际二进制字节复核已通过；最终远端HEAD的双架构CI以该提交的workflow和产物核对为准。

验证覆盖三模式及非法组合、host共享netns和本地受控服务/localhost解析、none直连拒绝、isolated正反例；额外挂载ro/rw、非法路径/控制挂载/重叠/配额组合和目标FD清理；strict/compat自定义规则覆盖默认允许/拒绝/参数规则、重复最后生效、非法配置、真实错误码与信号，以及自定义规则引发的启动错误报告。原有功能、资源、受控代理回归也按最终身份重跑。

| 发现与检视意见 | root确认后的最终处理 |
|---|---|
| 目标若先继承可信init固定拒绝过滤，后续ALLOW无法覆盖 | 采纳；目标在自己的分支安装完整有效策略，可信init父分支独立安装固定策略，用户覆盖不进入代理/guardian |
| 自定义write=deny/kill可能阻断旧错误管道并误分类准备/exec失败 | root发现、reviewer同意；使用私有MAP_SHARED原子错误/尝试阶段状态，父分支检查并终止/回收错误子进程；不增加write例外；新增10项启动回归纳入75项验证；修复前观察保留 |
| 放开mmap/mmap2/shmget/memfd_create会移除默认HugeTLB参数限制，可能破坏显式memory.max承诺 | 采纳；拒绝memory-bytes与这四类syscall最终有效ALLOW覆盖的组合，按最后一项规则校验，并保留默认未覆盖的参数限制 |
| 挂载文档把结果、导出、cgroup限制一概表述为只读/可写均不可暴露 | 修正文案为可写来源不得包含结果文件；只读/可写来源均不得与导出或cgroup控制目录重叠，未扩大实现拒绝范围 |
| 把CLOEXEC/EOF握手写成对所有异步时序的成功exec证明 | 明确它不是内核exec事件跟踪；command_started不替代目标实际执行标记 |
| 额外授权目录可能含Unix socket等其他IPC出口 | 明确调用方不得暴露替代代理或控制服务来同时声称isolated出口保证；不把已授权IPC流量计为受控代理 |

开发批次的58项或后续有限检查只作为开发观察，未挪用为最终全量。当前174项结果对应修复后8d387e49输入，两环境各一次完整执行。之前300c、5517等历史结果保持原字节和原身份。

VM的外层768MiB/256进程/2CPU为原始systemd启动配置；退出后transient unit被回收，原始service-status默认属性不能当作运行时限额读回，详见证据索引。任务内实际聚合配额的读回与触限事件另由资源报告证明。

Docker继续使用用户此前批准的专用测试容器限定例外及自身cgroup委派，不扩大为特权容器或宿主全局策略修改。host模式在容器中验证的是容器netns共享；它不等于物理宿主网络。长稳与专属自动检查仍暂停，本轮功能完成不表示整体P07/P10或发布验收完成。
