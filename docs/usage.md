# Enclio 使用指南与 CLI 契约

版本 `0.2.0-preview.1`，JSON `schema_version: 1`。当前版本在原字段上增加资源与清理信息；调用方应忽略未来新增字段，并按 `status` 区分业务结果和设施失败。平台条件见 [dependencies.md](dependencies.md)，委派步骤见 [deployment.md](deployment.md)，真实验收状态见 [validation.md](validation.md)。

## 安装与真实探测

Ubuntu 开发环境安装 `build-essential pkg-config libseccomp-dev bubblewrap ca-certificates curl python3`，执行 `make`。`make install PREFIX=$HOME/.local` 安装 `enclio`；`make package` 生成原生归档。运行 CLI 不需要 Python，解释器、编译器和目标程序的其他依赖应已存在于暴露的系统运行时。

```sh
enclio version
enclio help
enclio doctor
# 仅在管理员或服务管理器已提供委派父目录后：
enclio doctor --cgroup-parent "$CG_PARENT"
```

`doctor` 真正执行 bubblewrap、严格 seccomp、有界根文件系统及 `/bin/true`，而非只查文件是否存在。带 `--cgroup-parent` 时还实际请求 64 MiB 内存、64 个进程/线程和 100% CPU 配额。JSON 分开报告 `ready`、`strict_seccomp`、`bounded_tmpfs`、`cgroup_v2`、`cgroup_limits_probed` 与 `cleanup_complete`。只看到 `cgroup_v2: true` 不代表已获得委派；不带 parent 的基础探测成功也不代表所有配额或网络已验证。

## 公共命令与参数

```text
enclio run --workspace DIR [OPTIONS] -- COMMAND ARG...
enclio doctor [--cgroup-parent DIR]
enclio version
enclio help
```

| 参数 | 语义与默认值 |
|---|---|
| `--workspace DIR` | 必填的现有宿主目录，realpath 规范化；禁止 `/` |
| `--workspace-mode readwrite\|readonly\|tmpfs` | 默认 `readwrite`；三种语义见下节，无 `rw` 简写 |
| `--cwd /workspace/PATH` | 默认 `/workspace`；是沙箱内路径，可为其子目录 |
| `--timeout SECONDS` | 整数 1—86400，默认 300；单调时钟计算准备、执行及输出等待期限 |
| `--result FILE` | 可选宿主普通文件，必须在 workspace 和 export 目录之外；拒绝结果文件 symlink、多硬链接 |
| `--env NAME=VALUE` | 最多 64 项，只在目标安装过滤器后应用；值可以有空格和 `=` |
| `--seccomp strict\|compat` | 默认 `strict`；仅显式选择 `compat` 才使用兼容策略 |
| `--syscall NAME=ACTION` | 目标syscall覆盖项，可重复；动作`allow`、`deny`、`kill`、`errno:N`；相同syscall最后一项生效 |
| `--network none\|host\|isolated` | 无规则默认`none`；`isolated`必须有合法allow规则；显式`none`/`host`与allow规则冲突 |
| `--mount-ro SOURCE:DEST` | 将已有宿主目录额外只读绑定到沙箱绝对目录，可重复 |
| `--mount-rw SOURCE:DEST` | 额外可写目录绑定；不能与`--disk-bytes`组合，可重复 |
| `--allow-host HOST` | 授权精确 DNS 名的 TCP 443，不接受端口、URL、通配符或 IP 字面量 |
| `--allow HOST:PORT` | 授权精确 DNS 名与显式端口 1—65535；两类规则合计最多 64 项 |
| `--tmp-bytes N` | 共享临时根 tmpfs 的容量，默认 67108864；不包含宿主 readwrite 挂载 |
| `--disk-bytes N` | 仅用于 `readonly`/`tmpfs`，覆盖 `--tmp-bytes`；`tmpfs` 模式必须提供 |
| `--export EMPTY_DIR` | 仅用于 `tmpfs`，成功后导出至已存在的空宿主目录；输入/导出目录不得互相包含 |
| `--output-bytes N` | 目标 stdout 与 stderr 合计捕获预算，默认 16777216；超量终止任务 |
| `--cgroup-parent DIR` | 已正确委派的 cgroup v2 父目录；仅给此项也创建任务叶用于树级清理 |
| `--memory-bytes N` | 任务 cgroup 的 memory.max；同时设置 swap.max=0、oom.group=1 |
| `--pids-max N` | 任务 cgroup 的进程/线程数上限，包括可信辅助进程 |
| `--cpu-percent N` | cgroup CPU 带宽，1—10000；100 表示一个 CPU，不是整个机器的 100% |
| `--cpu-seconds N` | 每目标进程 CPU 时间 soft=N 秒、hard=N+1 秒，按内核秒级语义生效 |
| `--address-space-bytes N` | 每目标进程虚拟地址空间 hard limit；不等于 RSS 或进程树总内存 |
| `--file-bytes N` | 单文件增长/写入的大小hard limit；不截断已有大输入，不等于目录总空间 |
| `--open-files N` | 每目标进程的最大 FD 数；过低可能连程序加载都无法完成 |
| `-- COMMAND ARG...` | 必填；直接 exec，不隐式解析 shell；需要 shell 语法显式用 `/bin/sh -c` |

`--timeout`是触发终止的期限，不是承诺该秒数瞬间返回；后续有界回收会增加退出耗时，`duration_ms`包含整个过程。

所有数值参数都是正十进制整数，不接受 `64M` 等后缀。`memory-bytes`、`tmp-bytes`、`disk-bytes` 必须为当前系统 page size 的整数倍；典型 4 KiB 页环境可使用上表的 MiB 字节数。除固定禁用core dump外，未请求的CPU/内存/PID或rlimit不会被悄悄添加。请求任何聚合限制而缺少有效委派或控制器时，返回设施错误，不退化成逐进程限制。

## 网络、挂载与自定义syscall策略

新增配置的完整契约和已执行功能验证见[扩展记录](options-extension-20261111.md)。未显式指定`--network`且给出`--allow`/`--allow-host`时，为兼容既有调用推断`isolated`。显式`isolated`缺少合法规则即报错；显式`none`或`host`附带allow规则也报错。host共享当前父环境网络命名空间，Docker内仍是容器netns；不创建代理或自动代理环境，能直接访问的目标由外层网络政策决定。none和isolated保留独立netns，只有isolated提供受控TCP出口。

额外挂载合计最多32项，来源可用相对路径并realpath规范化，禁止根目录及路径中的冒号；目标须为无空段、`.`、`..`或结尾斜杠的绝对目录。来源预开O_PATH句柄，经bubblewrap的--bind-fd/--ro-bind-fd绑定；目标不继承这些句柄。拒绝覆盖默认管理目录、互相重叠；可写来源不得包含结果文件，只读/可写来源均不得与导出或cgroup控制目录重叠，来源不可携带危险控制文件系统。ro/rw是该挂载的权限，仍受宿主文件权限限制。额外rw目录写入不计入根tmpfs预算，不能与`--disk-bytes`组合。授权来源和既有workspace一样可能包含Unix socket等IPC端点；依赖isolated出口约束时，调用方不得把其他网络代理、控制服务或可转交网络句柄的IPC入口暴露给目标。目录挂载校验不把这些已授权IPC自动变成受控代理流量。

`--syscall`最多64项，按native syscall名称指定目标策略，用户项覆盖同一syscall的默认动作及参数过滤；未知名称/动作/errno应在启动前拒绝。`allow`不能解除外层seccomp已施加的拒绝，不改变capabilities。允许原先危险入口会放宽对应默认保护；拒绝execve等必需入口可能让目标无法启动。可信init及代理始终使用自己的固定策略，no_new_privs与非native ABI拒绝保持。

显式`--memory-bytes`不能与`mmap`、`mmap2`、`shmget`或`memfd_create`的最终有效`allow`覆盖组合使用：这会移除默认HugeTLB参数防护，使某些主机上未纳入memory.max计费的分配入口可达。校验按重复规则的最后一项判断，在启动前拒绝该组合；默认未覆盖这些syscall时仍保留原参数防护。

自定义规则阻断启动必需调用时可能得到`setup_error`。错误报告不放宽目标write策略；启动握手不是内核exec事件跟踪，不能证明所有异步死亡时序。显式阻止execve等启动失败保持`command_started=false`。

```sh
# 受控代理；至少授予一个合法域名/端口
enclio run --workspace /tmp/project --network isolated --allow example.com:443 -- /usr/bin/curl https://example.com
# 明确共享父环境网络，不启用域名白名单代理
enclio run --workspace /tmp/project --network host -- /bin/true
# 额外数据和宿主产物目录，调用方预先创建来源目录
enclio run --workspace /tmp/project --mount-ro /srv/data:/data --mount-rw /srv/output:/output -- /bin/true
# 覆盖目标默认允许的uname，让调用返回EPERM
enclio run --workspace /tmp/project --syscall uname=deny -- /bin/true
```

## 三种工作目录语义

| 模式 | `/workspace` | 宿主目录的变化 | 总容量保证 |
|---|---|---|---|
| `readwrite` | 直接可写绑定宿主目录 | 命令写入立即持久化 | 宿主目录无自动总 quota；`--disk-bytes` 被拒绝 |
| `readonly` | 直接只读绑定宿主目录 | 不经该挂载改变输入 | 临时根由 tmp/disk 字节数限制，输入只读挂载不计入写预算 |
| `tmpfs` | 从只读 `/input` 复制后得到的临时目录 | 输入不变；可显式成功导出 | workspace/tmp/home/shm 等命名可写路径共享根 tmpfs 预算 |

根 tmpfs 上只创建目录并绑定指定设备，不另挂无界 `/dev` tmpfs；`/dev/shm` 指向 `/tmp/shm`。`--disk-bytes` 约束该文件系统容量，不承诺所有匿名内核对象都落在其中。memfd/SysV 内存由 cgroup 内存控制器计费；需要同时控制这类分配时显式请求内存配额。

`tmpfs` 的初始复制、导出只接受普通文件、目录和符号链接，不追踪符号链接或复制特殊文件，不保留 owner、setuid/setgid、xattr 和硬链接拓扑。最多 65536 节点、深度 128；总逻辑内容不能超过所选文件系统容量，巨大稀疏文件会拒绝，不能经导出无限稠密化到宿主。输入本身超过容量会在执行前失败。

导出目标目录 FD 只由可信初始化器持有。主命令成功后，先终止并回收后台后代，再进行复制；业务失败、超时或取消不导出。目标条目独占创建，不覆盖已有文件或跟随目标 symlink。导出失败会报告设施错误，但之前完整复制的条目可能保留，因此不提供全树事务性。导出的符号链接仍是不可信数据，后续消费者不要自动跟随它访问其他宿主位置。

```sh
mkdir -p /tmp/input /tmp/export
enclio run --workspace /tmp/input --workspace-mode tmpfs \
  --disk-bytes 67108864 --export /tmp/export --result /tmp/job-result.json \
  -- /bin/sh -c 'echo ready > /workspace/result.txt'
```

`readwrite` 授权包含目录中已存在的硬链接、socket、子挂载及可读机密；输入目录必须由调用方审查。不要授权包含 Docker/SSH/D-Bus 控制 socket 的目录。宿主整个 home、run、sys、etc 不整体暴露；所需系统运行时和 `/etc/alternatives`、CA、加载配置是选择性只读绑定。

## 资源配额与输出

聚合限制覆盖 bwrap、可信 init、目标后代、宿主代理以及 HTTP 上传辅助进程。宿主 supervisor 和清理 guardian 留在该叶之外，以保留收集结果和清理能力；外层服务/容器仍应限制它们。一个目标请求可能需要多个辅助进程，不能将 `pids-max` 等同于目标能 fork 的数量。

```sh
# CG_PARENT 必须是已经启用所需控制器的空委派父目录。
enclio run --workspace /tmp/input --cgroup-parent "$CG_PARENT" \
  --memory-bytes 268435456 --pids-max 128 --cpu-percent 100 \
  --cpu-seconds 20 --address-space-bytes 536870912 \
  --file-bytes 8388608 --open-files 256 --output-bytes 1048576 \
  --result /tmp/job-result.json -- /usr/bin/python3 -c 'print("bounded")'
```

CPU 带宽允许持续节流，正常节流不自动等于业务失败。目标 exec 前将 SIGPIPE 恢复默认处理；请求 `--cpu-seconds` 或 `--file-bytes` 时，分别将 SIGXCPU、SIGXFSZ 恢复默认处理，避免继承调用方的忽略设置。目标程序运行后仍可自行安装信号处理或选择忽略。RLIMIT_CPU 的 soft 信号可由程序处理，继续运行到 hard 时被强制终止；地址空间、FD 数和单文件大小限制可表现为 syscall/库函数错误。命令若处理了 ENOSPC/ENOMEM/EMFILE 等并正常退出，不必然得到 `resource_limit`。是否设置上限、内核事件和业务状态应分别读取。

stdin 经只读管道中继，目标不直接继承调用方可写的终端或文件 FD0。目标 stdout/stderr 经固定缓冲、有界输出泵，慢消费者仍可超时或取消，不会无限缓存；取消/超时可丢弃有限的尚未输出队列。`output_bytes` 只记录已捕获并计入预算的目标字节，不保证消费者已经读到这么多字节。stdio 不接受 socket。

bwrap 与可信初始化器的 stderr 使用独立诊断管道，合计最多向调用方 stderr 转写 16384 字节（16 KiB），超额继续读取并丢弃；目标不持有该诊断写端。这些字节不计入 `output_bytes`，不触发 `--output-bytes` 超限。即使预算只有 1 字节，cwd/exec 等设施失败也不会仅因可信诊断而误报 `resource_limit/output`。supervisor 自身的少量参数/设施错误诊断另写 stderr，不属于上述 16 KiB 总额。最终 stderr 仍可能混有目标伪造的文本，应以 JSON 状态判断结果。

## TCP 网络

```sh
# HTTP，通常使用公网 80：
enclio run --workspace /tmp/input --allow example.com:80 \
  -- curl -fSs --max-time 10 http://example.com
# CONNECT，兼容的精确 HOST:443 授权：
enclio run --workspace /tmp/input --allow-host example.com \
  -- curl -fSs --max-time 10 https://example.com
# SOCKS5 域名在代理端解析；显式自定义端点可授权其他 TCP 端口：
enclio run --workspace /tmp/input --allow example.com:443 \
  -- curl --socks5-hostname 127.0.0.1:18080 -fSs https://example.com
```

isolated模式的三种协议共享本任务的 loopback 监听入口，由宿主代理通过交付的监听 FD 直接接受连接；沙箱内不运行 relay。启动器设置 HTTP_PROXY/HTTPS_PROXY 及小写形式为 `http://127.0.0.1:18080`，ALL_PROXY/all_proxy 为 `socks5h://127.0.0.1:18080`，并清空 NO_PROXY/no_proxy。显式 `--env` 可改变客户端选择，但不能扩大 netns 和宿主策略的授权。

规则不接受 IP 字面量、legacy 数字地址、通配符、后缀匹配或末尾点。每次连接检查全部 DNS 结果，任一非公网地址即拒绝；仅连接已经检查的 sockaddr。私网 API、公司内部 DNS 返回私网的服务会被拒绝。删除代理变量不会得到外部直连；重定向目标需要单独授权。

HTTP 是有意收紧的单请求代理：只接受 absolute `http://` URI，检查 Host 并转成 origin-form，上游强制 `Connection: close`，移除代理认证和 hop-by-hop 头。支持 Content-Length 与严格 chunked 请求体，最大 64 MiB；拒绝重复或冲突 framing、流水追加请求、Expect、Upgrade、chunk extension 和 trailer。支持上游提前响应，例如未等上传完成的 413；不承诺完全透明的 HTTP 兼容。CONNECT 和 SOCKS 建隧道后流转原始 TCP 字节，支持半关闭，不检查证书、TLS/SNI 或 URL。

SOCKS5 只支持 NOAUTH、CONNECT 和 DOMAIN 地址；IPv4/IPv6 地址类型、BIND、UDP ASSOCIATE 均拒绝。UDP、QUIC 和 TLS 解密不支持。

上限为 proxy 32 个连接 worker；每个 HTTP 连接最多再有 1 个上传辅助进程。头部缓冲 8192 字节、最多 128 字段，头接收约 10 秒、DNS/建立阶段约 20 秒、单地址连接约 10 秒、隧道空闲 30 秒、阶段寿命 300 秒；连接过载或超时关闭，无直连回退。

本指南示例中的 `curl --max-time 10` 是调用方选择的客户端期限，不是公网10秒内必定成功的延迟承诺。客户端期限可以先于代理允许的DNS/建立阶段结束；应按业务需要单独配置。

宿主 proxy 的独立过滤器对全部 ioctl 返回 EPERM，不只拒绝某些 request；这不改变目标命令自身的 strict/compat 策略。可读取 DNS/NSS 配置和模块不代表所有 NSS 实现均兼容。如果特定 NSS 模块依赖 ioctl 而无法完成解析，连接会被拒绝，不会放宽过滤器或直接联网；须在部署环境验证实际解析配置。

## JSON 结果和取消

以下仅展示常用字段，数值为结构示意；实际报告还包含完整资源计数及请求配置。

```json
{"schema_version":1,"status":"exited","exit_code":0,"command_exit_code":0,"signal":0,"duration_ms":20,"command_started":true,"limit_reason":"","cleanup_complete":true,"output_bytes":6,"resources":{"cgroup_enforced":false,"rlimits_requested":false,"rlimits_applied":false}}
```

| status / 退出码 | 含义 |
|---|---|
| `exited` / 业务结果 | 业务退出，含非零或信号终止；正常 `exit 143` 不等于 SIGTERM |
| `resource_limit` / 126 | 已观测到资源触限，`limit_reason` 可为 output/memory/pids/cpu/file/disk |
| `timeout` / 124 | 超过期限并进入清理 |
| `cancelled` / 128+signal | 接到 SIGINT/SIGTERM/SIGHUP，包括调用方死亡触发的取消 |
| `setup_error` / 125 | 设施、exec、导出或清理失败；可能发生在业务开始之后 |

参数错误为 2；结果打不开或写入失败也返回 125，可能没有完整 JSON。业务本身也能返回 124/125/126，因此不能只看退出数字。

- `command_exit_code` 保留可信 init 实际观察到的目标退出结果；未报告或被整体强制终止时为 -1。
- `command_started` 来自内部启动握手状态，或已观察到仅目标会写入的 stdout/stderr；可信诊断不会将它置为 true。该握手不是内核 exec 事件跟踪，不承诺覆盖所有异步死亡时序；它不证明某项业务操作已发生，安全负例还必须有 payload 执行标记。
- `signal` 记录实际观察到的目标终止信号或取消信号，未观察到时为 0。
- `cleanup_complete` 说明受管回收路径是否确认成功；false 必须作为设施问题处理。
- `resources.cgroup_enforced` 与兼容别名 `resources.enforced` 仅指 cgroup；`rlimits_requested/applied` 单列逐进程限制。未请求 cgroup 不等于未启用任何约束。
- `resources.limits` 记录请求的 memory_bytes/pids_max/cpu_percent/cpu_seconds/address_space_bytes/file_bytes/open_files。其零值表示未请求。
- 资源计数含 CPU usage/throttled 微秒、memory current/peak/max 事件、OOM kill、pids current/peak/max 事件。峰值接口缺少时看相应 `*_available`，不要把 0 当作已测峰值。

结果文件不与业务 stdout 混写，不承诺并发读取时原子可见，应等 CLI 退出后读取。stderr 前缀可以被业务伪造，信任判断应使用工作区之外的结果及实际退出状态。

`run`/`doctor` 在创建任务管理链前先安装 SIGINT/SIGTERM/SIGHUP 取消处理，将 SIGCHLD 恢复默认处理并清除 SA_NOCLDWAIT，将管理进程的 SIGPIPE 设为忽略，最后清空继承的线程信号 mask。因此，调用线程屏蔽取消信号或调用方忽略 SIGCHLD，不应使取消或正常 wait 回收失效。此初始化只改变新 CLI 进程及其管理链，不修改调用方进程。

SIGTERM可主动取消。CLI和guardian通过调用方的进程pidfd（flags=0）监控真正的调用进程退出，guardian经CLI的owner pidfd发送SIGTERM触发取消；启动CLI的临时工作线程结束不会仅因此取消任务。内部受控单线程子树仍使用PDEATHSIG，但不把其创建线程语义当作外部调用进程语义。CLI作为容器PID1、看不到命名空间外父进程时，不声称可以监控那个外部调用方；容器/PID1和内部守护边界仍适用。guardian 从创建临时目录/cgroup起拥有清理权，父 CLI SIGKILL 后仍由私有控制通道 EOF 触发清理。正常完成只有在父确认清理成功后解除守护；启动中止和未确认清理走回收路径。SIGKILL 不能保证生成结果 JSON，清理仍依赖内核响应及守护存活。当前版本不提供脱离调用方的后台任务模式。

## 测试与来源

`make unit`运行代理、资源和transport过滤单测，`make test`运行基础集成；`make fuzz-smoke`在ASan/UBSan下做25万次可复现解析器变异，`make network-test`运行独立受控协议场景。实际入口以Makefile为准；`scripts/validate-linux.sh` 运行环境记录、单测、baseline、独立资源和受控协议检查，`ENCLIO_CGROUP_PARENT`可传入已委派父目录；未提供时只运行资源非聚合场景及缺委派拒绝检查，不能当作聚合限制的正向覆盖。`scripts/soak.py` 默认真实 86400 秒，支持另选时长用于自测，报告保留 requested/observed duration，不把短时运行当成24小时验收。具体委派、Docker状态和复现见 [deployment.md](deployment.md) 与 [validation.md](validation.md)。

T1只调整 `tests/integration.py --network` 的三条公网功能正例（HTTPS CONNECT、HTTP显式端口、SOCKS5域名TCP）：curl总期限从10秒改为30秒、CLI从15秒改为40秒、Python对子进程的等待从15秒改为60秒。报告的 `network_smoke` 记录是否启用、这三层预算及 `automatic_retries: 0`。其他run helper的Python默认等待仍为15秒，所有负例、30项受控网络的生产时限、代理过滤与实际拨号逻辑均未改变。

生产DNS/建立阶段允许20秒、单地址连接允许10秒，原公网客户端预算可能在这些合规阶段内提前截断。因此公网功能检查采用独立预算，不能用它宣称10秒延迟SLA。旧a505公网超时和后续成功诊断均保留；T1不等于已定位全部原失败根因、修复生产拨号或排除所有NSS回归。完整通过状态须按新的执行输入分别验证，不能改写旧结果。
