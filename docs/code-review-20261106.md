# 2026-11-06 独立代码审查与修复台账

> 公开资料说明：本页验证记录中的证据链接现指向脱敏阶段摘要。机器原始日志、JSON、命令和归档已移出公开工作树并私下保留；历史段落中提及的原始文件不随仓库发布，旧原始校验值不适用于摘要。结果与失败状态未因此改变。

当前更新（北京2026-11-11）：[监听FD交付改造](listener-fd-handoff.md)已完成源码检视和本地Linux VM/获批委派Docker各一次99项功能验证、四组单元及各250000次ASan/UBSan变异，最终输入`300c9564b349e8a8bbc9e71cbf514ec1be3267dd59c87f02a7caba11bc8f185f`（36文件）。[公开阶段摘要](evidence/listener-fd-20261111/README.md)保留先前设施失败和全部新结果。用户暂停长稳和专属自动检查的指令继续有效；最终交付P07/P10仍未完成。下文5517为历史阶段记录。

审查基线为`27e1ccee`、执行输入CBD。R1/R2/R3a/R3b/R4五个代码问题及T1测试预算问题在806b阶段完成修复、双环境功能验证及reviewer复核。随后806b的VM长稳真实失败，引出T2测试同步缺陷。当前冻结输入为`5517be35c091fb37a778b8a7cf79b7cdb246eb93f801527fd136398e4b8de584`（35文件）。root/reviewer已逐SHA、AST、注入事件及原始数据完成最终复核：新输入双环境各一次99项通过，T2已关闭（功能验收）。历史5517长稳因采样空档失败，未通过，当前验收状态见[完成状态](completion-state.md)；最终CI和封装仍单列，不能沿用806b历史时长。

## 分工

code_review独立审查执行器、资源、清理、I/O及目标过滤，proxy_review子Agent检查网络协议/策略。root复核可触达路径、讨论裁决并修改C。review_validation及后续final_regression负责旧版复现、回归及真实VM/Docker执行，不修改C；budget_audit独立核对T1差异及原始结果，completion_docs同步文档。reviewer最终再次核对源码、原始报告、身份和校验和。

## 逐项裁决与修复

| ID | 发现、root确认及修改结论 | 验证与状态 |
|---|---|---|
| R1 / P2 | 继承调用线程signal mask使TERM取消失效。管理链先安装handler，再清空mask；目标仅在请求CPU/file限制时恢复对应默认信号 | 屏蔽TERM/CHLD/ALRM仍约21—22ms取消，资源信号回归通过；已关闭 |
| R2 / P2 | 继承SIGCHLD=SIG_IGN使正常命令退出也无法wait回收。显式设置CHLD默认并清SA_NOCLDWAIT | 真实marker、exit0、command_exit_code0、cleanup=true；已关闭 |
| R3a / P2 | 代理过滤遗漏fchmodat2。添加拒绝，支持ABI编号452兜底旧libseccomp名称库 | syscall为EPERM、mode不变，两个名称库分支均通过；已关闭 |
| R3b / P2 | 只读FD仍可用FS_IOC_SETFLAGS及高位别名修改宿主自有文件metadata。root提出关联疑点，reviewer实测确认，双方同意transport整体拒绝ioctl；目标策略不变 | 真实RO FD、原生/高32位setter拒绝、父读取flags不变，真实NSS/三协议正例通过；已关闭 |
| R4 / P2 | 初始化/exec诊断占用目标预算，使预算1字节时误报126/output。bwrap/init stderr走独立有界diag pipe，真实目标stderr经内部FD5传入后关闭；exec子只握手errno、init打印诊断 | exec/cwd失败为125/setup_error、output_bytes0且诊断完整；stderr-only各10次证明实际执行及预算1；已关闭 |
| T1 / 测试缺陷 | 代理DNS/建立阶段允许20秒、单候选10秒，公网正例却curl10/CLI15/Python15，可能在合规阶段内截断。仅三个公网正例改30/40/60，默认helper15及负例/受控时限不变 | AST逐项核对仅3个调用改变，报告记录预算/零重试；806b每环境仅1轮完整99项通过；已关闭 |
| T2 / 测试同步缺陷 | worker饱和测试未确认前一用例worker已reap，也未确认32个held连接均由存活worker受理。root/reviewer采纳NOAUTH握手、实际子进程/连接确认和有界reap屏障 | 三组有限对照确认同步缺陷机制；5517两环境各99项、3组单元及各250000次fuzz通过，实际补丁普通/quick及有限注入结果经最终复核；已关闭（功能验收），24h另验 |

SA_NOCLDWAIT是R2初始化时清除的状态，不把未经实测的exec继承行为另算缺陷。R3a/b是可信代理受攻陷后的第二层过滤缺口，不描述为已证实协议RCE、payload或内核逃逸。特定NSS若因被禁调用失败应拒绝连接，不声称任意NSS均兼容。

## 讨论与排除

- H1：root最初怀疑socket输出阻塞；reviewer指出main在创建资源前拒绝socket stdio，独立PoC约7ms返回125且未执行目标。root接受反证；usage已明确限制，无修改，不计已修复问题。
- R1/R2：采纳reviewer建议，仅重置管理所需disposition与mask，不重置所有无关ignored信号；目标仍可自行设置自己的资源信号处理。
- R4：仅提高setup_error优先级仍会误计output_bytes。讨论后选择独立diag pipe，保持FD3状态协议；诊断最多转写16KiB、超额继续消耗并丢弃，目标拿不到diag写端。
- R3b：没有因为97fb长稳及CI已通过而忽略同类入口；原始PoC恢复flags并删除自有文件。修复整体拒绝transport ioctl，避免枚举所有metadata request。
- H2：公网超时引出串行候选连接假设。一次host候选2秒未建立；后续10秒对照两个IP均在约1.2/3.2秒建立，filtered/unfiltered解析均10ms、同序成功。尚不足将历史超时归因于拨号或ioctl；未改生产拨号逻辑。
- T1：以可核查的预算契约不匹配修复测试，保留全部旧FAIL。新预算不是10秒延迟SLA，也不能证明旧失败全部根因已定位或所有NSS都无回归。reviewer建议Python60秒给CLI40后有界收尾留余量，root采纳。

## T2：长稳失败、有限对照与修复边界

806b的VM服务在第408轮自动失败停止，非人工中断：实际12225.017秒，1632个混合任务全部通过；102份受控网络报告共3060项，3059 PASS、1 FAIL。唯一失败为network-408的worker_limit_and_recovery，TimeoutError；summary为failures=1、interrupted=false、complete=false、coverage_sufficient=false。原始JSONL、全部网络报告、summary、服务/journal及身份校验已无损私下归档，公开结果见[失败摘要](evidence/soak-failure-806b-20261107/README.md)，旧FAIL不改写。

[独立有限对照](evidence/soak-failure-806b-20261107/diagnostic/README.md)只执行以下三组，各一次、零断言重试：

| 对照 | 结果与观察 |
|---|---|
| baseline、旧测试逻辑、无注入 | PASS，额外连接被拒绝并恢复 |
| 测试专用30ms worker关闭后退出延迟、旧逻辑 | FAIL，存在held连接重置和仅31个实际子进程；额外连接被受理后TimeoutError |
| 同一个延迟注入fixture、NOAUTH与reap屏障 | PASS，32次握手、32个存活held连接/子进程确认后，额外连接被拒绝并恢复 |

这些对照证明记录的注入条件下存在测试同步缺陷；它们不能回填历史第408轮的精确调度时序，也不单独证明生产缺陷或使旧长稳变成通过。诊断注入仅存在于独立fixture副本，不进入生产C。

root与code_review同意的T2只改tests/network_integration.py：填充前/关闭后最多2秒等待真实worker回收；生产模式在总计2秒内完成32次SOCKS NOAUTH握手，确认子进程数量及held连接仍存活后才测额外连接。保留生产32-worker上限、10秒头期限、额外连接1秒接收期限，断言不重试；额外连接、恢复请求各一次。失败记录阶段、时长、子进程与连接状态，不能用重新尝试掩盖失败。生产C、过滤器、拨号和协议时限均未修改。

806b的Docker长稳已由root核对原服务、容器、source/binary后正常SIGTERM中断，以便新输入复验；[结束证据](evidence/soak-superseded-806b-docker-20261107/README.md)记录14492.454秒、483轮、1932混合任务及120套网络3600检查全通过，failures=0、interrupted=true、complete=false。service的failed/exit1为主动中断预期，不是自然失败或24h通过。5517输入已完成全量双平台功能验收；完整新24h、最终CI和封装仍待实际结果。

## 5517最终功能验证（T2闭环）

[新输入公开摘要](evidence/worker-sync-5517-20261107/README.md)已归档并经root/reviewer逐SHA、AST、事件及原始报告复核。VM与获批委派Docker各完整执行一次并退出0，分别33基础+36资源+30生产时限受控网络=99 PASS、0 FAIL/BLOCKED；两者真实aggregate=true、3组单元及各250000次ASan/UBSan fuzz通过。实际补丁A普通模式、B quick模式各完整30 PASS；quick压缩时限不作为生产时限证据。T2已关闭（功能验收），不等于24h通过。

VM binary为`aca6592378291ee0f37b8532881a8b938efbbcbcef76d11b7dc168e7c951be64`；Docker binary为`78a5729ddb85861b93a51deff7a673059ae41ed6edf77752966c05d1d5fdfd72`，image为`sha256:ccfbd109c0f8287035ed5b9a28d49aa26cabf195e615de0fc51361c26923b475`。源身份前后均为5517。Docker inspect的OOMKilled=true与服务退出0均原样保留，不由此推断外层OOM未发生或其原因。

后续故障注入C/D首次尝试在fixture编译阶段因编译器wrapper的argv0为cc、找不到cc1而设施失败，没有执行测试断言，原失败保留。只修该外部wrapper的argv0为绝对编译器路径并以print-prog-name对照确认后，root批准在独立新目录各执行一次C2/D2；未修改冻结输入、注入、时限或断言。不能将这段过程称为“零设施重跑”，也不能将未执行断言的编译失败当成同步回归的通过或失败。C2/D2分别2/2 PASS，仅包含前置positive HTTP和与冻结补丁AST一致的worker_limit，不是完整30项suite；两者各一次额外连接拒绝、一次恢复。普通/quick分别确认32/4个存活held连接及子进程，30ms注入事件、阶段时限、原/修正wrapper与所有日志均保留并经最终复核。5517长稳随后因覆盖不足结束，验收现已暂停，状态见完成状态页。

## 806b阶段功能验证（历史通过）

冻结source：`806b059f336f976bb47764f1ad89e780abe180736d3c20da24c665137f913644`（35文件）。

| 环境 | 基础 | 资源/故障 | 受控网络 | 单元与fuzz |
|---|---:|---:|---:|---|
| 本地Linux VM | 33 PASS | 36 PASS，aggregate=true | 30 PASS，production_timing=true | 3组、ASan/UBSan250000次通过 |
| 获批委派Docker | 33 PASS | 36 PASS，aggregate=true | 30 PASS，production_timing=true | 同上 |

806b两环境各99 PASS、0 FAIL/BLOCKED，当时各完整运行1次、无自动重试。公网正例JSON明确curl30/CLI40/harness60。真实OOM、PID及CPU节流事件存在；100启动及4×3并发零失败。reviewer和budget_audit分别核对原始结果后同意关闭上述问题。

VM binary：`de50b79084c9abdfc4f441b3a140600607cd28c20f7b5fca5671c3a438567e9e`；Docker：`78a5729ddb85861b93a51deff7a673059ae41ed6edf77752966c05d1d5fdfd72`。原始身份、实际策略及校验和已私下归档，公开结果见[806b阶段摘要](evidence/code-review-ioctl-20261106/final-budget/README.md)。

## 阶段与剩余门槛

- CBD两套旧长稳在136轮/约4080秒主动中断，97fb两套在39轮/约1170秒主动中断；均0失败但interrupted=true、complete=false，不挪作新版本24h。
- a505三轮VM分别98/98/97 PASS，1/1/2个公网10秒超时，Docker99 PASS。全部失败、有限阶段诊断及不确定性原件已私下归档，结果与不确定性见[阶段摘要](evidence/code-review-ioctl-20261106/final/README.md)；没有删除或重写成PASS。
- 806b的VM长稳自动失败、Docker长稳为新输入复验而主动中断；两者均未通过24h。5517新输入双环境全量已通过最终核对，完整新24h及最终交付仍待验；5517长稳随后因覆盖不足结束，验收现已暂停，见[完成状态](completion-state.md)和[验证报告](validation.md)，旧时长不沿用。

生产修复位于main的signal初始化、FD转交与输出泵，internal的目标信号/exec握手，proxy的transport过滤；回归在resource_integration和transport_filter_unit，T1在integration，T2仅在network_integration测试同步。相关公开契约已同步使用、设计、依赖、安全及变更记录。

首轮R1/R2/R3a/R4旧版复现及97fb阶段证据另见[首次审查证据](evidence/code-review-20261106/README.md)。806b source与原始结果已由root、独立验证及reviewer分别核对；其99项只指当时单轮，不覆盖三轮a505旧失败、后续806b长稳失败或5517新输入。
