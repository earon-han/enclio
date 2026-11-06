# Enclio 验证与复现

> 公开资料说明：本页验证记录中的证据链接现指向脱敏阶段摘要。机器原始日志、JSON、命令和归档已移出公开工作树并私下保留；历史段落中提及的原始文件不随仓库发布，旧原始校验值不适用于摘要。结果与失败状态未因此改变。

当前新增任务（北京2026-11-11）：[网络模式、额外挂载和目标seccomp扩展](options-extension-20261111.md)已完成功能自验证。最终执行输入`8d387e49acaaba8ce0e915840a437b0f5ad16c12a8ec2977e80e03498c264885`（38文件）在Linux VM与获批委派Docker各一次完成33基础+36资源+30受控代理+75新增配置检查，均174 PASS、0 FAIL/BLOCKED；各5组单元及250000次ASan/UBSan变异通过。原件已私下归档，公开结果见[本轮摘要](evidence/options-extension-20261111/README.md)；独立原始数据及实际二进制字节复核已通过，最终实际HEAD的CI以该提交workflow和产物核对为准。下文300c及更早结果保留其原身份。长稳与专属自动检查仍暂停，整体P07/P10未完成。

历史300c阶段（北京2026-11-11）：[监听FD交付改造](listener-fd-handoff.md)已完成源码检视和本地Linux VM/获批委派Docker各一次99项功能验证、四组单元及各250000次ASan/UBSan变异，最终输入`300c9564b349e8a8bbc9e71cbf514ec1be3267dd59c87f02a7caba11bc8f185f`（36文件）。[公开阶段摘要](evidence/listener-fd-20261111/README.md)保留先前设施失败和全部新结果。用户暂停长稳和专属自动检查的指令继续有效；最终交付P07/P10仍未完成。下文5517为历史阶段记录。

记录日期：2026-11-06—07（北京）；版本`0.2.0-preview.1`。R1/R2/R3a/R3b/R4及T1在806b阶段修复、双环境各99项功能检查通过并经reviewer复核。随后806b VM真实长稳在408轮自动失败，独立有限对照确认T2测试同步缺陷机制。当前T2冻结输入为`5517be35c091fb37a778b8a7cf79b7cdb246eb93f801527fd136398e4b8de584`（35文件），源码、双环境各一次99项、有限回归及原始证据均经root/reviewer最终核对，T2已关闭（功能验收），P08完成；历史5517长稳因采样空档失败，未通过，当前验收状态见[完成状态](completion-state.md)；最终交付仍未完成，旧时长不累计。

## 5517当前功能结果与身份

| 检查 | Linux VM | 委派Docker |
|---|---|---|
| 基础集成 | 33 PASS，0 FAIL/BLOCKED | 33 PASS，0 FAIL/BLOCKED |
| 资源/故障及新增回归 | 36 PASS，真实聚合配额 | 36 PASS，真实聚合配额 |
| 生产时限受控网络 | 30 PASS | 30 PASS |
| 单元 | 代理、资源、代理过滤3组通过 | 同3组通过 |
| ASan/UBSan解析fuzz | 250000次通过 | 250000次通过 |
| 启动重复/并发 | 100次、4×3均通过 | 100次、4×3均通过 |
| 806b的86400秒 | 第408轮自动失败，complete=false | 为T2复验主动中断，complete=false |
| 5517真实86400秒 | 历史5517长稳因采样空档失败，未通过 | 历史5517长稳因采样空档失败，未通过 |

5517两环境JSON、日志、环境和实际容器配置原件已私下归档，公开结果见[阶段摘要](evidence/worker-sync-5517-20261107/README.md)；资源报告均`aggregate_cases_requested=true`，网络均`production_timing=true`。网络fixture使用测试专用链接包装器，生产无私网测试开关。

5517 VM binary SHA256：`aca6592378291ee0f37b8532881a8b938efbbcbcef76d11b7dc168e7c951be64`；Docker：`78a5729ddb85861b93a51deff7a673059ae41ed6edf77752966c05d1d5fdfd72`。源码相同，调试构建路径不同。转运副本无Git时字段如实为null，不伪填提交。T2只修改受控网络测试同步，测试身份已改变且已独立重新验证；源身份前后均为5517，最终CI和包仍须核对最终HEAD及该输入，不能沿用旧状态。

## 审查复现与修复验收

完整逐项裁决、讨论和排除项见[审查台账](code-review-20261106.md)。806b之前的生产修复有真实PoC及新增7个CLI回归，以下为当时两环境通过记录：

- 继承屏蔽TERM/CHLD/ALRM仍能及时取消，约21ms返回143，cleanup_complete=true；SIGCHLD=IGN不再破坏退出码和wait回收。
- 显式CPU/file请求的目标恢复默认XCPU/XFSZ，继承的忽略策略不再污染默认触限行为；目标自身仍可设置处理。
- fchmodat2及只读FD ioctl可修改宿主自有文件metadata，分别补拒绝及transport整体禁ioctl；单测验证EPERM、mode/flags不变、旧名称库及高位别名。
- 极小目标输出预算下，exec/cwd失败仍为setup_error125、started=false、command_exit=-1、output_bytes=0，可信诊断完整转写。
- stderr-only超量每环境10次均以独立文件marker证明实际执行、started=true、126/output、预算1字节且清理完成。

socket stdio阻塞猜测经main前置拒绝及独立探针反证关闭，未当作漏洞修复。随后T2确认的是测试同步缺陷，不能据有限对照宣称已还原历史第408轮时序或确认生产缺陷；这些审查不是外部人工安全审计或漏洞不存在的保证。

## 环境与授权范围

5517本地Lima VM为Ubuntu24.04 ARM64、Linux`6.8.0-147-generic`、普通UID501；Docker为Ubuntu24.04 ARM64、UID/GID1000。精确工具/内核版本的environment.txt原件已私下归档。容器镜像`sha256:ccfbd109c0f8287035ed5b9a28d49aa26cabf195e615de0fc51361c26923b475`，inspect/delegation/namespace保留实际策略。inspect的OOMKilled=true与服务/容器退出0均原样保留；测试包含嵌套OOM，不能仅由该标志或退出0断言外层OOM未发生，也不据此归因事件。macOS只作协调。

用户明确批准的[测试配置例外](deployment-validation-review.md)仅限专用本地VM一次性验证容器：cap-drop ALL、仓库seccomp、容器级AppArmor/proc遮罩例外、外层768MiB/256进程/2CPU，无privileged/SYS_ADMIN。管理员只委派容器自身子树，private cgroup namespace新挂载的根不能访问宿主祖先；任务不迁出外层配额。没有修改全局sysctl、LSM、Docker daemon或防火墙。

806b阶段镜像的默认Docker诊断为doctor125/ready=false/setup_error，属于嵌套启动BLOCKED，保留于`final-budget/docker-default`。不能当作payload已运行后的安全拒绝通过，也不替代完整受支持配置验证。外部依赖与安全策略详见[dependencies.md](dependencies.md)。

## 覆盖边界与长稳

基础覆盖文件/路径/FD/env、proc可信内存/控制通道、strict/compat/替代ABI、Python线程/编译器/Git、异常退出/取消/调用方死亡/创建线程退出/后代与guardian故障、memory OOM/PID/CPU真实事件、rlimit、输出/输入背压、共享临时容量/导出/稀疏文件。真实公网HTTP80、CONNECT443及SOCKS与受控DNS/私网/混合/重绑定/无回退、framing/smuggling/body/early413/100、4MiB双工半关闭、worker饱和恢复和真实慢头时限均覆盖。

安全负例须有PROBE_EXECUTED及command_started证明；输出预算只有1字节的新增stderr测试改用独立workspace文件marker。目标未执行单列BLOCKED；参数拒绝和设施预期失败不冒充攻击测试。

旧CBD两环境曾各92项短期通过，但24h在2026-11-06 VM UTC14:31:19主动中断。各summary为约4080秒/136轮/544任务/1020网络、0失败、interrupted=true、complete=false；原样无损归档，不用于修复版验收。

806b的两路长稳均已结束，具体失败/中断记录见下一节。5517双环境全量已通过最终核对，随后长稳因覆盖不足结束；验收现已暂停，见[完成状态](completion-state.md)，旧时长不复用。每组必须observed≥86400、rounds≥2592、max_round_gap≤120、failures=0、未中断、complete/coverage_sufficient=true且source/binary一致。每30秒4并发混合配额任务，每4轮完整30项网络；实际结束前不标长期通过。

## T2：806b长稳失败与测试同步修复

806b VM在12225.017秒、408轮后自动失败停止：1632混合任务全部通过，102套受控网络共3060检查为3059 PASS/1 FAIL。唯一失败是network-408的worker_limit_and_recovery TimeoutError；summary为failures=1、interrupted=false、coverage_sufficient=false、complete=false。服务MainPID=0、Result=exit-code、status1，非人工中断。完整JSONL、102份网络报告、summary、服务/journal与身份校验原件已私下归档，公开结果见[失败摘要](evidence/soak-failure-806b-20261107/README.md)，原FAIL保持不变。

[独立同步对照](evidence/soak-failure-806b-20261107/diagnostic/README.md)严格只做三组、各一次、零断言重试：

| 条件 | 结果 |
|---|---|
| 无注入、旧逻辑baseline | PASS，拒绝额外连接并恢复 |
| 测试专用30ms worker关闭后退出延迟、旧逻辑 | FAIL，held连接重置、额外连接TimeoutError，恢复未执行 |
| 同一延迟fixture、NOAUTH握手与reap屏障 | PASS，确认32个存活worker/连接后拒绝额外连接并恢复 |

对照证明注入条件下的同步缺陷，不能反推历史第408轮的精确时序或抹去长稳失败。root/reviewer同意T2最小改动：饱和前/关闭后最多2秒等待实际worker被回收，生产模式总计2秒内完成32次SOCKS NOAUTH握手并核对worker及held连接状态，记录阶段/时长/子进程和失败前状态。生产C、32-worker上限、10秒头期限、额外连接1秒接收期限未改，断言不重试；额外连接及恢复请求仍各一次。新输入5517已冻结，完整双平台和有限实际补丁回归经原始证据最终核对通过；5517长稳随后因覆盖不足结束，验收现已暂停，不能标记为24h通过。

806b Docker因T2确认后由root核验身份并正常SIGTERM中断，非自然失败；[结束摘要](evidence/soak-superseded-806b-docker-20261107/README.md)记录14492.454秒/483轮/1932混合任务/120套网络3600检查全部通过，failures=0、interrupted=true、complete=false。service的failed/exit1是主动中断预期，不能当成VM那次真实失败，也不构成24h通过。

## 5517复验与设施重跑边界（最终核对通过）

VM、获批委派Docker各一次完整套件退出0、各99 PASS及0 FAIL/BLOCKED，两者真aggregate、3组单元及各250000次fuzz通过。root/reviewer已逐SHA、AST、注入事件及所有原始报告完成最终核对，T2功能闭环、P08完成；P07/P10继续。实际补丁的有限验证范围如下，不能把quick或两项故障注入扩大成完整生产套件：

| 验证 | 实际执行范围与结果 |
|---|---|
| A普通模式 | 完整30项网络suite，一次30 PASS |
| B quick模式 | 完整30项压缩时限suite，一次30 PASS，不作生产时限证据 |
| C/D首次故障注入 | fixture编译阶段设施失败，无断言执行、无测试JSON，原错误保留 |
| C2普通/D2 quick | 各一次有限2/2 PASS：前置positive HTTP及与实际补丁AST一致的worker_limit；不是完整30项suite |

故障注入C/D首次在fixture编译阶段因外部wrapper argv0=cc导致cc1无法定位而设施失败，未执行断言；原始错误保留。经仅修wrapper argv0绝对路径、print-prog-name对照后，root另批独立目录C2/D2各一次，冻结输入、注入和时限不变；C2/D2各确认32/4个存活worker和held连接，30ms退出延迟事件存在、额外连接及恢复各一次；相关wrapper差异、编译器对照、注入事件和原始结果已核对。5517长稳随后因覆盖不足结束，验收现已暂停，状态见完成状态页。这是明确记录的设施修正及获批再执行，不得称整个过程零设施重跑，不与断言不重试混淆。

## 复现与CI

```sh
sudo apt-get install -y build-essential pkg-config libseccomp-dev bubblewrap python3 curl git ca-certificates
scripts/validate-linux.sh
# 完整聚合资源在专属委派服务中设置ENCLIO_CGROUP_PARENT，见部署指南。
# 仅本轮已批准的专用Linux测试VM：
sudo scripts/validate-delegated-docker.sh
```

[部署指南](deployment.md)给出委派、容器和长稳步骤。公网正例需可访问example.com的80/443，不删正例后声称完整通过。

[Linux workflow](https://github.com/earon-han/enclio/actions/workflows/linux.yml)配置原生AMD64/ARM64 VM、Docker、fuzz和打包。VM普通runner专属委派service真实测聚合配额；远端Docker没有委派时aggregate=false，不替代本地完整容器检查。CI scoped bwrap AppArmor profile记录加载卸载，保持全局sysctl原值。最终必需CI应匹配修复版amend HEAD，旧CBD或a199绿色状态不覆盖本轮修改。

## 公网正例预算与历史失败

T1及5517输入沿用的测试契约仅对三个公网连通性正例采用curl30/CLI40/harness60秒、无自动重试；默认helper、安全负例及30项受控网络的生产协议期限均未改。原因是代理DNS/建立阶段允许20秒、单候选10秒，旧正例curl10/CLI15/harness15可能在合规阶段内截断。该正例检查功能连通性，不给公网10秒SLA。

a505三轮完整VM各98/98/97 PASS，对应1/1/2个公网超时，全部保留于[阶段记录](evidence/code-review-ioctl-20261106/final/README.md)。后续有限诊断成功与新预算成功不能定位其全部原失败原因，也不证明任意NSS兼容或生产拨号缺陷已修。T1按独立reviewer确认的预算契约问题修复，806b每环境完整执行1次99项通过。其后长稳失败/主动中断均如上保留；T2新输入的独立功能复验已通过，仍须重新满足24h；服务与metadata见续接状态。
