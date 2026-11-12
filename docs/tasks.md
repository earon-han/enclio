# Enclio 实施台账

> 公开资料说明：本页验证记录中的证据链接现指向脱敏阶段摘要。机器原始日志、JSON、命令和归档已移出公开工作树并私下保留；历史段落中提及的原始文件不随仓库发布，旧原始校验值不适用于摘要。结果与失败状态未因此改变。

当前新增任务（北京2026-11-11）：[网络模式、额外挂载和目标seccomp扩展](options-extension-20261111.md)已完成功能自验证。最终执行输入`8d387e49acaaba8ce0e915840a437b0f5ad16c12a8ec2977e80e03498c264885`（38文件）在Linux VM与获批委派Docker各一次完成33基础+36资源+30受控代理+75新增配置检查，均174 PASS、0 FAIL/BLOCKED；各5组单元及250000次ASan/UBSan变异通过。原件已私下归档，公开结果见[本轮摘要](evidence/options-extension-20261111/README.md)；独立原始数据及实际二进制字节复核已通过，最终实际HEAD的CI以该提交workflow和产物核对为准。下文300c及更早结果保留其原身份。长稳与专属自动检查仍暂停，整体P07/P10未完成。

历史300c阶段（北京2026-11-11）：[监听FD交付改造](listener-fd-handoff.md)已完成源码检视和本地Linux VM/获批委派Docker各一次99项功能验证、四组单元及各250000次ASan/UBSan变异，最终输入`300c9564b349e8a8bbc9e71cbf514ec1be3267dd59c87f02a7caba11bc8f185f`（36文件）。[公开阶段摘要](evidence/listener-fd-20261111/README.md)保留先前设施失败和全部新结果。用户暂停长稳和专属自动检查的指令继续有效；最终交付P07/P10仍未完成。下文5517为历史阶段记录。

本轮版本`0.2.0-preview.1`，依据《实施计划.txt》及[功能完善计划](completion-plan.md)。五个代码问题及T1测试预算问题在806b阶段完成逐项裁决、修复、reviewer复核及VM/获批Docker各99项功能检查。随后806b的VM长稳自动失败；独立有限对照确认T2测试同步缺陷机制，root/reviewer采纳最小测试修复。当前5517输入已冻结并完成源码/原始数据最终复核，VM与获批Docker各一次99项通过，T2已关闭（功能验收）、P08完成。历史5517长稳因采样空档失败，未通过，当前验收状态见[完成状态](completion-state.md)；最终交付仍待完成，P07/P10继续进行。

## Agent职责

| Agent | 职责与交付 |
|---|---|
| root | 总体契约与集成、C实现、逐项裁决修复、文档及amend/push |
| resource_engine / network_engine | 资源、安全复制和TCP协议独立实现；集成后交叉复核 |
| independent_verification | 原完善阶段独立功能/故障/平台验证，原始证据与旧长稳 |
| code_review / proxy_review | 本轮独立只读代码审查及网络子审查；讨论反证、复核全部修复 |
| review_validation | 旧版真实PoC、独立回归、修复版双环境99项及新长稳；不改C实现 |
| final_regression / budget_audit | 806b双环境执行、预算AST审计、原始数据复核及同binary长稳；T2独立有限对照与后续新输入复验 |
| completion_docs | 设计/使用/依赖/安全文档同步和独立一致性核对 |

## 任务状态

| ID | 状态 | 交付及验收 |
|---|---|---|
| P00 | 完成 | C11、普通用户、CLI/JSON、威胁模型及TCP范围明确 |
| P01 | 完成 | 真实委派cgroup CPU/内存/PID聚合配额、事件和readback；rlimit真实范围明确 |
| P02 | 完成 | 共享有界root tmpfs、三种工作区、安全导出、无界RW quota拒绝 |
| P03 | 完成 | 合计目标输出预算、背压、只读stdin；本轮独立诊断通道修复R4 |
| P04 | 完成 | HTTP/CONNECT/自定义端口/SOCKS5 TCP，共用域名端口与全部DNS检查 |
| P05 | 完成 | 默认strict、显式compat、代理独立过滤；本轮补fchmodat2拒绝/旧库fallback及transport全拒ioctl |
| P06 | 完成 | guardian、pidfd及后代清理；本轮信号mask/CHLD回收语义修复 |
| P07 | 进行中 | 5517单元/fuzz/重复/并发及普通/quick、有限注入回归通过；旧806b VM408轮失败保留。新输入须独立重新跑满真实24h |
| P08 | 完成 | 5517两环境各33+36+30=99 PASS、0 FAIL/BLOCKED，真aggregate；3组单元、各250000次fuzz通过；A/B各30、C2/D2有限各2 PASS，root/reviewer已核对 |
| P09 | 完成 | 使用/设计/依赖/部署/安全及审查台账已同步，后续真实长稳与交付结果继续补充 |
| P10 | 进行中 | 等修复版最终HEAD双架构CI、同源安装包及最终验收 |

[代码审查台账](code-review-20261106.md)记录R1/R2/R3a/R3b/R4及T1已关闭、H1反证关闭，以及新增T2测试同步修复的功能闭环。T2三组对照不回填历史第408轮精确时序，不将原FAIL重写为PASS，也不替代24h或外部人工安全认证。UDP/QUIC、SOCKS BIND/UDP ASSOCIATE及TLS解密按确认范围不支持。

## 身份与证据

当前T2冻结输入SHA256：`5517be35c091fb37a778b8a7cf79b7cdb246eb93f801527fd136398e4b8de584`，35个执行/测试/构建文件；新双平台原始结果和binary证据已由root/reviewer完成核对，见[5517最终证据](evidence/worker-sync-5517-20261107/README.md)。VM binary为`aca6592378291ee0f37b8532881a8b938efbbcbcef76d11b7dc168e7c951be64`，Docker binary为`78a5729ddb85861b93a51deff7a673059ae41ed6edf77752966c05d1d5fdfd72`，image为`sha256:ccfbd109c0f8287035ed5b9a28d49aa26cabf195e615de0fc51361c26923b475`。T2只改测试同步，生产C、32-worker上限、10秒头期限、额外连接1秒接收期限不变，断言不重试。C/D曾在fixture编译阶段因wrapper argv0/cc1问题设施失败、无断言执行；原失败保留，仅修外部wrapper后另批独立C2/D2各一次，实际各2/2 PASS并经复核；不能声称整个过程零设施重跑，也不把两项有限断言写成完整30项suite。Docker inspect的OOMKilled=true与退出0保持原始，不推断外层OOM没有发生。

806b历史VM binary为`de50b79084c9abdfc4f441b3a140600607cd28c20f7b5fca5671c3a438567e9e`，Docker为`78a5729ddb85861b93a51deff7a673059ae41ed6edf77752966c05d1d5fdfd72`；这些身份对应806b的99+99阶段通过和其长稳，不能直接标为5517结果。

806b VM在12225.017秒/408轮自动失败；1632混合任务全通过，3060网络检查为3059 PASS、1个worker_limit_and_recovery TimeoutError。summary的interrupted=false、complete=false，见[完整失败证据及三组有限对照](evidence/soak-failure-806b-20261107/README.md)。同期Docker已核验身份后由root正常SIGTERM中断；[原始终态](evidence/soak-superseded-806b-docker-20261107/README.md)为14492.454秒/483轮/1932任务/3600网络检查全通过，failures=0、interrupted=true、complete=false，不是自然失败或24h通过。

[806b阶段报告](evidence/code-review-ioctl-20261106/final-budget/README.md)与[关联问题/阶段证据](evidence/code-review-ioctl-20261106/README.md)、[首次审查证据](evidence/code-review-20261106/README.md)分别保留完整结果、修复前PoC、真实策略与旧soak归档。[原完善证据](evidence/completion-20261106/README.md)属于CBD旧输入；旧24h在约4080秒主动中断，interrupted=true/complete=false，不挪作修复版结果。

按用户要求仅`git commit --amend`，保留9个提交及原两个合并父；只更新`codex/enclio-linux-sandbox`并用精确force-with-lease。不改main，不新建Release/tag。最终包及安装报告置ignored dist，来源保持与已测binary和清洁提交一致。后续服务、原始metadata和收尾见[completion-state.md](completion-state.md)。
