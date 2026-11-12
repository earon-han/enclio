# Enclio 性能与稳定性验证

> 公开资料说明：本页验证记录中的证据链接现指向脱敏阶段摘要。机器原始日志、JSON、命令和归档已移出公开工作树并私下保留；历史段落中提及的原始文件不随仓库发布，旧原始校验值不适用于摘要。结果与失败状态未因此改变。

当前更新（北京2026-11-11）：[监听FD交付改造](listener-fd-handoff.md)已完成源码检视和本地Linux VM/获批委派Docker各一次99项功能验证、四组单元及各250000次ASan/UBSan变异，最终输入`300c9564b349e8a8bbc9e71cbf514ec1be3267dd59c87f02a7caba11bc8f185f`（36文件）。[公开阶段摘要](evidence/listener-fd-20261111/README.md)保留先前设施失败和全部新结果。用户暂停长稳和专属自动检查的指令继续有效；最终交付P07/P10仍未完成。下文5517为历史阶段记录。

以下为`0.2.0-preview.1`的806b阶段历史性能样本，执行输入为`806b059f336f976bb47764f1ad89e780abe180736d3c20da24c665137f913644`。当前T2输入`5517be35c091fb37a778b8a7cf79b7cdb246eb93f801527fd136398e4b8de584`已冻结并完成源码复核，新双环境各一次99项及有限回归已通过root/reviewer原始数据最终复核，T2功能闭环、P08完成；历史5517长稳因采样空档失败，未通过，当前验收状态见[完成状态](completion-state.md)。下表保留806b旧样本，新5517统计另列，不能互相替代。包含源码/二进制身份、逐次退出码/启动状态的原始样本已私下归档，公开结果见[806b阶段摘要](evidence/code-review-ioctl-20261106/final-budget/README.md)。

两环境在同一台ARM64 Lima VM及其Docker中各运行100次无网`/bin/true`，使用默认strict、只读系统、宿主RW workspace、有界root tmpfs和目标输出预算，未请求额外cgroup配额。时间包含隔离、执行、输出和清理，不代表网络吞吐或聚合限额下延迟。另各做4并发共12次，均通过。

| 环境 | 顺序样本 | 失败 | median | p95 | max |
|---|---:|---:|---:|---:|---:|
| Linux VM | 100 | 0 | 14.316 ms | 15.232 ms | 16.863 ms |
| 获批Docker | 100 | 0 | 16.356 ms | 17.538 ms | 18.272 ms |

median为中位数，p95取排序后第`ceil(0.95*N)`个样本。预览观测目标100次/并发零失败、median<200ms、p95≤200ms，806b该阶段达到。完整保留样本；共享VM负载下观测不外推为其他服务器保证。

806b各环境99项完整功能/故障检查、3个单元组和250000次ASan/UBSan解析fuzz历史通过。其VM长稳随后自动失败、Docker主动中断，均未达到24h；5517新输入全量最终核对通过，新24h仍未完成，服务及metadata见[completion-state.md](completion-state.md)。门槛为实际86400秒、至少2592轮、最大轮间/尾段间隔120秒、源码/binary不变、未中断且零失败；每30秒4并发混合配额任务，每4轮附加30项生产时限网络。

旧CBD长稳在136轮、544任务、1020网络检查、约4080秒时因本轮代码审查修复主动结束，failures=0但interrupted=true、complete=false。其无损原始归档见[首次审查证据](evidence/code-review-20261106/README.md)的superseded-cbd-soak；旧基准数字及阶段短自验不移作本次结果。

## 806b长稳终态与T2

VM实际运行12225.017秒/408轮后自动失败；1632混合任务全通过，102套网络3060检查中3059 PASS、1个worker_limit_and_recovery TimeoutError。failures=1、interrupted=false、complete=false、coverage_sufficient=false，[原始失败证据](evidence/soak-failure-806b-20261107/README.md)保留完整样本，不改为通过或主动中断。

同期Docker为新输入复验而经身份核对后正常SIGTERM中断：实际14492.454秒/483轮/1932任务/120套网络3600检查均通过，failures=0、interrupted=true、complete=false；见[结束证据](evidence/soak-superseded-806b-docker-20261107/README.md)。service的failed/exit1是这次主动中断的预期状态，不是VM那类自然失败，亦非24h通过。

三组独立有限对照各执行一次：baseline旧逻辑PASS；测试专用30ms worker关闭后退出延迟加旧逻辑FAIL；同一个延迟fixture加NOAUTH握手/reap屏障PASS。它证明同步缺陷机制，不还原历史第408轮精确调度。T2只修测试同步，生产C、32-worker、10秒头及额外连接1秒期限不变、断言不重试，详见[审查台账](code-review-20261106.md)。5517新输入已重新通过双环境全量，真实86400秒仍须独立完成，旧时长不累计，P07/P10仍进行中，P08完成。

5517双环境各一次完整99 PASS，A/B普通/quick完整网络各一次30 PASS；C2/D2有限回归各一次2/2 PASS，仅前置positive HTTP与实际worker_limit，不是完整30项。所有原始样本及root/reviewer最终复核已通过。故障注入C/D初次在fixture编译阶段因外部wrapper argv0导致cc1定位失败，没有执行断言；仅修wrapper后另获批准C2/D2，原错误保留，不能描述整个过程零设施重跑。Docker inspect的OOMKilled=true与退出0均保留，不推断外层OOM没有发生。新24h实际身份见续接状态，P07/P10继续。

## 5517当前性能样本

5517原件中的各100次无网/bin/true启动/回收样本已私下归档，公开结果见[阶段摘要](evidence/worker-sync-5517-20261107/README.md)，沿用前述median/p95定义及场景；全部退出0且command_started=true，另4×3并发通过。以下为新输入实际观测，不覆写806b旧表，也不外推为网络延迟或其他宿主保证。

| 环境 | 顺序样本 | 失败 | median | p95 | max |
|---|---:|---:|---:|---:|---:|
| Linux VM | 100 | 0 | 20.382 ms | 23.132 ms | 26.719 ms |
| 获批Docker | 100 | 0 | 14.443 ms | 24.756 ms | 53.341 ms |

VM binary为`aca6592378291ee0f37b8532881a8b938efbbcbcef76d11b7dc168e7c951be64`；Docker binary为`78a5729ddb85861b93a51deff7a673059ae41ed6edf77752966c05d1d5fdfd72`。同binary新24h正在进行、尚未验收，仍须实际达到原定时长/覆盖/零失败门槛；功能复验不替代持续验证，当前验收状态见[完成状态](completion-state.md)。
