# Enclio 功能完善计划

> 公开资料说明：本页验证记录中的证据链接现指向脱敏阶段摘要。机器原始日志、JSON、命令和归档已移出公开工作树并私下保留；历史段落中提及的原始文件不随仓库发布，旧原始校验值不适用于摘要。结果与失败状态未因此改变。

当前新增任务（北京2026-11-11）：[网络模式、额外挂载和目标seccomp扩展](options-extension-20261111.md)已完成功能自验证。最终执行输入`8d387e49acaaba8ce0e915840a437b0f5ad16c12a8ec2977e80e03498c264885`（38文件）在Linux VM与获批委派Docker各一次完成33基础+36资源+30受控代理+75新增配置检查，均174 PASS、0 FAIL/BLOCKED；各5组单元及250000次ASan/UBSan变异通过。原件已私下归档，公开结果见[本轮摘要](evidence/options-extension-20261111/README.md)；独立原始数据及实际二进制字节复核已通过，最终实际HEAD的CI以该提交workflow和产物核对为准。下文300c及更早结果保留其原身份。长稳与专属自动检查仍暂停，整体P07/P10未完成。

历史300c阶段（北京2026-11-11）：[监听FD交付改造](listener-fd-handoff.md)已完成源码检视和本地Linux VM/获批委派Docker各一次99项功能验证、四组单元及各250000次ASan/UBSan变异，最终输入`300c9564b349e8a8bbc9e71cbf514ec1be3267dd59c87f02a7caba11bc8f185f`（36文件）。[公开阶段摘要](evidence/listener-fd-20261111/README.md)保留先前设施失败和全部新结果。用户暂停长稳和专属自动检查的指令继续有效；最终交付P07/P10仍未完成。下文5517为历史阶段记录。

日期：2026-11-06；基线提交403130b。用户确认本轮网络覆盖HTTP、HTTPS CONNECT、自定义端口和SOCKS5 TCP；UDP/QUIC与TLS解密不支持。本轮沿用C11、普通用户、无特权容器，以及本地Linux VM和Docker分别真实验证。

## 分工与步骤

| ID | 工作项 | 负责 | 完成条件 |
|---|---|---|---|
| P00 | 需求/接口/威胁模型和验收清单 | root设计，验证Agent独立评审 | CLI/JSON、限制单位和失败语义明确 |
| P01 | cgroup v2 CPU/内存/PID进程树配额；额外rlimit | resource_engine实现 | 委派真实可写、控制器readback、事件证明触限；请求无法执行就拒绝 |
| P02 | 总量受限临时文件系统/工作区、安全导出 | resource_engine复制/导出，root挂载接入 | 有界共享root tmpfs覆盖workspace/tmp/home/shm，无无界dev旁路；原地RW目录不能冒充有总额 |
| P03 | 合计stdout/stderr输出上限、背压、资源结果 | root实现，独立验证 | 超量终止且输出不超过预算；慢消费可取消；保留业务结果和limit_reason |
| P04 | HTTP正向、CONNECT自定义端口、SOCKS5域名TCP | network_engine | 共用精确host:port和全部DNS地址先验，无直连降级 |
| P05 | 严格seccomp/可信代理独立过滤 | root目标策略，network_engine代理 | 常用命令可用，危险/未知入口拒绝；compat仅显式选择 |
| P06 | 清理guardian/父死亡/故障 | root实现，独立验证注入 | SIGKILL也收敛受管进程、cgroup和内部目录；控制FD不泄漏 |
| P07 | 可控DNS/协议fixture、sanitizer/fuzz/并发/持续压力 | independent_verification | 每个安全负例真实执行；原始样本含source/binary身份；真实时长不改写 |
| P08 | Linux VM及Docker全套复验 | independent_verification | 功能/拒绝/触限/故障逐项PASS，设施失败单列BLOCKED，禁止privileged与全局安全降级 |
| P09 | 使用/设计/依赖/部署/兼容/任务文档 | root整合，Agent交叉核对 | 所有公开参数、cgroup委派、AppArmor/SELinux/外部依赖及边界明确 |
| P10 | 二进制/源码/包/证据同源与远端CI | root | 单测/集成/安装/双架构CI通过，版本和清洁提交可追溯 |

P01与P04并行。root并行实现P03/P05/P06并集成；验证Agent不修改执行器实现。接口变更须通知其他Agent；任何请求的限制都不得静默降级。完成后沿用用户的amend要求，不另加后续提交。

## 明确的能力语义

- cgroup提供聚合CPU配额、实际内存与进程数限制；rlimit只提供其真实的每进程/每文件语义，不替代聚合配额。
- tmpfs模式把授权宿主目录作为只读input，复制到有总容量边界的临时workspace；导出只经可信init持有的目录FD，不暴露宿主可写目录。readwrite模式保留兼容语义，无法证明原地总磁盘配额时拒绝该请求。
- 输出预算为stdout+stderr合计；资源触限与业务非零退出、启动失败分别报告。
- HTTP代理使用单请求/连接、显式Connection:close，严格正文语义；CONNECT/SOCKS授权目标TCP服务，不检查TLS/SNI/URL。协议边界、尺寸/时限均写明。
- 严格seccomp默认拒绝未列出的syscall，兼容策略只能显式选择。内核漏洞、同UID宿主恶意进程、允许服务的数据外传和外部安全认证仍不属于项目可保证范围。
- 测试包含长时稳定性和可重复脚本；发布前所承诺的持续时长必须真实跑满，不能将短时结果标成长稳完成。

## 状态

P00—P06、P08—P09完成。五个代码问题及T1在806b阶段完成root逐项裁决、修复、reviewer复核和两环境各99项功能检查，另有3个单元组、各250000次fuzz及7个CLI回归通过；这些保留为历史记录，不能当作T2新输入结果，详见[审查台账](code-review-20261106.md)。

P07进行中：806b VM在408轮/12225.017秒自动失败，1632混合任务全通过、3060网络检查3059 PASS及1个worker_limit Timeout；原FAIL无损保留。三组有限对照为baseline PASS、30ms关闭后退出延迟加旧逻辑FAIL、同一注入加NOAUTH/reap屏障PASS，证明测试同步缺陷机制，不回填历史第408轮时序。root/reviewer采纳T2最小测试修复，未修改生产C、32-worker/10秒头/额外连接1秒期限，断言不重试。旧CBD/97fb长稳主动中断；806b Docker也因T2正常中断，均不计24h通过。新输入须独立重新真实跑满。

P08完成：5517的VM与获批委派Docker各一次完整99 PASS、0 FAIL/BLOCKED，3组单元、各250000次fuzz及真实aggregate通过；A/B普通/quick网络各一次完整30 PASS，C2/D2各一次有限2 PASS。root/reviewer已逐SHA/AST/事件/原始报告完成核对。C/D在fixture编译阶段因wrapper argv0=cc无法定位cc1而设施失败、未运行断言，旧错误保留；只修外部wrapper后另批独立目录C2/D2，不改输入/注入/时限，不能称整个过程零设施重跑。Docker inspect的OOMKilled=true原样保留，不据退出0推断外层OOM没有发生。旧806b的99+99仍保留。P10进行中：等待新输入最终amend HEAD双架构CI、同源归档与安装最终验收。

当前T2冻结输入为`5517be35c091fb37a778b8a7cf79b7cdb246eb93f801527fd136398e4b8de584`（35文件），源码及新双环境全量原始数据最终核对已通过，T2功能闭环。历史5517长稳因采样空档失败，未通过，仍须独立真实跑满；5517已因覆盖不足结束，长稳验收现已暂停，见[完成状态](completion-state.md)。只在独立新副本验证，旧执行副本和[806b失败证据](evidence/soak-failure-806b-20261107/README.md)不改写。文档与新证据可补充。详细结果见[tasks.md](tasks.md)、[validation.md](validation.md)，后续服务与收尾见[completion-state.md](completion-state.md)。没有达到的门槛不标完成。
