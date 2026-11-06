# 监听 FD 交付方案与验证计划

> 公开资料说明：本页验证记录中的证据链接现指向脱敏阶段摘要。机器原始日志、JSON、命令和归档已移出公开工作树并私下保留；历史段落中提及的原始文件不随仓库发布，旧原始校验值不适用于摘要。结果与失败状态未因此改变。

日期：2026-11-11。依据用户要求，将 CLI 的 relay → Unix socket 出口改为监听 FD 交付；长稳验收和自动检查继续暂停。

## 分工和实施顺序

1. root：集成监督器、FD 布局和可信 init；同步设计及状态文档。
2. listener_proxy：独立实现监听 FD 发送/接收、校验、确认和外部直接 accept，删除 relay 数据通路。
3. listener_tests：独立编写交付协议、句柄泄漏、故障及跨沙箱隔离测试。
4. listener_review：只读检视设计和最终代码；root逐项确认、讨论并修复，记录结论。
5. 在新执行目录运行 Linux VM 及获批委派 Docker 的单元、集成、资源和受控协议检查，记录 source/binary、实际安全策略和原始结果。失败保持原样，修复后新批次复验。
6. 仅 amend 原提交，并检查最终远端 HEAD 的双架构 CI；本轮功能验证不计作24小时验收或最终发布验收。

## 数据与控制通路

监督器在启动代理和 bwrap 之前创建任务私有的 AF_UNIX SOCK_SEQPACKET socketpair。外部代理只保留接收端 FD3；可信 init 经 bwrap 继承发送端 FD6。监督器及无关子进程关闭各自副本。

init 在沙箱 netns 创建 AF_INET TCP socket，绑定 127.0.0.1:18080 并 listen，再用 SCM_RIGHTS 交给外部代理。监听 socket 保持沙箱 netns 身份，外部代理对其 accept；代理新建的上游 socket 属于宿主 netns。工具仍通过 HTTP_PROXY/ALL_PROXY 连接沙箱 loopback，无宿主 IP 路由。

外部代理接收时验证协议及单一描述符，拒绝截断、额外 FD、非监听或非预期地址，使用 CLOEXEC 并在错误时关闭收到的描述符。校验与 transport seccomp 安装完成后才确认。init 等到确认，关闭本地 listener 与 FD6 后才 fork/exec 目标。代理接收端不进入 worker 或目标；不会挂载代理 socket 目录。

交付失败时拒绝启动工具，外部监督器继续执行总超时、取消、代理死亡监测和 guardian 回收。去除 relay 后，只剩代理最多32个连接 worker、HTTP最多32个辅助上传进程，均受原任务 cgroup 预算约束。旧 Unix proxy API只用于既有模块接口/测试，CLI不创建路径型代理入口。

## 验证门槛

- 真实 bwrap/netns 中的 HTTP、CONNECT、SOCKS5 成功，全部目标授权和DNS检查保持。
- 目标不继承监听或控制 FD，不存在 relay，不能从 procfs 重开可信控制句柄，也无 Unix代理挂载。
- 两个并发沙箱使用相同本地端口但不同策略，不能借用对方出口。
- 交付协议拒绝不合法消息/FD，超时、对端关闭和确认失败有界退出且不泄漏。
- 代理死亡、取消、超时、调用方死亡、无网络模式、资源触限及导出路径继续通过。

## 结果

实现和独立源码检视完成；root确认审查意见并补强双沙箱互斥策略、响应分片读取、失败清理。最终输入为`300c9564b349e8a8bbc9e71cbf514ec1be3267dd59c87f02a7caba11bc8f185f`（36文件）。

| 最终C批次 | 基础集成 | 资源集成 | 受控网络 | 单元 | ASan/UBSan |
|---|---|---|---|---|---|
| 本地Linux VM（ARM64，内核6.8） | 33 PASS | 36 PASS，aggregate=true | 30 PASS | 4组PASS | 250000次PASS |
| 获批委派Docker（普通UID、cap-drop ALL） | 33 PASS | 36 PASS，aggregate=true | 30 PASS | 4组PASS | 250000次PASS |

每环境完整套件仅在该最终输入上执行一次，0 FAIL/BLOCKED；先前A/B批次与设施纠正保留，不能称全部过程零设施重跑。VM还记录外部代理持有沙箱监听inode、代理留在宿主netns、init位于另一netns且无监听/FD6的实际观测。源码/二进制/环境/镜像策略及原始报告已私下归档，公开结果见[阶段摘要](evidence/listener-fd-20261111/README.md)。Docker inspect的OOMKilled=true与退出0原样保留，不推断外层OOM未发生。

| 检视与自验证发现 | root最终结论及处理 |
|---|---|
| 初始双沙箱测试只拒绝同一未授权域名，未证明不同策略 | 采纳；改为两个沙箱分别允许example.com/example.org，并各拒绝对方域名，实际均403；三项公网正例另证明允许通路可用 |
| 测试响应可能分片、失败清理变量未初始化 | 采纳；循环收满12字节前缀、提前初始化状态，保持单次断言 |
| probe忽略fgets结果，在VM严格编译时阻断 | 采纳；检查返回值并关闭文件/目录后失败，保留A批原错误 |
| Docker仓库HEAD超时 | 设施问题；使用既有Ubuntu24.04镜像的固定实际摘要，不放宽运行安全策略 |
| macOS tar附带34个AppleDouble文件导致输入摘要不同 | 设施问题；保留B批70文件身份，禁用归档元数据，在新C目录核对36文件/300c后重新全量 |
| 外部观测脚本把result误放workspace，CLI拒绝配置 | 设施问题；仅修脚本路径，保留原异常和脚本；最终C观测含实际binary摘要 |

没有未决的生产代码审查异议。先前失败未被改写为PASS。历史5517两组24h因采样空档终止，complete=false；用户于11月8日暂停长稳及自动检查，该暂停保持。本轮不宣称整体最终发布或长稳验收完成。
