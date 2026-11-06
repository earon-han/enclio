# Changelog

## 0.2.0-preview.1 — 2026-11-06

- Add explicit none/host/isolated networking, caller-authorized read-only/read-write directory mounts, and per-syscall target policy overrides; preserve isolated listener-FD handoff.

本轮功能完善版本；最终环境验收、24小时持续运行、同源包和CI状态见`docs/validation.md`与`docs/tasks.md`，此条目不表示已经发布远端Release或达到稳定版认证。

- 网络增加HTTP正向代理、显式host:port CONNECT及SOCKS5域名TCP，全部共用精确端点/DNS策略；保留allow-host的443语义。用户确认UDP/QUIC与TLS解密不支持。
- 增加cgroup v2聚合内存、进程/线程和CPU带宽配额；缺少委派/控制器/原子清理能力就拒绝，不降级。
- 增加目标逐进程CPU/地址空间/FD及单文件大小限制，分开记录其真实作用范围。
- 增加readonly/tmpfs工作区、共享有界临时根、受信目录FD安全导出及稀疏文件/路径防护。
- 增加stdout/stderr合计预算、stdin只读中继、可取消背压和更明确的业务/触限/清理结果。
- 默认采用native syscall允许清单与拒绝清单交集；compat显式选择，proxy/relay独立过滤。
- guardian从创建资源开始持有清理责任，pidfd固定进程身份，正常解除守护与启动中止回收分开处理。
- 扩展独立资源/协议测试、sanitizer/fuzz、并发/持续运行脚本，以及依赖、委派、部署和安全边界文档。
- 独立审查后修复启动线程信号mask及SIGCHLD忽略状态继承，按顺序建立管理handler再解除屏蔽，保留取消和wait回收契约。目标请求CPU/file限制时恢复对应SIGXCPU/SIGXFSZ默认处理。
- proxy/relay补充fchmodat2拒绝（R3a）；两支持native ABI使用已核对的编号452兜底，避免旧libseccomp名称库漏规则。交叉复核另补整体ioctl拒绝（R3b），关闭只读文件FD的元数据修改及高位request别名；不改变目标seccomp。依赖这些调用而无法完成解析的NSS机制会失败，不放宽策略。
- bwrap/可信init诊断与目标stderr独立，诊断最多转写16KiB、超额丢弃；不计目标输出预算，避免微小budget将设施失败误报为资源超限。
- 本轮共五个具体代码问题、四类修复，裁决及复验见[独立审查台账](docs/code-review-20261106.md)。先前CBD与97fb输入的长稳已主动中断并保留未完成状态，最终修复输入不能沿用旧通过记录。

- 另修测试预算问题T1：仅三条公网连通正例采用curl/CLI/Python等待30/40/60秒并在network_smoke中记录，无自动重试；其他helper默认等待、负例、受控网络和生产拨号/过滤不变。不承诺公网10秒延迟SLA，不将此调整视为已定位全部旧公网超时根因或排除所有NSS回归；旧失败及后续诊断保留。

- 修复长稳发现的测试同步问题T2：worker饱和用例先等待前序worker回收，以SOCKS5握手确认每个占位连接，并记录实际子进程、连接状态和失败阶段；关闭后有界等待回收，再执行一次恢复请求。生产32-worker上限、10秒头期限及额外连接1秒接收期限未改。806b VM第408轮原始FAIL完整保留，新输入独立验收，旧时长不沿用。

## 0.1.0-preview.1 — 2026-11-06

历史首版：C11 CLI、bubblewrap基础隔离、TCP443 CONNECT代理、seccomp拒绝清单、JSON结果、超时取消、基础后代清理、Linux/Docker验证和打包入口。项目/CLI/代码/文档统一命名Enclio，迁移合并提交按用户要求通过amend更新。

0.1当时未提供cgroup聚合配额、普通HTTP或SOCKS；这些历史限制由0.2实现扩展，不作为当前能力说明。两个版本均不承诺TLS内容策略、32位ABI、内核漏洞防护或外部安全认证。
