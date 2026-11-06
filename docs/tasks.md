# 实施进度与协作台账

以根目录《实施计划.txt》为原始任务依据，首版目标为 `0.1.0-preview.1`。
本台账区分预览版已交付能力和稳定版追加门槛；不把 CI 配置写出等同于 CI 已运行。

## Agent 分工和评审机制

| Agent | 独立责任 | 交付 |
|---|---|---|
| 主 Agent | CLI、bubblewrap 执行器、seccomp、生命周期、结果、集成、使用说明 | `src/main.c internal.c seccomp.c`、README、使用指南、通用示例 |
| design_review | 方案、依赖、官方资料、独立安全评审；不修改实现 | `design.md dependencies.md references.md security-review.md` |
| proxy | 独立代理/relay、协议策略单测、源码指纹和可安装发行包 | `src/proxy.* tests/proxy_unit.c`、打包脚本和说明 |
| validation | 独立攻击探针、VM/Docker 环境与实测、基准、CI；不修改执行器 | `tests/probe.c integration.py`、Dockerfile、CI、验证报告和原始证据 |

设计先明确 C11、namespace、CONNECT 授权和结果契约；随后执行器与代理并行实现，验证 Agent 独立准备 Linux VM 和容器条件。安全评审持续指出边界问题，主 Agent 修复，验证 Agent 添加回归并重新执行。详细问题及闭环见独立评审报告。

## 任务状态

| ID | 状态 | 交付物 | 验证/阻断与下一步 |
|---|---|---|---|
| A00 | 完成 | 设计范围、语言与非目标 | C11 独立CLI；Linux普通用户，预览版不做cgroup/多租户服务 |
| A01 | 完成 | LICENSE、AGENTS、README、模板、构建入口 | 构建/测试/安装入口已写；提交追溯见下表 |
| A02 | 完成 | 官方参考/许可证、依赖说明 | VM namespace 真实探测成功；具体版本见验证报告 |
| A03 | 完成 | 威胁模型、接口、安全决策、独立review | 各层职责/边界明确；高风险发现修复后需独立回归 |
| A04 | 完成 | doctor、VM能力探测、Docker条件验证脚本 | VM普通用户user/pid/net成功；Docker条件单列，不放宽全局sysctl |
| A05 | 完成 | C CLI、Makefile、参数校验、版本、结果错误 | VM编译和基础启动通过；完整终版结果以validation为准 |
| A06 | 完成 | 文件系统隔离、原生ABI seccomp、FD/env清理 | 独立probe执行后验证文件/符号链接/syscall/FD限制 |
| A07 | 完成 | CONNECT代理、relay、DNS地址校验、连接上限 | 真实HTTPS正向与负例、协议单元测试；不声称TLS内容检查 |
| A08 | 进行中 | 超时、取消、调用方死亡、后代清理、示例 | 最终调用方死亡/故障注入与PID1修复后重测中 |
| A09 | 进行中 | VM与Docker报告、安全回归证据 | VM首轮通过；最终源代码两个环境重测中；amd64未实测 |
| A10 | 进行中 | 100重复/并发、CI与打包流水线 | 原始样本、容器条件与最终package验证待收尾 |
| A11 | 进行中 | 预览版包、校验、清洁安装和探测 | 本地包待构建验证；远端Release发布需准确记录，不把本地打包当远端发布 |

## 提交追溯

本次提交使用任务 ID 分组；验证证据同时记录可执行输入源码指纹和二进制 SHA256，以避免未提交阶段误引用仓库最初空实现的 HEAD。最终提交号、推送和预览版包在完成后补入这里。

## 检查点

1. 设计可实施：已完成；VM非特权namespace机制实测成功，代理/文件/ABI边界经过独立审查。
2. CLI功能完整：最终生命周期故障回归和修复后重测中。
3. 版本可发布：首个预览版两环境证据和安装包验证收尾中；稳定版另需至少两架构原生验证、资源限制集成和更广泛的安全审计。
