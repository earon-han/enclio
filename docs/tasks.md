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
| A08 | 完成 | 超时、取消、调用方死亡、后代清理、示例 | 两环境实际调用方退出、SIGKILL、setsid、代理/relay故障均通过 |
| A09 | 完成 | VM与Docker报告、安全回归证据 | 同源两环境各31项PASS、0FAIL、0BLOCKED；默认Docker阻断单列；amd64尚无本地实测 |
| A10 | 完成 | 100重复/并发、CI与打包流水线 | 每环境100顺序+4并发共12次零失败，原始样本保留；双架构远端CI配置与本地结果分别说明 |
| A11 | 完成 | 预览版包、校验、清洁安装和探测 | ARM64包两次生成一致，解压校验、doctor、实际运行通过；预览版本见下方发布记录 |

## 提交追溯

| 任务 | 提交/来源 |
|---|---|
| A00—A04 设计与安全基线 | `8ea4053` |
| A05—A09 C实现与独立攻击探针 | `dbb87b3` |
| A10—A11 容器、CI、源码追溯、打包 | 该文件所在分支的 `build(A10-A11)` 提交 |
| A09—A11 最终证据和验收 | 该文件所在分支的 `docs(A09-A11)` 提交 |

工作分支：`codex/tegum-linux-sandbox`。首个预览版本：[v0.1.0-preview.1](https://github.com/earon-han/tegum/releases/tag/v0.1.0-preview.1)。远端版本以该链接的实际发布状态为准；未合并主分支不影响 tag 对具体源码的追溯。

执行与验证输入 SHA256：`847b9a7fa6d9f9820987a45d6ee3321a10e35f395484813e35e3a6c83242d9cd`。报告同时记录二进制SHA256，避免把传输到VM时尚无`.git`的源码误标为空实现HEAD；这种传输副本的Git字段明确为null。发布包manifest另记录最终tag对应的Git提交。

`docs/evidence/package-installation.json` 为实验阶段无Git元数据归档的重复打包/安装证据。最终Release归档因加入最终Git提交和文档而改变archive SHA，C二进制和实现输入不变；随Release提供的 `release-verification.json` 单独校验最终归档、提交与安装探测，不改写原始证据。

## 检查点

1. 设计可实施：已完成；VM非特权namespace机制实测成功，代理/文件/ABI边界经过独立审查。
2. CLI功能完整：已完成；PID1/non-dumpable等修复均在两个环境重跑，含生命周期及故障注入。
3. 版本可发布：预览版门槛已完成；稳定版另需两架构原生验证、资源限制集成和更广泛的安全审计/压力测试。未覆盖项继续保留，不以预览版完成等同于稳定版完成。
