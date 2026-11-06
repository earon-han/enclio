# 二进制交付与来源追溯

`make package` 在 Linux 本机完成编译后生成：

```text
dist/enclio-0.2.0-preview.1-linux-arm64.tar.gz
dist/SHA256SUMS
```

x86_64 本机构建的文件名使用 `linux-amd64`。不提供未经实测的跨架构
产物。生成过程需要 Python 3 标准库；运行 CLI 不需要 Python。

这是独立 C 可执行文件，使用动态 glibc 和 `libseccomp.so.2`；它不是静态
可执行文件，也不打包 bubblewrap。运行环境必须另外安装 `/usr/bin/bwrap`，
并满足 [运行依赖与安全策略](../docs/dependencies.md)。完整资源模式还要求有效cgroup v2委派与cgroup.kill，见[部署指南](../docs/deployment.md)。应在目标发行版上构建，
或先验证目标环境的 glibc ABI 兼容性，不保证不同发行版之间直接复制即可运行。

## 从归档安装和自检

```sh
sha256sum -c SHA256SUMS
tar -xzf enclio-0.2.0-preview.1-linux-arm64.tar.gz
cd enclio-0.2.0-preview.1-linux-arm64
sha256sum -c SHA256SUMS
./bin/enclio version
./bin/enclio doctor
sudo install -m755 bin/enclio /usr/local/bin/enclio
```

`doctor`必须实际启动成功，JSON中ready为true。基础探测不代表已有聚合配额委派；有委派parent时，另运行：

```sh
./bin/enclio doctor --cgroup-parent "$CG_PARENT"
```

检查cgroup_limits_probed与cleanup_complete。依赖或宿主策略阻止
namespace/seccomp 时，自检失败必须按 BLOCKED 处理，不能标记为安全测试通过。
包内保留 README、许可证、更新记录、设计/依赖/使用文档、通用 Agent 示例。
包内不复制 `docs/evidence/` 与 `docs/reports/`。原始机器日志、运行环境转储、
测试二进制和压缩归档保存在 Git 外，已移出当前工作树且不随新安装包发布。公开的
[验证摘要](https://github.com/earon-han/enclio/tree/codex/enclio-linux-sandbox/docs/evidence)
保留对应输入的结果、失败和限制；它不是原始报告，不能用旧原始报告的 SHA
校验摘要。结合包中 `docs/validation.md` 和 manifest 的 Git HEAD、源码身份核对。

## 构建信息和校验

`manifest.json` 记录交付版本、架构、二进制 SHA256、源码树 SHA256、Git HEAD、
完整工作区是否有未提交修改、动态链接结果和 bubblewrap 版本。校验值用于
完整性与本次构建的追溯，没有发行者签名，不等同于来源认证。

在仓库根目录运行 `python3 scripts/source-id.py --json` 可复算执行与验证输入的身份。
范围为 `src/`、`tests/`、`scripts/`、`examples/`、`.github/workflows/`、
`Makefile` 和 `Dockerfile`，也记录在 `source_scope` 字段。
算法为 `enclio-source-tree-v1`：按照路径字节顺序遍历文件，将节点类型、
带长度的相对路径和文件内容输入 SHA256；可执行位参与散列，软链接只散列
链接目标文本，不追踪目标。包括上述范围内未提交、未跟踪的源码文件，以便当前预览版
在提交之前也能追溯到同一套实际源码。

排除虚拟环境与常见缓存；所有 `docs/`、`packaging/`、README、许可证、更新记录、
用户原始计划和 Git/build/dist 元数据都在范围之外。证据与任务台账可以引用
源码身份而不会引起自身散列循环；包内文档仍由归档和包内 `SHA256SUMS` 覆盖。
`git_dirty` 来自完整 Git 状态，可能因不参与源码身份的文档而为 `true`；
源码归档外复制若缺少 Git，Git 字段为 `null`。

打包时拒绝目录内软链接、版本不匹配、源码文件比二进制新、打包过程中的源码
变化。二进制来源依赖正常的 `make package` 构建流程；保留时间戳并人为替换
文件不能由新旧时间检查识别。发行前应在干净检出上重新构建和验证。

归档的路径顺序、属主、权限与时间戳规范化，gzip 不写入本机路径和当前时间。
可用 `SOURCE_DATE_EPOCH` 固定时间；默认使用 Git HEAD 的提交时间。相同输入
文件和环境元数据可生成相同归档，但当前构建含调试信息，工具链、构建路径、
动态链接库版本和 manifest 的运行环境变化会影响结果，不承诺跨机器逐字节一致。

该预览版的支持矩阵、真实 Linux / Docker 证据与尚未完成的发布门槛，以仓库
验证报告为准。生成本地安装包不代表已上传到远端 Release 或获得稳定版认证。

## 本轮交付门槛

`0.2.0-preview.1`包含HTTP/CONNECT/SOCKS、自定义端口、严格seccomp、资源限制和受管导出等能力。本地VM与Docker分别全量验证、24小时持续运行、最终清洁提交封装和双架构CI为分别记录的门槛；未达到的项目不会因归档已生成而自动完成。证据状态见[验证](../docs/validation.md)和[完成计划](../docs/completion-plan.md)。

实验阶段传输副本可如实记录git_head/git_dirty为null；同一已测二进制可在最终提交元数据同步后重新封装。最终archive hash因此可能变化，但source_tree_sha256与binary_sha256必须继续匹配。不要改写先前安装证据使其冒充最终归档；最终归档可用忽略目录中的`dist/release-verification.json`单独验证，避免自引用散列循环。

完整cgroup或容器部署通常由管理员配置，归档安装不自动取得这些权限。也不安装或关闭AppArmor/SELinux、改sysctl、启动特权容器，或自动发布远端Release。正式发布的版本、签名和外部认证必须另有真实记录。
