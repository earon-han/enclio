# 二进制交付与来源追溯

`make package` 在 Linux 本机完成编译后生成：

```text
dist/tegum-0.1.0-preview.1-linux-arm64.tar.gz
dist/SHA256SUMS
```

x86_64 本机构建的文件名使用 `linux-amd64`。不提供未经实测的跨架构
产物。生成过程需要 Python 3 标准库；运行 CLI 不需要 Python。

这是独立 C 可执行文件，使用动态 glibc 和 `libseccomp.so.2`；它不是静态
可执行文件，也不打包 bubblewrap。运行环境必须另外安装 `/usr/bin/bwrap`，
并满足 [运行依赖与安全策略](../docs/dependencies.md)。应在目标发行版上构建，
或先验证目标环境的 glibc ABI 兼容性，不保证不同发行版之间直接复制即可运行。

## 从归档安装和自检

```sh
sha256sum -c SHA256SUMS
tar -xzf tegum-0.1.0-preview.1-linux-arm64.tar.gz
cd tegum-0.1.0-preview.1-linux-arm64
sha256sum -c SHA256SUMS
./bin/tegum version
./bin/tegum doctor
sudo install -m755 bin/tegum /usr/local/bin/tegum
```

`doctor` 必须实际启动成功，JSON 中 `ready` 为 `true`。依赖或宿主策略阻止
namespace/seccomp 时，自检失败必须按 BLOCKED 处理，不能标记为安全测试通过。
包内保留 README、许可证、更新记录、设计/依赖/使用文档、通用 Agent 示例。
包内不复制 `docs/evidence/` 与 `docs/reports/` 原始证据，避免安装报告记录
归档校验值而形成自身散列循环。原始测试结果在
[仓库验证证据](https://github.com/earon-han/tegum/tree/main/docs/evidence)，
与包中 `docs/validation.md` 一起按 manifest 的 Git HEAD 和源码身份核对。

## 构建信息和校验

`manifest.json` 记录交付版本、架构、二进制 SHA256、源码树 SHA256、Git HEAD、
完整工作区是否有未提交修改、动态链接结果和 bubblewrap 版本。校验值用于
完整性与本次构建的追溯，没有发行者签名，不等同于来源认证。

在仓库根目录运行 `python3 scripts/source-id.py --json` 可复算执行与验证输入的身份。
范围为 `src/`、`tests/`、`scripts/`、`examples/`、`.github/workflows/`、
`Makefile` 和 `Dockerfile`，也记录在 `source_scope` 字段。
算法为 `tegum-source-tree-v1`：按照路径字节顺序遍历文件，将节点类型、
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
