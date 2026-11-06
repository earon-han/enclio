# Enclio

可运行的[CLI安全效果示例](docs/security-demo.md)展示目录挂载、网络策略、自定义seccomp和资源/输出/超时边界。

面向 Agent 的普通用户 Linux 命令沙箱：**C11 CLI + bubblewrap + TCP 策略代理 + seccomp + 可选 cgroup v2 配额**。当前版本为 `0.2.0-preview.1`；实现、模块自测和最终环境验收的状态分别记录，见 [完成计划](docs/completion-plan.md) 与 [验证报告](docs/validation.md)。

默认无外网、严格 seccomp、300 秒期限、64 MiB 临时根文件系统、16 MiB 的目标 stdout/stderr 合计预算。默认授权目录以可写 `/workspace` 暴露；可选择只读模式，或复制到容量受限的临时工作区并安全导出。聚合 CPU、内存、进程数限制需要显式提供可用的 cgroup v2 委派父目录；请求的限制无法实施时拒绝启动。

isolated模式支持精确域名与端口授权的 HTTP 正向代理、HTTPS CONNECT 和 SOCKS5 域名 TCP，客户端共享 `127.0.0.1:18080`。该代理不支持 UDP/QUIC、SOCKS BIND/UDP ASSOCIATE 和 TLS 解密；显式host模式可使用的直接网络由父环境政策决定。授权 TCP 服务并不检查 TLS/SNI/URL，也不防止允许服务保存或转发任务数据。

当前增加[三种网络模式、额外挂载和目标seccomp覆盖](docs/options-extension-20261111.md)，最终8d387e49输入已通过Linux VM与获批委派Docker各174项功能检查、5组单元及各250000次sanitizer变异；独立原始数据复核和最终HEAD CI另行记录。默认仍不授予外网；显式host模式共享父环境网络，isolated模式必须有合法allow规则。

本轮按[监听FD交付方案](docs/listener-fd-handoff.md)移除沙箱内relay，功能验证结果以该文档为准；长稳验收按用户要求暂停。

独立代码审查后补齐了继承信号状态、子进程回收、代理元数据修改过滤及可信诊断计费边界，五个具体代码问题归入四类，另修公网正例的测试预算问题T1，见[审查与修复台账](docs/code-review-20261106.md)。proxy 拒绝全部 ioctl；依赖该调用而无法完成解析的 NSS 配置会拒绝连接，不自动放宽策略。bwrap/可信初始化器的诊断与目标输出预算分离。先前 CBD 与 97fb 执行输入的双环境长稳已主动中断，不算长稳通过；最终修复输入的双环境结果与真实 24 小时重验状态以[验证报告](docs/validation.md)为准。

## 构建与基本运行

在支持的 Linux 普通用户下运行；macOS/Windows 需要 Linux VM。Docker 内也不能以 root 运行 CLI。

```sh
sudo apt-get update
sudo apt-get install build-essential pkg-config libseccomp-dev bubblewrap ca-certificates curl python3
make
./build/enclio doctor
mkdir -p /tmp/enclio-work
./build/enclio run --workspace /tmp/enclio-work --result /tmp/enclio-result.json \
  -- /bin/sh -c 'echo hello; echo saved > /workspace/result.txt'
cat /tmp/enclio-result.json
```

C 二进制不依赖 Python/Node/Go 运行时；运行仍需 bubblewrap、libseccomp、libc 及内核/安全策略能力。Python 是测试和打包工具。完整资源模式需要 cgroup v2 的 cpu/memory/pids 控制器、`cgroup.kill` 和真实委派，详见 [依赖](docs/dependencies.md) 与 [部署](docs/deployment.md)。

## 有界工作区与网络

```sh
mkdir -p /tmp/enclio-export
./build/enclio run --workspace /tmp/enclio-work \
  --workspace-mode tmpfs --disk-bytes 67108864 --export /tmp/enclio-export \
  --output-bytes 1048576 --result /tmp/enclio-result.json \
  -- /bin/sh -c 'echo generated > /workspace/artifact.txt'

./build/enclio run --workspace /tmp/enclio-work --allow-host example.com \
  -- curl -fSs --max-time 10 https://example.com

./build/enclio run --workspace /tmp/enclio-work --allow example.com:80 \
  -- curl -fSs --max-time 10 http://example.com
```

导出目录必须预先存在且为空，不得与输入工作目录互相包含。仅命令成功后导出；复制失败可能留下先前已复制的节点，不提供整树事务语义。`--disk-bytes` 限制临时命名文件系统，不能为原地宿主可写目录设置总 quota；匿名 memfd/SysV 内存由内存限制另行约束。

## 文档与验证入口

- [使用指南/CLI 与 JSON](docs/usage.md)、[通用 Agent 调用示例](examples/agent.py)
- [架构与威胁模型](docs/design.md)、[安全审查及验收边界](docs/security-review.md)
- [内核/外部依赖/安全策略](docs/dependencies.md)、[委派与容器部署](docs/deployment.md)
- [验证报告](docs/validation.md)、[性能与长稳记录](docs/benchmark.md)、[任务台账](docs/tasks.md)
- [包与来源追溯](packaging/README.md)、[参考资料](docs/references.md)、[变更记录](CHANGELOG.md)

```sh
make unit
make test
make fuzz-smoke
make network-test
scripts/validate-linux.sh
make package
```

公网连通正例的T1预算为curl 30秒、CLI 40秒、Python等待60秒，无自动重试；这是功能检查，不承诺公网10秒延迟，也未修改生产拨号或过滤器。完整测试契约见[使用指南](docs/usage.md)。

`validate-linux.sh` 包含 baseline、独立资源和受控协议测试；设置`ENCLIO_CGROUP_PARENT`可测真实聚合限制；未设置时资源suite只覆盖非聚合场景与拒绝降级检查。环境拒绝启动单列 BLOCKED，不能当作安全负例通过。24 小时持续测试必须实际跑满，短时自测不构成长稳完成。Docker 的默认策略、显式例外和聚合配额委派分别验收，不能用特权容器或全局关闭安全策略替代。
