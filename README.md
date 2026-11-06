# Tegum

面向 Agent 的轻量 Linux 命令沙箱：**C CLI + bubblewrap + 精确域名网络代理 + seccomp**。
当前版本 `0.1.0-preview.1`，独立于任何 Agent 框架。

默认关闭外网；显式授权的目录映射为可写 `/workspace`；系统运行时只读。
按需通过受控 CONNECT 代理访问域名的公网 TCP 443 端口。
支持独立 stdout/stderr、JSON 结果、超时、取消和后代进程清理。

## 在 Linux 上构建运行

```sh
sudo apt-get update
sudo apt-get install build-essential libseccomp-dev bubblewrap python3 curl ca-certificates
make
./build/tegum doctor
mkdir -p /tmp/tegum-work
./build/tegum run --workspace /tmp/tegum-work --result /tmp/tegum-result.json \
  -- /bin/sh -c 'echo hello; echo saved > /workspace/result.txt'
cat /tmp/tegum-result.json
```

使用普通用户运行，Docker 内也不能使用 root。macOS 需要通过 Linux 虚拟机运行。
构建产物是无需语言运行时的 C 可执行文件，运行仍依赖 bubblewrap、libseccomp、libc 和内核能力。

```sh
./build/tegum run --workspace /tmp/tegum-work --allow-host example.com \
  -- curl --fail --show-error https://example.com
make unit
make test
make package
```

`--allow-host` 授权精确域名的公网 TCP 443 隧道，不检查 TLS/SNI/URL；普通 HTTP 代理、UDP、QUIC 不在首版范围。
工作目录及暴露的 `/usr` 等运行时目录不能包含不希望命令读取的机密或宿主服务 socket。
预览版没有 cgroup 资源配额，部署方需提供外层限制。

## 文档与验证

- [设计与威胁模型](docs/design.md)、[独立安全评审](docs/security-review.md)
- [使用指南与 CLI/JSON 契约](docs/usage.md)、[通用 Agent 示例](examples/agent.py)
- [外部依赖、内核与安全策略](docs/dependencies.md)、[参考资料](docs/references.md)
- [Linux VM / Docker 验证](docs/validation.md)、[性能原始数据说明](docs/benchmark.md)
- [实施任务台账](docs/tasks.md)、[发布包说明](packaging/README.md)、[变更记录](CHANGELOG.md)

容器默认 seccomp/AppArmor 策略可能阻止嵌套 namespace；`doctor` 失败时拒绝启动。
支持条件和实测结果分别列出，默认策略下启动受阻不计为安全测试通过。
不要用 `--privileged` 或全局关闭宿主安全策略解决容器兼容性。
