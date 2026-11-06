# Changelog

## 0.1.0-preview.1 — 2026-11-06

- C11 CLI、bubblewrap 文件/进程/网络隔离、seccomp 拒绝清单。
- 精确域名、公网 TCP 443 CONNECT 代理和 namespace 内 loopback relay。
- 独立 JSON 结果、显式环境、继承 FD 清理、超时/信号取消及 PID 后代清理。
- Linux VM 和非特权 Docker 的真实验证、独立攻击探针、协议策略单元测试。
- 设计、安全评审、内核和宿主安全策略依赖、使用指南、Agent 示例与打包入口。

预览版限制：无 cgroup 资源配额，非 TLS 内容策略，无 32 位 ABI 支持。
已验证的平台、未完成的稳定版门槛以 docs/validation.md 为准。
