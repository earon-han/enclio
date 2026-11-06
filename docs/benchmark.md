# 性能与稳定性验证

首版采用 100 次顺序启动 `/bin/true`、4 并发共 12 次启动作为轻量基线；有网代理还单独运行真实 HTTPS 正例。策略为最小只读系统目录、一个可写 workspace、无网络（基准阶段），默认 seccomp 开启。wall time 包括创建 namespace、挂载、安装 seccomp、执行和清理；不等于 payload CPU 时间。

本次本地 arm64 实测：VM median 11.806 ms / p95 12.482 ms / max 13.721 ms；Docker median 11.773 ms / p95 12.870 ms / max 29.244 ms。两边各 100 样本、0 失败，均满足本轮观测目标。

原始样本在 `docs/evidence/vm-integration.json`、`docker-integration.json` 的 `benchmark_samples` 字段，每条含耗时、返回码和 `command_started`。摘要见 `docs/evidence/benchmark-summary.json`。报告关联的源码树与二进制摘要均在 JSON 中；本次在测试时的普通用户、共享 Lima VM 负载条件下采样，不能外推到独占服务器。

| 环境 | 样本 | 失败 | median | p95 |
|---|---:|---:|---:|---:|
| Linux VM | 100 | 0 | 11.380 ms | 12.411 ms |
| Docker | 100 | 0 | 11.397 ms | 12.085 ms |

预览验收：100 次零失败且真实命令全部启动；4 并发任务无失败；median < 200 ms、p95 <= 200 ms 作为首轮目标。预算之外的样本保留，不剔除；外网延迟不混入无网启动基准。稳定版还需 x86_64、更多内核、24 小时 soak、系统性故障注入和独立安全审计，不以本轮数分钟检查替代。
