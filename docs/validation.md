# 验证报告与复现

验证日期：2026-11-06。测试使用本机 Lima Linux 虚拟机，以及该虚拟机中独立启动的 Docker 容器。macOS 仅用于编辑和协调，没有把 macOS 检查算作 Linux 沙箱验证。

最终结果：**VM与Docker分别31项PASS、0 FAIL、0 BLOCKED**。每环境另含100次顺序和4并发共12次执行，零失败。实现/验证输入摘要为 `847b9a7fa6d9f9820987a45d6ee3321a10e35f395484813e35e3a6c83242d9cd`；所有安全探针和故障注入采用最后修复后的同一份源码。

发布的ARM64 C二进制SHA256：`26e56068301b6dd5aabd1faf593e04ef85e5cfd918d7529a9e68cf4986066c75`。Docker同源独立编译的二进制摘要不同，包含构建路径等调试信息；各自结果文件记录各自的真实摘要。

## 实测平台

| 环境 | 实测配置 | 结果来源 |
|---|---|---|
| Linux VM | Ubuntu 24.04.5 LTS，aarch64，Linux 6.8.0-147-generic；普通用户 UID 501；bubblewrap 0.9.0；libseccomp 2.5.5；GCC 13.3 | `docs/evidence/vm-integration.json`、`vm-environment.txt` |
| Docker | Docker 29.1.3，Ubuntu 24.04 arm64，内核同上；UID/GID 1000:1000；`--cap-drop ALL` | `docs/evidence/docker-integration.json`、`docker-environment.txt`、`docker-policy.json` |
| Docker 默认安全策略 | 普通用户，默认 seccomp/AppArmor/proc masking | `docs/evidence/docker-default-doctor.json`；启动受阻，不能算安全负例通过 |
| Docker 仅放宽 seccomp/AppArmor | 仍保留默认 proc masking | `docs/evidence/docker-proc-masked.json`；私有 proc 挂载 EPERM，记为 BLOCKED |

Docker 基础镜像实际来自 `m.daocloud.io/docker.io/library/ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852`；这是 Docker Hub Ubuntu 24.04 的镜像代理来源，固定 digest 记录于 `docker-policy.json`。

验证未改变 VM 全局 sysctl 或 AppArmor 配置。VM 保持 `kernel.unprivileged_userns_clone=1`、`user.max_user_namespaces=15329`、`kernel.apparmor_restrict_unprivileged_userns=1`。Docker 成功配置显式允许 launcher 的 namespace/mount 操作，并解除外层 AppArmor 与 proc 路径遮罩：

```sh
docker run --name tegum-test --user 1000:1000 --cap-drop ALL \
  --security-opt seccomp="$PWD/scripts/docker-seccomp.json" \
  --security-opt apparmor=unconfined \
  --security-opt systempaths=unconfined \
  tegum-validation scripts/validate-linux.sh
```

该容器配置不是 Docker 默认安全配置。`scripts/docker-seccomp.json` 为允许优先的外层策略，仅拒绝其中列明的高风险系统调用；它比 Docker 默认 seccomp 宽。内层 tegum 仍强制自己的 seccomp、namespace、capability 和挂载边界。宿主管理者必须针对用途评估这些外层策略；不能据此声称任意非特权容器均兼容。未使用 `--privileged`、`CAP_SYS_ADMIN`、宿主 PID/net namespace 或宿主 Docker socket 挂载。

## 本次结果

最终源码在两个环境分别通过 **31 项集成检查，0 FAIL、0 BLOCKED**，另通过 proxy unit。两个环境各有 100 次无网启动样本、0 次失败，4 并发共 12 次全部通过。真实 HTTPS allowlist 正例也实际访问成功。

| 指标 | Linux VM | Docker |
|---|---:|---:|
| 100 次启动 median | 11.806 ms | 11.773 ms |
| p95 | 12.482 ms | 12.870 ms |
| 最大值 | 13.721 ms | 29.244 ms |

源码摘要、每项日志、逐次样本和构建二进制摘要见 `docs/evidence/`。原始证据保存在源码仓库，二进制发布包不重复打包这些原始记录。

## 测试语义

`tests/probe.c` 在执行安全探测前打印 `PROBE_EXECUTED`。集成测试同时检查该标记与 `command_started=true`。若负例的命令没有实际执行，则记 `BLOCKED`，脚本返回 2；断言失败记 `FAIL`，返回 1；只有全部检查通过才返回 0。纯配置拒绝和预期启动失败各自单列。

检查项目包括：

- workspace 写入、宿主 secret 不可见、只读系统目录、绝对符号链接及 `..` 路径逃逸。
- 默认清空环境、显式变量、继承 FD 清理，`LD_PRELOAD` 只作用于受限 payload。
- seccomp 和 no_new_privs 已安装；AF_PACKET、AF_VSOCK、raw socket、unshare、clone3、io_uring、keyctl，以及高位 ioctl 参数别名。
- 实际存在的 namespace PID 1、可信 relay 的 `/proc/PID/mem` 和控制 FD 访问拒绝。
- 业务非零退出、stdout/stderr、目标 SIGTERM 与普通 exit 143 的结果区别、超时、SIGTERM 取消。
- setsid 后台后代清理、tegum SIGKILL 后代清理、实际调用方进程退出后取消与清理。
- 不存在的命令、不存在的 cwd、result 写入 workspace 被拒绝。
- 宿主代理和 relay 的主动 SIGKILL 故障注入，执行中错误不伪装成业务成功。
- 真实 HTTPS allowlist 正例、未授权 host、HTTP 非 CONNECT、删除代理配置后的字面 IP 直连。
- 100 次顺序执行，4 个并发任务分 3 轮；每个任务独立 result 文件。

代理 unit 另外验证 IPv4/IPv6 公网地址策略、IP 旧格式与 hostname 校验、CONNECT 请求注入、非法端口、请求体及私网 DNS 目标拒绝。unit 的输出保存在原始日志中。

SIGKILL 无法执行宿主文件清理逻辑，可能保留仅当前用户可访问的 mode 0700 `/tmp/tegum-XXXXXX` 目录。测试将记录这类目录，再清理本次自己产生的目录。它不等同于进程或网络访问权限残留。正常退出、取消、超时和可处理启动失败应清理自己的临时目录。

## 复现

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libseccomp-dev bubblewrap python3 curl ca-certificates
scripts/validate-linux.sh
scripts/validate-docker.sh
```

`validate-linux.sh` 产生环境记录、proxy unit 结果和 `build/integration.json`。加 `--network` 的集成检查依赖外网 `example.com:443`；外网故障应记录真实失败或受阻，不能删掉正例后宣称网络验证完整。

CI覆盖Ubuntu24.04 x86_64和arm64的VM、Docker、打包与artifact保存。首次[远端运行42184102453](https://github.com/earon-han/tegum/actions/runs/42184102453)在两个架构的Linux7.0 Azure runner因AppArmor限制loopback RTM_NEWADDR而BLOCKED；原始记录保存于`docs/evidence/ci-initial/`，未计作安全负例通过，Docker阶段当时未执行。

随后CI增加仅临时runner使用的bwrap限定AppArmor许可，保留全局sysctl原值，配置原文、加载状态和检查值作为artifact保存。重跑结果以实际workflow为准；本地ARM64的两环境结果不依赖此CIprofile。

原始 JSON 带实现源码摘要、二进制 SHA-256、每项 stdout/stderr、CLI result 及每次性能样本；二进制摘要可以对应发布包 manifest，源码树摘要用于追溯。最终结果以原始证据中的 `failed`、`blocked` 字段为准。
