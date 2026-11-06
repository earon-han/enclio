# Docker 完整资源验证：限定配置评审

状态：用户已明确批准，仅限本文所列专用本地Linux测试VM、一次性容器与验证用途。实际执行结果另行记录。

本轮自动审批两次拒绝创建计划中的Docker委派验证脚本。其原因是脚本沿用`apparmor=unconfined`与`systempaths=unconfined`，审核认为用户尚未明确授权这两项容器外层保护例外。既有仓库提交403130b的`validate-docker.sh`和验证报告已记录相同配置，但本轮仍以当前审批结果为准，未通过其他工具或间接执行绕过。

## 已批准的配置范围

| 项目 | 设置与作用 | 影响范围 |
|---|---|---|
| 容器用户 | UID/GID 1000:1000 | Enclio运行时普通用户 |
| capabilities | 删除全部，不使用privileged或添加SYS_ADMIN | 该容器实例 |
| 外层seccomp | 仓库`docker-seccomp.json`，允许初始化namespace/mount并拒绝列明高危接口 | 该容器实例；比Docker默认更宽 |
| AppArmor | `apparmor=unconfined` | 该容器不由Docker默认AppArmor profile约束；不卸载或修改宿主全局AppArmor |
| proc路径遮罩 | `systempaths=unconfined` | 解除该容器默认masked/readonly proc路径，以允许bwrap创建私有proc；不改宿主sysctl |
| 外层资源安全网 | 768MiB内存、256进程、最多2CPU | 同一容器全部进程及内部任务仍受此限制 |
| cgroup委派 | 宿主测试管理员仅委派该容器自身cgroup的子树给UID1000 | 不提供整个宿主cgroup树，内部任务不能迁出容器外层配额 |
| 委派可见性 | 管理员短暂进入该容器的mount/PID namespace，把该容器子树挂入`/run/enclio-cgroup` | 管理员引导操作；不是给容器进程增加能力 |

## 风险、验证与回滚

两项保护例外会减少Docker外层隔离，因此只用于专用本地Linux测试VM内的一次性容器；不能称为默认Docker安全策略下通过，也不能作为未经管理员评估的生产推荐。Enclio自身仍强制seccomp、cap-drop和文件/进程/网络namespace，原始结果必须记录真实容器策略和委派路径。

测试后停止并删除本次容器；其cgroup随Docker/systemd作用域回收，临时mount随容器mount namespace消失。不改Docker daemon配置，不关闭宿主AppArmor/SELinux，不修改全局userns或防火墙设置。默认Docker策略的启动BLOCKED继续单列保留。

用户批准后，验证入口为`scripts/validate-delegated-docker.sh`；需测试VM管理员执行，Enclio实际运行仍为普通UID1000。默认容器下单元/协议测试和默认策略阻断诊断继续保留，不能代替完整Docker沙箱功能验证。
