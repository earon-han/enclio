# 委派、容器与持续验证部署

本指南区分普通用户运行、服务管理器/管理员引导和测试证据。能力边界见[dependencies.md](dependencies.md)，命令/结果契约见[usage.md](usage.md)。不要用关闭全局userns防护、停用LSM或特权容器替代兼容配置。

## 选择运行方式

- 只需文件/进程/网络隔离及rlimit：普通用户可在基础doctor通过的Linux直接运行，不要求额外的cgroup parent。
- 需要CPU带宽/内存/PID聚合配额：服务管理器先提供真实委派父目录，CLI以普通用户管理其下任务叶；请求时缺少委派即拒绝。
- 需要宿主原地文件持久变化：使用readwrite，但不能把它称为拥有总磁盘quota。
- 需要有界命名写空间：使用readonly或tmpfs与disk-bytes；后者可在成功后导出到空目录。

监督器和guardian本身留在任务叶之外，应由所属systemd服务/容器的外层限制兜底。不要只限制payload而让大量独立CLI无限并发；宿主调用服务应设置自身并发和整体资源边界。

## Linux VM中的专用用户委派scope

先确认systemd用户管理器可用、所在层级为v2且用户有自己的委派作用域。普通SSH session的任意目录不能自动当成可迁移父组。以下是本地验证采用的scope模式：只在新作用域内把监督shell移到control叶，再启用该作用域的子控制器，不修改app.slice等其他服务父节点。

在仓库目录执行：

```sh
systemd-run --user --scope --quiet \
  -p Delegate=yes -p MemoryMax=805306368 -p TasksMax=256 \
  /bin/sh -c '
    set -eu
    relative=$(sed -n "s/^0:://p" /proc/self/cgroup)
    parent=/sys/fs/cgroup$relative
    mkdir "$parent/control"
    printf "%s\n" "$$" > "$parent/control/cgroup.procs"
    printf "+cpu +memory +pids\n" > "$parent/cgroup.subtree_control"
    ENCLIO_CGROUP_PARENT="$parent" scripts/validate-linux.sh
  '
```

这是专用验证scope，外层768MiB/256任务是主动耗尽负例的安全网。服务退出后由systemd回收该作用域。若用户bus、controller委派或迁移权限不足，应单列BLOCKED并由管理员配置；不要在全局cgroup根上chmod/chown或移动无关进程。

生产服务应由管理员设计Delegate与外层CPU/Memory/TasksMax策略，遵循单一管理者和无内层进程规则。CLI只创建自己的随机叶，不承担通用服务管理器职责。可先执行`enclio doctor --cgroup-parent "$CG_PARENT"`验证基础执行与请求的三类聚合限制。

## Docker验证和批准范围

本轮用户批准的例外限于专用本地Linux测试VM中的指定验证容器，具体配置、风险和回滚见[deployment-validation-review.md](deployment-validation-review.md)。这种批准不代表生产部署普遍允许放宽外层策略。

基础容器测试以UID/GID1000:1000、cap-drop ALL运行，不使用privileged、SYS_ADMIN、宿主PID/net或Docker socket。外层seccomp为仓库明确profile；AppArmor与proc遮罩例外仅作用于容器实例。默认策略诊断应保留，启动BLOCKED不计作安全负例通过。原有`scripts/validate-docker.sh`可复现其所包含的基础流程，是否包含最新聚合验证需以脚本当前内容和实际结果为准。

完整聚合验证需要管理员只委派运行中容器**自己的**cgroup子树：将其中的监督进程移到control叶，启用所需子控制器、赋予容器普通UID该子树的必要权限，并使该子树在容器命名空间内可见。管理员的限定引导与容器进程拥有SYS_ADMIN是不同操作。不得把任务迁出容器作用域，不得给容器整个宿主cgroup树的可写访问。

验证容器外层还设置768MiB内存、256进程和2CPU安全网。引导记录需包含容器ID、实际cgroup路径、scope归属、mount可见性、有效UID/capabilities和外层配额；测试后停止删除该容器，cgroup及临时mount随其作用域/命名空间回收。不能更改Docker daemon、宿主sysctl、全局AppArmor/SELinux或防火墙。

本轮完整引导入口为`scripts/validate-delegated-docker.sh`，需要在获批准的Linux测试VM由管理员执行：

```sh
sudo scripts/validate-delegated-docker.sh
# 若管理员批准的环境需要显式基础镜像或镜像源：
sudo env ENCLIO_BASE_IMAGE=ubuntu:24.04 ENCLIO_TEST_IMAGE=enclio-delegated-validation \
  scripts/validate-delegated-docker.sh
# 仅复用刚构建、已核对同源的测试镜像时：
sudo ENCLIO_SKIP_BUILD=1 ENCLIO_TEST_IMAGE=enclio-delegated-validation \
  scripts/validate-delegated-docker.sh
```

它创建一次性容器、定位并只委派其自身作用域。引导先确认该容器拥有独立cgroup namespace，否则拒绝；管理员进入该容器mount/PID/cgroup namespace建立新的cgroup2挂载到`/run/enclio-cgroup`，由内核把可见根裁剪到本容器作用域，不能看到可写宿主祖先。最后由原来的普通用户等待进程运行全套。它不使用后续docker exec把新进程放回已启用domain controller的空父组。日志、inspect、委派路径和测试JSON按每次运行保存在`build/delegated-docker/enclio-delegated-PID/`；退出时清理本次容器。脚本存在不代表本轮已经通过，实际结果由[validation.md](validation.md)记录。

## 长时间运行

`scripts/soak.py`默认真实86400秒、每30秒4并发，混合shell、tmpfs导出、输出触限和Python线程；默认每4轮再运行完整production-timing受控网络suite，不缩短协议时限。每轮写JSONL并fsync，记录源码/二进制身份、UTC和requested/observed seconds。长运行还核对最小轮数（预期的90%）、最大间隔及尾段覆盖；只经历很长墙钟、却因暂停漏掉大部分样本不能complete。源码或二进制改变、失败、中断和残留同样不能标完成。

下面的命令创建专属用户服务，使运行能持续到终端退出之后；需先确保用户管理器有对应权限，并为每次run选择新的unit和输出目录：

```sh
systemd-run --user --unit=enclio-soak-vm \
  -p Delegate=yes -p MemoryMax=805306368 -p TasksMax=256 \
  --working-directory="$PWD" \
  /usr/bin/python3 "$PWD/scripts/soak.py" --binary "$PWD/build/enclio" \
  --duration 86400 --interval 30 --workers 4 --prepare-delegation \
  --output "$PWD/build/soak-vm"
```

`--prepare-delegation`只用于该专属已委派服务：脚本发现自己的作用域，把自己移到control叶，再启用父控制器；不与`--cgroup-parent`同时使用。已有服务提供parent时可改用后者。未请求aggregate会在metadata中明示，不能把该结果算作聚合配额长稳验收。

已批准的同一容器引导可用soak动作，保持其普通用户、委派根和外层配额：

```sh
sudo env ENCLIO_TEST_ACTION=soak ENCLIO_SOAK_SECONDS=86400 \
  scripts/validate-delegated-docker.sh
```

复用镜像时同样必须先核对同源身份并显式给出ENCLIO_TEST_IMAGE/ENCLIO_SKIP_BUILD；不要为了追求同名产物复用过期二进制。Docker长稳需在同一受控容器子树及外层配额下单独跑满；VM结果不代替容器结果。短时试跑可检查脚本，但不能替代承诺的24小时。原始metadata/samples/summary必须保留；进程仍在运行或summary.complete为false时，不宣布完成。

## 诊断顺序

1. 确认以普通用户运行且bwrap/libseccomp/解释器存在，执行基础doctor。
2. 检查userns额度、AppArmor/SELinux/audit及外层seccomp的具体拒绝；不要先全局降级。
3. 单独检查委派parent的v2类型、控制器、所有权、迁移和cgroup.kill能力；仅“目录可读”不够。
4. 阅读独立JSON的status、limit_reason、command_started和cleanup_complete，区分业务失败、触限和设施失败。
5. 对启动失败单列BLOCKED，再修配置后重新执行真正payload；保留失败记录，不改写历史日志。
