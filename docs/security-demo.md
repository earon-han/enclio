# Enclio CLI 安全效果示例

> 公开资料说明：本页验证记录中的证据链接现指向脱敏阶段摘要。机器原始日志、JSON、命令和归档已移出公开工作树并私下保留；历史段落中提及的原始文件不随仓库发布，旧原始校验值不适用于摘要。结果与失败状态未因此改变。

这个样例使用合成数据，直接打印每次真正执行的CLI命令，并保存stdout、stderr与可信结果JSON。包含6个有限场景：目录和网络策略、自定义seccomp与rlimit、共享临时盘与导出、进程上限、内存上限、超时、输出预算。长稳验收和自动检查仍暂停。

## 运行

需要支持Enclio的Linux环境、普通用户、bubblewrap/libseccomp、curl、Python3及C编译器。Python是样例调用方的依赖，Enclio本身仍是C二进制。脚本会编译同目录的`security_probe.c`为演示工具。

已经有委派的cgroup v2父目录时，在仓库根目录运行：

```sh
make
python3 examples/security_demo.py \
  --enclio "$PWD/build/enclio" \
  --cgroup-parent "$CG_PARENT" \
  --output "$PWD/build/security-demo-$(date +%s)"
```

也可通过`ENCLIO_CGROUP_PARENT`传入该目录。若未提供有效委派，样例拒绝启动，不会把聚合限制悄悄降级为rlimit。输出目录必须不存在；省略`--output`时自动创建私有临时目录，运行后保留数据供检查。

管理员可以仅给这次示例创建专用委派服务；命令仍以当前普通用户执行：

```sh
sudo systemd-run --wait --pipe --collect \
  --unit="enclio-security-demo-$(date +%s)" \
  --property="User=$(id -un)" --property="Group=$(id -gn)" \
  --property=Delegate=yes --property=MemoryMax=768M \
  --property=TasksMax=256 --property=CPUQuota=200% \
  --working-directory="$PWD" \
  python3 tests/with_delegation.py -- \
  python3 examples/security_demo.py --enclio "$PWD/build/enclio" \
  --output "$PWD/build/security-demo-$(date +%s)"
```

这不会修改宿主全局安全策略；userns/AppArmor等运行条件应事先符合[依赖要求](dependencies.md)。容器内也需要仅限容器自身的正确委派；默认Docker的只读cgroup不能运行完整样例。使用已有批准的容器支持配置，勿把`--privileged`作为替代。

## 第一个场景的核心CLI

脚本会创建`workspace`（工具）、`inputs`（只读数据）、`outputs`（允许持久写入）、`reports`（结果）、未挂载的`private-secret.txt`。下面的`$DEMO`为脚本输出的实际目录：

```sh
enclio run \
  --workspace "$DEMO/workspace" --workspace-mode readonly \
  --mount-ro "$DEMO/inputs:/data/input" \
  --mount-rw "$DEMO/outputs:/data/output" \
  --network isolated --allow example.com:443 \
  --seccomp strict --syscall getppid=errno:42 \
  --env DEMO_MESSAGE=hello-from-caller \
  --cgroup-parent "$CG_PARENT" \
  --memory-bytes 134217728 --pids-max 64 --cpu-percent 50 \
  --cpu-seconds 5 --address-space-bytes 268435456 \
  --file-bytes 65536 --open-files 64 \
  --tmp-bytes 33554432 --output-bytes 8192 --timeout 40 \
  --result "$DEMO/reports/policy.json" \
  -- /workspace/demo-probe check "$DEMO/private-secret.txt"
```

`--allow-host example.com`等价于这里的TCP443授权。`getppid`默认允许，这里覆盖成errno42，工具通过原生`syscall(SYS_getppid)`实际检查，不依赖libc缓存或把启动失败当拒绝通过。

| 实际动作 | 应观察到的效果 |
|---|---|
| 读取`/data/input/message.txt` | 成功，内容为READ_ONLY_INPUT |
| 修改同一文件 | EROFS，宿主文件保持原文 |
| 写`/data/output/result.txt` | 成功，宿主outputs中立即出现文件 |
| 读取未挂载的合成宿主secret路径 | ENOENT，文件不可见 |
| 读取宿主测试环境变量/显式环境变量 | 宿主测试变量不存在，显式DEMO_MESSAGE保留 |
| 调用默认允许的getppid | 返回-1、errno42，证明用户规则覆盖默认允许 |
| 打开过多文件、写单文件超过64KiB | 分别EMFILE、EFBIG；示例主动捕获并验证错误 |
| 查询地址空间和CPU秒数rlimit | 256MiB；CPU soft5/hard6秒（每进程） |
| 通过代理请求`example.org:443` | 明确收到HTTP403，不用任意联网失败冒充白名单拒绝 |
| 绕过代理直连`1.1.1.1:443` | 实际connect返回无路由，使用IP字面量避免DNS失败混淆 |
| curl获取`https://example.com/` | 通过代理完成真实HTTPS请求，文件非空 |

允许的公网正例依赖实际公网连通；失败会让样例FAIL，零自动重试，不标记成安全拒绝通过。`--timeout 40`包括启动和执行，curl预算为30秒。CPU50%表示任务进程树最多约半个CPU的带宽；它和每进程CPU秒数是不同约束。内存/PID/CPU聚合限制的实际配置及事件见JSON的`resources`。

## 其余5个场景与结果

| 场景 | 关键策略 | 预期可信结果 |
|---|---|---|
| managed_disk | tmpfs workspace、8MiB disk、成功后export；不配置额外RW挂载 | 工具写临时盘遇ENOSPC后删除填充文件并正常退出；status=exited/0，export中有answer.txt，宿主原workspace不变 |
| pids | 聚合pids-max16；最多尝试64次fork，回收自己的全部子进程 | EAGAIN及pids_max_events>0；resource_limit/pids，退出126 |
| memory | 聚合memory32MiB；最多申请并触碰128MiB普通页 | oom_kills>0；resource_limit/memory，退出126 |
| timeout | 工具sleep10秒、CLI timeout1秒 | timeout，退出124，工具与后代清理完成 |
| output | 输出最多1MiB的工具、stdout+stderr预算1024字节 | 捕获不超过1024字节；resource_limit/output，退出126 |

只读输入+额外RW输出的首场景不能设置`--disk-bytes`，因为宿主RW目录不属于临时盘总额；因此单独用无RW挂载的managed_disk展示总盘限额。rlimit错误及ENOSPC被工具处理后可以正常退出，不应强行把它们的JSON写成resource_limit。

每个场景都先要求`PROBE_EXECUTED`、`command_started=true`、`cleanup_complete=true`，避免把平台启动拒绝当作payload防护通过。正常/非零退出含义以结果JSON为准，不能只看终端文字。预期的124/126由样例调用方检查后记作对应场景PASS。

运行后查看：

```sh
cat "$DEMO/summary.json"
cat "$DEMO/reports/policy.command.json"   # 实际argv，可复制为CLI
cat "$DEMO/reports/policy.stdout"
cat "$DEMO/reports/memory.json"         # 真实OOM事件
cat "$DEMO/reports/pids.json"           # 真实PID事件
cat "$DEMO/reports/output.json"
```

`summary.json`保存CLI binary及两个样例源文件摘要，所有原始结果不覆盖旧目录。本例不是对恶意宿主同UID进程或内核漏洞的保证；额外目录中的Unix socket仍属于调用方明确授权的IPC，勿暴露其他代理或控制服务来同时声称isolated出口约束。host模式不提供本例的受控出口保证。

## 本轮实测

样例在本地Linux VM与获批委派Docker各一次运行，均6/6场景通过、零自动重试。VM运行时实际读回外层768MiB/256进程/2CPU；Docker使用此前批准的普通UID、cap-drop ALL和专有cgroup委派，未扩大权限。实际命令、6份结果JSON、stdout/stderr、宿主文件效果、源码与binary记录已私下归档，公开结果见[阶段摘要](evidence/security-demo-20261112/README.md)。独立源码及原始数据复核已通过，摘要与原始文件一并归档。

样例输入为`bffcafd05d962f68a790513e567e892acd20f025c83d3045c7ec0d777529be33`（40文件）。生产C执行器本轮没有改动，复用111c69a2阶段已测CLI；此前174项功能结果保留其原输入身份，不因增加样例而重新命名。Docker inspect的OOMKilled=true/退出0原样保留，不据此推断外层OOM没有发生。长期验收仍暂停。
