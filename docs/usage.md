# 使用指南与 CLI 契约

CLI/JSON 契约版本为 1。目标平台和容器要求见 [dependencies.md](dependencies.md)，实测状态见 [validation.md](validation.md)。以下命令在 Linux 普通用户下运行。

## 安装和探测

Ubuntu 24.04：安装 `build-essential libseccomp-dev bubblewrap ca-certificates curl python3` 后执行 `make`。
开发/测试用到编译器和 Python；运行已构建 CLI 不需要 Python。
`make install PREFIX=$HOME/.local` 安装 CLI。发行包通过 `make package` 构建，校验 `SHA256SUMS` 后解压。
动态链接产物应在兼容 libc/libseccomp 的系统运行，不能跨 CPU 架构使用。

```sh
tegum version
tegum help
tegum doctor
```

`doctor` 真正运行 bubblewrap 和 seccomp 初始化及 `/bin/true`，stdout 为 JSON。
`ready: true` 表示本次基础执行探测成功；不能代替完整安全测试或代理出口验证。
失败时 stderr 保留诊断，退出非零。缺 bwrap/userns/seccomp/AppArmor 权限时不降级运行。

## 命令执行

```sh
mkdir -p /tmp/task
tegum run --workspace /tmp/task --cwd /workspace --timeout 30 \
  --result /tmp/task-result.json --env TASK_NAME=demo \
  -- /bin/sh -c 'printf "%s\n" "$TASK_NAME"; echo done > output.txt'
```

| 参数 | 约定 |
|---|---|
| `--workspace DIR` | 必填，现有目录，经 realpath 解析为 `/workspace`；禁止 `/` |
| `--cwd PATH` | 默认 `/workspace`，使用沙箱内 `/workspace` 或其子目录 |
| `--timeout SECONDS` | 整数 1—86400，默认 300，monotonic wall time |
| `--result FILE` | 可选，宿主普通文件，必须在工作目录以外；拒绝 symlink、多个 hardlink；stdout 不混入 JSON |
| `--env NAME=VALUE` | 可重复，最多 64 项，只传给已安装 seccomp 的目标命令；值可包含空格与 `=` |
| `--allow-host DOMAIN` | 可重复，最多 64 个精确 DNS 名，仅授权公网 TCP 443 CONNECT |
| `-- COMMAND ARGS...` | 必填，直接 exec，不隐式经过 shell；需要 shell 语法请显式 `/bin/sh -c` |

保留命令 stdin/stdout/stderr 三个流。其余继承 FD 均关闭；stdio 禁止使用 socket。
stdio 的普通文件或管道是调用方授权的额外数据能力。沙箱诊断以 `tegum:` 或 `bwrap:` 开头写 stderr，业务 stderr 原样保留，因此单凭前缀不能验证诊断来源，应结合独立 JSON 结果。

环境不继承宿主的 token、SSH_AUTH_SOCK、loader 变量等；可信 init/relay 只使用固定环境。
显式 `--env` 在 seccomp 生效后才用于目标的 exec，所以不会以 `LD_PRELOAD` 注入可信初始化器。
目标默认 `PATH=/usr/local/bin:/usr/bin:/bin`、`HOME=/home/agent`、`TMPDIR=/tmp`、`LANG=C.UTF-8`。
代理开启时提供 `HTTP_PROXY`/`HTTPS_PROXY` 及小写版本 `http://127.0.0.1:18080`、空 `NO_PROXY`。
显式用户变量可以改变目标客户端行为，但无法扩大代理授权或获得外部直连。

仅挂载所需系统目录 `/usr /bin /sbin /lib /lib64`（存在的目录），均只读；最小生成 passwd/group，选择性挂载 CA 和动态加载配置。宿主 home、SSH、Docker socket、整个 `/etc`、`/sys` 不暴露。`/tmp`、`/home`、`/proc`、`/dev` 是隔离视图。系统运行时的内容对命令可读。

## 网络

```sh
tegum run --workspace /tmp/task --allow-host example.com \
  -- curl -fSs --max-time 10 https://example.com
```

域名不允许通配符、IP 字面量、URL、端口或末尾点。DNS 返回的所有地址必须满足公网规则；混入一个禁止地址就拒绝。
代理直接连接已经校验过的 sockaddr，避免检查与连接二次 DNS 解析的差异。
普通 `http://` 请求会失败。重定向到其他域名需要逐个授权；授权域名控制的服务可能转发或存储任务数据，这是授权者需要考虑的边界。
代理每层最多 32 个 worker、头部小于 8192 bytes、请求约 10 秒、空闲约 30 秒、连接寿命最多 300 秒；过载/超时关闭，不回退直连。

## 结果、退出码和取消

```json
{"schema_version":1,"status":"exited","exit_code":0,"signal":0,"duration_ms":25,"command_started":true}
```

| status | 含义 |
|---|---|
| `exited` | 命令实际 exec 成功，`exit_code` 为业务退出结果，含非零值 |
| `setup_error` | bwrap/代理/seccomp/exec 等设施失败；可能在命令开始后发生 |
| `timeout` | 到达期限并已清理，退出 124 |
| `cancelled` | 收到 SIGINT/SIGTERM/SIGHUP，退出 `128 + signal` |

`command_started` 仅在 exec 握手确认成功后为 true；它不证明业务操作本身成功。
`signal` 为实际命令终止或取消信号，正常 `exit 143` 仍为 0；`duration_ms` 含准备与清理时间。
设施失败退出 125，参数错误退出 2。业务也可以退出 124/125/130 等值，调用方必须读取 `status` 区分。
结果路径参数错误或无法打开时没有有效 JSON；结果写入失败会退出 125，调用方必须检查退出状态和 JSON 完整性。
结果文件写入不保证对并发读者原子可见，应等 CLI 退出后读取；不要让不可信外部同 UID 进程修改结果路径。

向 CLI 发送 SIGTERM 可取消任务；完成后才读取结果。默认不使用 SIGKILL，因为 SIGKILL 无法生成完整结果。
执行器 SIGKILL 死亡时 PDEATHSIG 与 PID namespace 链会终止受管进程，但 `/tmp/tegum-*` 私有元数据目录可能遗留；确认无活动任务后可由该用户清理。
调用方死亡会通过 `PR_SET_PDEATHSIG(SIGTERM)` 触发同一取消和清理路径；首版不支持脱离调用方的后台任务模式。Agent 应持有 CLI 并在主动取消时显式发信号。

后台 fork/setsid 后代随本次 PID namespace 结束而终止。首版没有 cgroup CPU/内存/磁盘/进程数配额；应使用外层 VM/容器资源限制，避免耗尽宿主。

## 开发和容器验证

`make unit` 运行代理策略/协议测试；`make test` 运行离线集成测试。
`scripts/validate-linux.sh` 包含真实公网代理、环境记录和重复/并发测试。
安全负例必须包含 `PROBE_EXECUTED`，启动失败记录 BLOCKED；详见验证报告。
Docker 所需的 namespace/AppArmor/seccomp 条件、实测命令与明确放宽的外层权限全部记录在依赖和验证文档中。
