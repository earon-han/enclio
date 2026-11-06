# 调研、来源与许可证

调研日期：2026-11-06。只参考官方上游实现/文档；以下 tag 或内核版本固定设计依据，部署时仍需采用受维护的补丁版本。

| 来源 | 固定参考 | 借鉴/使用范围 | 许可证/复用方式 |
|---|---|---|---|
| [bubblewrap README v0.11.0](https://github.com/containers/bubblewrap/blob/v0.11.0/README.md) | v0.11.0 | 用户 namespace、从空 root 构造挂载、网络隔离与终端/服务 socket 边界 | 执行外部 bwrap，不复制代码 |
| [bubblewrap 实现](https://github.com/containers/bubblewrap/blob/v0.11.0/bubblewrap.c) | v0.11.0 | 核对选项、PID 1、父进程死亡处理 | 文件 SPDX `LGPL-2.0-or-later`，见 [COPYING](https://github.com/containers/bubblewrap/blob/v0.11.0/COPYING) |
| [libseccomp](https://github.com/seccomp/libseccomp/tree/v2.5.5) | v2.5.5 | 原生 syscall 解析、参数过滤、过滤器加载 | 链接依赖，`LGPL-2.1`，见 [LICENSE](https://github.com/seccomp/libseccomp/blob/v2.5.5/LICENSE) 与各文件声明 |
| [Linux seccomp BPF](https://docs.kernel.org/6.12/userspace-api/seccomp_filter.html) | Linux 6.12 文档 | 过滤器继承、ABI 检查、参数指针不能解引用及其边界 | 文档参考，不复制实现 |
| [Linux user sysctl](https://docs.kernel.org/6.12/admin-guide/sysctl/user.html) | Linux 6.12 文档 | 每用户 namespace 额度及嵌套计费 | 文档参考 |
| [Docker seccomp](https://docs.docker.com/engine/security/seccomp/) | 滚动文档，访问日如上 | 外层默认策略、显式 profile 与 namespace 初始化限制 | 文档参考，需在测试报告固定 Engine/profile |
| [Ubuntu AppArmor](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/) | 滚动文档，访问日如上 | 非特权 userns 的 AppArmor 许可 | 文档参考，需在报告固定发行版/profile |

上游工具的安全属性不能直接视为 Tegum 的属性；Tegum 对传给 bwrap 的参数、代理策略、可信初始化阶段和清理路径负责。项目不引用特定闭源产品作为已核实的实现基线，也不承诺与其安全强度相同。

自主实现部分：CLI/结果契约、挂载策略构造、环境/FD 清理、CONNECT 解析与地址策略、namespace 内 relay、执行管理、测试和验证材料。未从第三方沙箱项目复制代理或启动器代码；若后续引入代码，需要补充其来源、版本和许可证。

此清单是工程依赖记录；实际分发包的第三方材料必须按构建时的真实依赖版本生成，不能用本表代替上游许可证全文或其分发条件。
