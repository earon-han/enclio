# 来源、协议与许可证

日期：2026-11-06；版本`0.2.0-preview.1`。只参考上游官方实现/文档。固定tag/内核文档用于可追溯设计，不建议部署停留在旧安全补丁；滚动文档的实际能力仍需由目标环境验证。

| 来源 | 固定参考或访问日 | 本项目用途与复用方式 |
|---|---|---|
| [bubblewrap README](https://github.com/containers/bubblewrap/blob/v0.11.0/README.md) | v0.11.0 | namespace、空根挂载和服务socket边界；作为外部执行依赖 |
| [bubblewrap源码](https://github.com/containers/bubblewrap/blob/v0.11.0/bubblewrap.c) | v0.11.0 | 核对选项/PID1/父死亡机制，不复制代码；[COPYING](https://github.com/containers/bubblewrap/blob/v0.11.0/COPYING)及文件SPDX为LGPL-2.0-or-later |
| [libseccomp](https://github.com/seccomp/libseccomp/tree/v2.5.5) | v2.5.5 | native syscall/参数规则与过滤器加载，动态链接依赖；[LICENSE](https://github.com/seccomp/libseccomp/blob/v2.5.5/LICENSE)及各文件声明 |
| [Linux seccomp BPF](https://docs.kernel.org/6.12/userspace-api/seccomp_filter.html) | Linux6.12文档 | ABI、继承、参数指针及过滤器边界，文档参考 |
| [Linux asm-generic syscall UAPI](https://github.com/torvalds/linux/blob/v6.8/include/uapi/asm-generic/unistd.h) | Linux v6.8 | 核对arm64采用的fchmodat2编号452，作为名称库缺失时的拒绝规则依据；不提升运行内核下限 |
| [Linux x86-64 syscall表](https://github.com/torvalds/linux/blob/v6.8/arch/x86/entry/syscalls/syscall_64.tbl) | Linux v6.8 | 独立核对x86_64 native ABI的fchmodat2编号452 |
| [Linux user sysctl](https://docs.kernel.org/6.12/admin-guide/sysctl/user.html) | Linux6.12文档 | namespace额度/嵌套限制，文档参考 |
| [Linux cgroup v2](https://docs.kernel.org/6.12/admin-guide/cgroup-v2.html) | Linux6.12文档 | 控制器、委派、计费、事件和原子终止，文档参考 |
| [systemd cgroup delegation](https://systemd.io/CGROUP_DELEGATION/) | 官方滚动文档，2026-11-06 | 服务管理器委派与层级管理，实际版本另记环境报告 |
| [Linux pidfd_open](https://man7.org/linux/man-pages/man2/pidfd_open.2.html) | Linux man-pages，2026-11-06 | flags=0的进程身份/生命周期，与线程pidfd区别 |
| [Linux pidfd_send_signal](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html) | Linux man-pages，2026-11-06 | 经稳定进程引用发取消/终止信号，避免PID重用 |
| [Linux PR_SET_PDEATHSIG](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html) | Linux man-pages，2026-11-06 | 创建线程死亡语义；限内部受控单线程树使用 |
| [Linux getrlimit](https://man7.org/linux/man-pages/man2/getrlimit.2.html) | Linux man-pages，2026-11-06 | CPU/AS/FSIZE/NOFILE的作用粒度和信号，文档参考 |
| [Linux signal](https://man7.org/linux/man-pages/man7/signal.7.html)、[execve](https://man7.org/linux/man-pages/man2/execve.2.html) | Linux man-pages，2026-11-06 | 启动线程mask与忽略设置跨exec保留、Linux对SIGCHLD的处理；作为管理链显式初始化的依据 |
| [Linux FS_IOC_SETFLAGS](https://man7.org/linux/man-pages/man2/FS_IOC_SETFLAGS.2const.html) | Linux man-pages，2026-11-06 | inode flags的查询/修改及所有者权限；结合只读FD独立复现，说明transport需整体拒绝ioctl的原因 |
| [HTTP/1.1 RFC9112](https://www.rfc-editor.org/rfc/rfc9112.html) | RFC9112 | 请求格式、目标和framing，协议参考 |
| [HTTP语义 RFC9110](https://www.rfc-editor.org/rfc/rfc9110.html) | RFC9110 | Host、CONNECT、代理和响应，协议参考 |
| [SOCKS5 RFC1928](https://www.rfc-editor.org/rfc/rfc1928.html) | RFC1928 | NOAUTH与DOMAIN CONNECT子集，协议参考 |
| [Docker seccomp](https://docs.docker.com/engine/security/seccomp/) | 官方滚动文档，2026-11-06 | 默认限制与显式profile，实际Engine/profile写入验证报告 |
| [Docker Ubuntu rootless提示](https://docs.docker.com/engine/security/rootless/troubleshoot/) | 官方滚动文档，2026-11-06 | 按应用授予AppArmor userns许可形式，非生产通用配置 |
| [Ubuntu AppArmor](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/) | 官方滚动文档，2026-11-06 | 发行版LSM/userns限制与管理员配置，文档参考 |

Enclio对传给bwrap的参数、代理端点策略、可信初始化、cgroup接入、FD和清理路径负责；上游工具的属性不自动成为本项目整体安全保证。不引用闭源产品作为已核实实现基线，也不承诺同等安全强度。

自主实现包括CLI/JSON、挂载与有界工作区、环境/FD、HTTP/CONNECT/SOCKS解析和地址检查、relay、cgroup/rlimit接口、guardian/I/O执行管理、安全复制/导出及测试。未从第三方沙箱复制启动器或代理实现；后续引入代码需记录版本、来源与许可证。协议按选定子集自主实现，无复制RFC代码组件。

项目原始实现按根目录LICENSE发布。此表不能替代实际分发内容的第三方许可证、源码获取或适用的重链接材料；若开始分发bwrap/libseccomp二进制或做静态包，须按实际版本补齐。最终支持和完成状态以真实验证记录为准。
