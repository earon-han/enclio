# 资源引擎接口与假设

资源模块为`src/resources.c/.h`，执行器负责解析CLI、把配置传入目标初始化器、启动前加入cgroup、选择结果状态以及安装后的清理。模块不修改主机sysctl，不自动启用其他服务的cgroup控制器，也不使用RLIMIT_NPROC冒充每任务进程限制。

## 聚合限制与普通用户委派

`enclio_resources_prepare(parent,limits,handle,error,size)`要求调用方提供真实cgroup v2目录；父级必须已经启用所需cpu/memory/pids控制器。模块创建随机`enclio-PID-RANDOM`叶节点，设置请求的`memory.max`、`memory.swap.max=0`、`memory.oom.group=1`、`pids.max`和`cpu.max`。`cpu_percent=100`表示一个CPU的带宽，周期固定100000微秒。内存字节数必须是系统PAGE_SIZE整数倍，避免内核向上取整超过请求。

未请求聚合限制、也未提供parent时模块不创建cgroup。请求任何聚合限制而缺少委派、控制器、可写文件或原子终止接口时拒绝，绝不降级成无约束执行。仅提供parent也会创建受管cgroup供树级清理。支持要求包含`cgroup.kill`能力；不能仅凭一个内核版本字符串判断。

宿主supervisor与清理守护进程应留在任务cgroup外，防止OOM时失去清理能力。bwrap子进程和宿主proxy子进程都应在创建后代前调用`enclio_resources_enter`，所有后代继承同一组。控制FD是CLOEXEC，并在目标执行前关闭；cgroup目录绝不挂载给payload。

普通SSH session通常不在用户委派子树，不能假定能够把进程迁入用户service的cgroup。可由服务管理器启动委派scope，并在该任务专用scope中把supervisor移动到control叶后为父启用控制器，再使用另一个workload叶。模块本身不自动执行这种服务配置。Docker必须委派容器自身的子树；把payload迁移到容器外的host子树可能逃离外层容器配额，不是等价安全配置。

## 统计与清理

`enclio_resources_stats`读取cpu usage/throttled、memory current/peak/max事件/OOM kill、pids current/peak/max事件。peak接口可能随内核不同而缺少，由available标记说明；计数器不是单凭业务退出码推断。

`enclio_resources_cleanup`调用`cgroup.kill`，在有界等待内检查`populated=0`，然后移除本任务叶。未能杀净或移除返回错误，执行器不能把它报告成清理成功。句柄先由prepare初始化，或显式将parent_fd/group_fd初始化为-1，避免早退路径误关闭调用方FD。

## 逐进程rlimit

`enclio_resources_apply_rlimits`在目标exec前设置CPU时间及hard address-space bytes、individual-file bytes和open-file count，并关闭core dump。CPU soft=N秒、hard=N+1秒；内核按秒粒度记账，默认在soft处发送SIGXCPU，目标忽略/处理它继续运行则hard处SIGKILL，不能宣称严格在N秒完成无超差终止。CPU seconds是逐进程CPU时间，AS是逐进程虚拟地址空间，FSIZE是单文件大小；它们不等于整棵进程树CPU/RSS/持久文件系统总quota。硬上限不可由无特权目标抬高。聚合限制必须通过cgroup，不能悄悄用这些逐进程限制替代。

## 工作目录复制与导出

`enclio_workspace_copy(source,destination,...)`和`enclio_workspace_export(source,preopened_destination_dirfd,...)`只复制普通文件、目录和符号链接。目录遍历使用相对FD和NOFOLLOW；普通文件写入使用O_EXCL，不合并/覆盖已有目标节点，尤其不会跟随已有目标symlink。特殊文件、过深目录和碰撞均失败。文件不保留setuid/setgid、owner、xattr或硬链接拓扑；符号链接作为不可信数据原样复制，绝不追踪它来读取或写入宿主路径。

复制/导出最多65536个节点、深度128。复制按目标文件系统总容量，导出按源文件系统总容量限制全树逻辑内容字节；每个文件在创建目标前检查逻辑大小，读写时继续扣总预算。巨大稀疏文件不能经导出稠密化后无限消耗宿主磁盘，超预算直接拒绝。此内容字节预算不等于给宿主目标文件系统施加精确物理块/inode quota。

导出前可信init必须停止并回收其余payload后代，避免导出时被后台进程并发修改。失败可能已留下先前完整复制的节点，不提供整棵树事务语义；当前失败的普通文件会移除。结果中的export状态必须如实反映失败。原地宿主RW目录的严格总磁盘quota仍需要管理员提供的文件系统边界，FSIZE不提供该保证。

## 自验证证据

严格GCC编译通过。资源单测在本地Linux VM普通用户实际验证了AS分配失败、FSIZE写入EFBIG、NOFILE的EMFILE、安全复制/导出和碰撞拒绝，以及缺少委派时fail closed。临时用户systemd委派scope中实际验证pids=8触发fork EAGAIN、CPU25%产生throttle、16MiB memory触发OOM SIGKILL、原子清理及叶目录移除。最终整体验证结果应以独立测试Agent的VM和Docker报告为准，不把这些模块级测试替代两环境集成验收。
