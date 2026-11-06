#define _GNU_SOURCE
#include "enclio.h"
#include <errno.h>
#include <seccomp.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>

/* Overrides are resolved before either filter is loaded: stacked seccomp
 * filters cannot loosen an earlier denial. Later duplicate rules win. */
static int override_index(const struct enclio_seccomp_rule *rules, size_t count, int nr)
{
    for (size_t i = count; i > 0; --i)
        if (rules[i - 1].syscall_nr == nr)
            return (int)(i - 1);
    return -1;
}
static int action_valid(unsigned action)
{
    return action == SCMP_ACT_ALLOW || action == SCMP_ACT_KILL_PROCESS ||
           ((action & 0xffff0000U) == SCMP_ACT_ERRNO(0) &&
            (action & 0xffffU) > 0 && (action & 0xffffU) <= 4095);
}
static int native_syscall(int nr)
{
    if (nr < 0)
        return 0;
    char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, nr);
    if (!name)
        return 0;
    free(name);
    return 1;
}
int enclio_seccomp_rule_parse(const char *text, struct enclio_seccomp_rule *rule)
{
    if (!text || !rule)
        return -1;
    const char *equal = strchr(text, '=');
    if (!equal || equal == text || (size_t)(equal - text) >= 64)
        return -1;
    char name[64];
    memcpy(name, text, (size_t)(equal - text));
    name[equal - text] = 0;
    int nr = seccomp_syscall_resolve_name_arch(SCMP_ARCH_NATIVE, name);
    if (!native_syscall(nr))
        return -1;
    const char *policy = equal + 1;
    unsigned action;
    if (!strcmp(policy, "allow")) action = SCMP_ACT_ALLOW;
    else if (!strcmp(policy, "deny")) action = SCMP_ACT_ERRNO(EPERM);
    else if (!strcmp(policy, "kill")) action = SCMP_ACT_KILL_PROCESS;
    else if (!strncmp(policy, "errno:", 6)) {
        const char *number = policy + 6;
        if (!*number) return -1;
        unsigned code = 0;
        for (const char *p = number; *p; ++p) {
            if (*p < '0' || *p > '9') return -1;
            code = code * 10 + (unsigned)(*p - '0');
            if (code > 4095) return -1;
        }
        if (!code) return -1;
        action = SCMP_ACT_ERRNO(code);
    } else return -1;
    rule->syscall_nr = nr;
    rule->action = action;
    return 0;
}
static int add_overrides(scmp_filter_ctx ctx, const struct enclio_seccomp_rule *rules,
                         size_t count, unsigned default_action)
{
    for (size_t i = 0; i < count; ++i) {
        if (override_index(rules, count, rules[i].syscall_nr) != (int)i ||
            rules[i].action == default_action)
            continue;
        if (seccomp_rule_add(ctx, rules[i].action, rules[i].syscall_nr, 0) < 0)
            return -1;
    }
    return 0;
}

/* Namespace isolation supplies the network/filesystem boundary. This denylist
 * reduces kernel attack surface; it is deliberately not a syscall allowlist. */
int enclio_install_seccomp_rules(int strict, const struct enclio_seccomp_rule *rules, size_t count)
{
    if (count > ENCLIO_SECCOMP_RULE_MAX || (count && !rules))
        return -1;
    for (size_t i = 0; i < count; ++i)
        if (!native_syscall(rules[i].syscall_nr) || !action_valid(rules[i].action))
            return -1;
    static const char *const denied[] = {"mount",
                                         "umount2",
                                         "pivot_root",
                                         "chroot",
                                         "unshare",
                                         "setns",
                                         "clone3",
                                         "ptrace",
                                         "process_vm_readv",
                                         "process_vm_writev",
                                         "bpf",
                                         "perf_event_open",
                                         "userfaultfd",
                                         "keyctl",
                                         "add_key",
                                         "request_key",
                                         "kexec_load",
                                         "kexec_file_load",
                                         "reboot",
                                         "init_module",
                                         "finit_module",
                                         "delete_module",
                                         "swapon",
                                         "swapoff",
                                         "open_by_handle_at",
                                         "name_to_handle_at",
                                         "io_uring_setup",
                                         "io_uring_enter",
                                         "io_uring_register",
                                         "fanotify_init",
                                         "fsopen",
                                         "fsconfig",
                                         "fsmount",
                                         "move_mount",
                                         "open_tree",
                                         "mount_setattr",
                                         "pidfd_getfd",
                                         "iopl",
                                         "ioperm",
                                         "acct",
                                         "quotactl",
                                         "sethostname",
                                         "setdomainname"};
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx)
        return -1;
    /* Do not permit compatibility ABIs to bypass native syscall rules. */
    if (seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS) < 0)
        goto fail;
    for (unsigned i = 0; i < sizeof(denied) / sizeof(denied[0]); i++) {
        int nr = seccomp_syscall_resolve_name(denied[i]);
        if (nr == __NR_SCMP_ERROR || override_index(rules, count, nr) >= 0)
            continue;
        unsigned action =
            !strcmp(denied[i], "clone3") ? SCMP_ACT_ERRNO(ENOSYS) : SCMP_ACT_ERRNO(EPERM);
        if (seccomp_rule_add(ctx, action, nr, 0) < 0)
            goto fail;
    }
    /* clone remains available for threads/processes, never new namespaces. */
    const unsigned long namespaces = 0x00020000UL | 0x02000000UL | 0x04000000UL | 0x08000000UL |
                                     0x10000000UL | 0x20000000UL | 0x40000000UL | 0x00000080UL;
    for (unsigned long bit = 1; bit; bit <<= 1) {
        if (override_index(rules, count, SCMP_SYS(clone)) < 0 &&
            (namespaces & bit) && seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1,
                                                   SCMP_A0(SCMP_CMP_MASKED_EQ, bit, bit)) < 0)
            goto fail;
    }
    /* Only UNIX and namespace-local IP sockets are required by workloads. */
    for (int family = 0; family < AF_MAX; family++) {
        if (override_index(rules, count, SCMP_SYS(socket)) >= 0 ||
            family == AF_UNIX || family == AF_INET || family == AF_INET6)
            continue;
        if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
                             SCMP_A0(SCMP_CMP_EQ, family)) < 0)
            goto fail;
    }
    if ((override_index(rules, count, SCMP_SYS(socket)) < 0 &&
         seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
                          SCMP_A0(SCMP_CMP_GE, AF_MAX)) < 0) ||
        (override_index(rules, count, SCMP_SYS(socketpair)) < 0 &&
         seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socketpair), 1,
                          SCMP_A0(SCMP_CMP_NE, AF_UNIX)) < 0) ||
        (override_index(rules, count, SCMP_SYS(socket)) < 0 &&
         seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
                          SCMP_A1(SCMP_CMP_MASKED_EQ, 0xf, SOCK_RAW)) < 0))
        goto fail;
    if (override_index(rules, count, SCMP_SYS(ioctl)) < 0 &&
        (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 1,
                         SCMP_A1(SCMP_CMP_MASKED_EQ, 0xffffffffUL, 0x5412)) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 1,
                         SCMP_A1(SCMP_CMP_MASKED_EQ, 0xffffffffUL, 0x541c)) < 0))
        goto fail;
    /* HugeTLB allocations may be outside memory.max accounting on hosts that
     * have not opted into its accounting. Do not expose that bypass. */
    if ((override_index(rules, count, SCMP_SYS(memfd_create)) < 0 &&
         seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(memfd_create), 1,
                         SCMP_A1(SCMP_CMP_MASKED_EQ, 4, 4)) < 0) ||
        (override_index(rules, count, SCMP_SYS(shmget)) < 0 &&
         seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(shmget), 1,
                         SCMP_A2(SCMP_CMP_MASKED_EQ, 0x800, 0x800)) < 0))
        goto fail;
    const char *maps[] = {"mmap", "mmap2"};
    for (unsigned i = 0; i < 2; i++) {
        int nr = seccomp_syscall_resolve_name(maps[i]);
        if (nr != __NR_SCMP_ERROR && override_index(rules, count, nr) < 0 &&
            seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), nr, 1,
                             SCMP_A3(SCMP_CMP_MASKED_EQ, 0x40000, 0x40000)) < 0)
            goto fail;
    }
    /* In strict mode defer custom actions to the final filter: a custom
     * denial of seccomp/prctl must not block installing that final policy. */
    if ((!strict && add_overrides(ctx, rules, count, SCMP_ACT_ALLOW)) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 || seccomp_load(ctx) < 0)
        goto fail;
    seccomp_release(ctx);
    if (!strict)
        return 0;
    /* Intersect the compatibility denylist with an explicit native allowlist.
     * Keeping separate filters retains argument checks without duplicate rules. */
    static const char *const allowed[] = {"read",
                                          "write",
                                          "readv",
                                          "writev",
                                          "pread64",
                                          "pwrite64",
                                          "preadv",
                                          "pwritev",
                                          "preadv2",
                                          "pwritev2",
                                          "close",
                                          "close_range",
                                          "lseek",
                                          "stat",
                                          "fstat",
                                          "lstat",
                                          "newfstatat",
                                          "statx",
                                          "statfs",
                                          "fstatfs",
                                          "access",
                                          "faccessat",
                                          "faccessat2",
                                          "open",
                                          "openat",
                                          "openat2",
                                          "readlink",
                                          "readlinkat",
                                          "getdents",
                                          "getdents64",
                                          "fcntl",
                                          "flock",
                                          "dup",
                                          "dup2",
                                          "dup3",
                                          "pipe",
                                          "pipe2",
                                          "poll",
                                          "ppoll",
                                          "select",
                                          "pselect6",
                                          "epoll_create",
                                          "epoll_create1",
                                          "epoll_ctl",
                                          "epoll_wait",
                                          "epoll_pwait",
                                          "epoll_pwait2",
                                          "signalfd",
                                          "signalfd4",
                                          "eventfd",
                                          "eventfd2",
                                          "timerfd_create",
                                          "timerfd_settime",
                                          "timerfd_gettime",
                                          "inotify_init",
                                          "inotify_init1",
                                          "inotify_add_watch",
                                          "inotify_rm_watch",
                                          "mmap",
                                          "mmap2",
                                          "mprotect",
                                          "pkey_mprotect",
                                          "munmap",
                                          "mremap",
                                          "msync",
                                          "mincore",
                                          "madvise",
                                          "brk",
                                          "shmget",
                                          "shmat",
                                          "shmdt",
                                          "shmctl",
                                          "semget",
                                          "semctl",
                                          "semop",
                                          "semtimedop",
                                          "msgget",
                                          "msgctl",
                                          "msgsnd",
                                          "msgrcv",
                                          "execve",
                                          "execveat",
                                          "exit",
                                          "exit_group",
                                          "clone",
                                          "fork",
                                          "vfork",
                                          "wait4",
                                          "waitid",
                                          "kill",
                                          "tkill",
                                          "tgkill",
                                          "pidfd_open",
                                          "pidfd_send_signal",
                                          "rt_sigaction",
                                          "rt_sigprocmask",
                                          "rt_sigpending",
                                          "rt_sigreturn",
                                          "rt_sigsuspend",
                                          "rt_sigtimedwait",
                                          "rt_sigqueueinfo",
                                          "rt_tgsigqueueinfo",
                                          "sigaltstack",
                                          "restart_syscall",
                                          "clock_gettime",
                                          "clock_getres",
                                          "clock_nanosleep",
                                          "gettimeofday",
                                          "time",
                                          "times",
                                          "getrusage",
                                          "nanosleep",
                                          "alarm",
                                          "setitimer",
                                          "getitimer",
                                          "timer_create",
                                          "timer_delete",
                                          "timer_getoverrun",
                                          "timer_gettime",
                                          "timer_settime",
                                          "futex",
                                          "futex_waitv",
                                          "set_tid_address",
                                          "set_robust_list",
                                          "get_robust_list",
                                          "rseq",
                                          "arch_prctl",
                                          "set_thread_area",
                                          "get_thread_area",
                                          "sched_yield",
                                          "sched_getaffinity",
                                          "sched_setaffinity",
                                          "sched_getparam",
                                          "sched_setparam",
                                          "sched_getscheduler",
                                          "sched_setscheduler",
                                          "sched_get_priority_max",
                                          "sched_get_priority_min",
                                          "sched_rr_get_interval",
                                          "getpriority",
                                          "setpriority",
                                          "nice",
                                          "getuid",
                                          "geteuid",
                                          "getgid",
                                          "getegid",
                                          "getresuid",
                                          "getresgid",
                                          "getgroups",
                                          "setuid",
                                          "setgid",
                                          "setresuid",
                                          "setresgid",
                                          "getpid",
                                          "getppid",
                                          "gettid",
                                          "getpgrp",
                                          "getpgid",
                                          "setpgid",
                                          "setsid",
                                          "getsid",
                                          "uname",
                                          "sysinfo",
                                          "prlimit64",
                                          "getrlimit",
                                          "setrlimit",
                                          "prctl",
                                          "seccomp",
                                          "capget",
                                          "capset",
                                          "umask",
                                          "chdir",
                                          "fchdir",
                                          "getcwd",
                                          "creat",
                                          "mkdir",
                                          "mkdirat",
                                          "rmdir",
                                          "rename",
                                          "renameat",
                                          "renameat2",
                                          "link",
                                          "linkat",
                                          "unlink",
                                          "unlinkat",
                                          "symlink",
                                          "symlinkat",
                                          "chmod",
                                          "fchmod",
                                          "fchmodat",
                                          "fchmodat2",
                                          "chown",
                                          "lchown",
                                          "fchown",
                                          "fchownat",
                                          "utime",
                                          "utimes",
                                          "futimesat",
                                          "utimensat",
                                          "getxattr",
                                          "lgetxattr",
                                          "fgetxattr",
                                          "setxattr",
                                          "lsetxattr",
                                          "fsetxattr",
                                          "listxattr",
                                          "llistxattr",
                                          "flistxattr",
                                          "removexattr",
                                          "lremovexattr",
                                          "fremovexattr",
                                          "truncate",
                                          "ftruncate",
                                          "fsync",
                                          "fdatasync",
                                          "readahead",
                                          "fadvise64",
                                          "fallocate",
                                          "copy_file_range",
                                          "sendfile",
                                          "splice",
                                          "tee",
                                          "vmsplice",
                                          "ioctl",
                                          "socket",
                                          "socketpair",
                                          "connect",
                                          "bind",
                                          "listen",
                                          "accept",
                                          "accept4",
                                          "shutdown",
                                          "getsockname",
                                          "getpeername",
                                          "getsockopt",
                                          "setsockopt",
                                          "sendto",
                                          "recvfrom",
                                          "sendmsg",
                                          "recvmsg",
                                          "sendmmsg",
                                          "recvmmsg",
                                          "getrandom",
                                          "memfd_create"};
    ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if (!ctx)
        return -1;
    if (seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS) < 0)
        goto fail;
    for (unsigned i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) {
        int nr = seccomp_syscall_resolve_name(allowed[i]);
        if (nr != __NR_SCMP_ERROR && override_index(rules, count, nr) < 0 &&
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0) < 0)
            goto fail;
    }
    if ((override_index(rules, count, SCMP_SYS(clone3)) < 0 &&
         seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0) < 0) ||
        add_overrides(ctx, rules, count, SCMP_ACT_ERRNO(EPERM)) || seccomp_load(ctx) < 0)
        goto fail;
    seccomp_release(ctx);
    return 0;
fail:
    seccomp_release(ctx);
    return -1;
}

int enclio_install_seccomp(int strict)
{
    return enclio_install_seccomp_rules(strict, NULL, 0);
}
