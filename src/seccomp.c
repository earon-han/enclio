#define _GNU_SOURCE
#include "tegum.h"
#include <errno.h>
#include <seccomp.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>

/* Namespace isolation supplies the network/filesystem boundary. This denylist
 * reduces kernel attack surface; it is deliberately not a syscall allowlist. */
int tg_install_seccomp(void)
{
    static const char *const denied[] = {
        "mount", "umount2", "pivot_root", "chroot", "unshare", "setns",
        "clone3", "ptrace", "process_vm_readv", "process_vm_writev",
        "bpf", "perf_event_open", "userfaultfd", "keyctl", "add_key",
        "request_key", "kexec_load", "kexec_file_load", "reboot",
        "init_module", "finit_module", "delete_module", "swapon", "swapoff",
        "open_by_handle_at", "name_to_handle_at", "io_uring_setup",
        "io_uring_enter", "io_uring_register", "fanotify_init",
        "fsopen", "fsconfig", "fsmount", "move_mount", "open_tree",
        "mount_setattr", "pidfd_getfd", "iopl", "ioperm", "acct",
        "quotactl", "sethostname", "setdomainname"
    };
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) return -1;
    /* Do not permit compatibility ABIs to bypass native syscall rules. */
    if (seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS) < 0)
        goto fail;
    for (unsigned i = 0; i < sizeof(denied) / sizeof(denied[0]); i++) {
        int nr = seccomp_syscall_resolve_name(denied[i]);
        if (nr == __NR_SCMP_ERROR) continue;
        unsigned action = !strcmp(denied[i], "clone3") ?
                          SCMP_ACT_ERRNO(ENOSYS) : SCMP_ACT_ERRNO(EPERM);
        if (seccomp_rule_add(ctx, action, nr, 0) < 0) goto fail;
    }
    /* clone remains available for threads/processes, never new namespaces. */
    const unsigned long namespaces = 0x00020000UL | 0x02000000UL |
        0x04000000UL | 0x08000000UL | 0x10000000UL | 0x20000000UL |
        0x40000000UL | 0x00000080UL;
    for (unsigned long bit = 1; bit; bit <<= 1) {
        if ((namespaces & bit) && seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
            SCMP_SYS(clone), 1, SCMP_A0(SCMP_CMP_MASKED_EQ, bit, bit)) < 0)
            goto fail;
    }
    /* Only UNIX and namespace-local IP sockets are required by workloads. */
    for (int family = 0; family < AF_MAX; family++) {
        if (family == AF_UNIX || family == AF_INET || family == AF_INET6) continue;
        if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
                            SCMP_A0(SCMP_CMP_EQ, family)) < 0) goto fail;
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
                        SCMP_A0(SCMP_CMP_GE, AF_MAX)) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socketpair), 1,
                        SCMP_A0(SCMP_CMP_NE, AF_UNIX)) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
                        SCMP_A1(SCMP_CMP_MASKED_EQ, 0xf, SOCK_RAW)) < 0)
        goto fail;
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 1,
                        SCMP_A1(SCMP_CMP_MASKED_EQ, 0xffffffffUL, 0x5412)) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 1,
                        SCMP_A1(SCMP_CMP_MASKED_EQ, 0xffffffffUL, 0x541c)) < 0) goto fail;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 || seccomp_load(ctx) < 0)
        goto fail;
    seccomp_release(ctx);
    return 0;
fail:
    seccomp_release(ctx);
    return -1;
}
