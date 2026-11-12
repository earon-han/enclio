#define _GNU_SOURCE
#include "enclio.h"
#include "proxy.h"
#include "resources.h"
#include <arpa/inet.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <poll.h>
#include <seccomp.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
struct startup_state { atomic_int error, attempted; };
static struct startup_state *startup;
static void report(unsigned char c) { (void)!write(3, &c, 1); }
static void child_failure(int fd, int error)
{
    /* Target rules may deny reporting/exit syscalls. Publish first via memory. */
    atomic_store_explicit(&startup->error, error ? error : EIO, memory_order_release);
    (void)!write(fd, &error, sizeof(error));
    _exit(127);
}
static int value(const char *text, unsigned long long *n)
{
    char *end;
    errno = 0;
    *n = strtoull(text, &end, 10);
    return errno || !*text || *end || *text == '-' ? -1 : 0;
}
int enclio_internal_main(int argc, char **argv)
{
    if (getpid() != 1)
        return 125;
    if (prctl(PR_SET_DUMPABLE, 0) || prctl(PR_SET_NAME, "enclio-init"))
        return 125;
    if (argc < 13)
        return 125;
    unsigned long long v[9];
    for (int i = 2; i <= 9; i++)
        if (value(argv[i], &v[i - 2]))
            return 125;
    if (value(argv[11], &v[8]) || v[8] > ENCLIO_MAX_ENV || argc <= 12 + (int)v[8])
        return 125;
    if (v[0] > 1 || v[1] > 1 || v[2] > 1 || v[3] > 1)
        return 125;
    int syscall_index = 12 + (int)v[8];
    unsigned long long syscall_count;
    if (value(argv[syscall_index], &syscall_count) || syscall_count > ENCLIO_SECCOMP_RULE_MAX ||
        argc <= syscall_index + 1 + (int)syscall_count)
        return 125;
    struct enclio_seccomp_rule syscalls[ENCLIO_SECCOMP_RULE_MAX];
    for (unsigned i = 0; i < syscall_count; i++)
        if (enclio_seccomp_rule_parse(argv[syscall_index + 1 + (int)i], &syscalls[i]))
            return 125;
    int command_index = syscall_index + 1 + (int)syscall_count;
    /* bwrap consumes mount source FDs. Defensively close any remaining copies
     * before creating child channels; only the documented bootstrap FDs remain. */
    DIR *fds = opendir("/proc/self/fd");
    if (!fds) return 125;
    struct dirent *entry;
    while ((entry = readdir(fds))) {
        int fd = atoi(entry->d_name);
        if (fd >= 7 && fd != dirfd(fds)) close(fd);
    }
    closedir(fds);
    bool network = v[0] != 0, strict = v[1] != 0, managed = v[2] != 0, export_enabled = v[3] != 0;
    struct enclio_resource_limits limits = {.cpu_seconds = (unsigned)v[4],
                                            .address_space_bytes = v[5],
                                            .file_bytes = v[6],
                                            .open_files = (unsigned)v[7]};
    pid_t supervisor = getpid();
    signal(SIGPIPE, SIG_IGN);
    char error[512] = {0};
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core))
        goto fail;
    if (managed && enclio_workspace_copy("/input", "/workspace", error, sizeof(error))) {
        if (errno == ENOSPC || errno == EDQUOT || errno == EFBIG)
            report('D');
        goto fail;
    }
    if (chdir(argv[10]))
        goto fail;
    if (network) {
        /* The listener belongs to this netns; only the trusted host proxy
         * receives its descriptor. Payloads inherit neither listener nor control. */
        int rc = enclio_proxy_send_listener(6, ENCLIO_PROXY_PORT, 5000);
        close(6);
        if (rc)
            goto fail;
    }
    startup = mmap(NULL, sizeof(*startup), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (startup == MAP_FAILED) { startup = NULL; goto fail; }
    atomic_init(&startup->error, 0);
    atomic_init(&startup->attempted, 0);
    bool exec_blocked = false;
    int execve_nr = seccomp_syscall_resolve_name("execve");
    for (unsigned i = 0; i < syscall_count; i++)
        if (syscalls[i].syscall_nr == execve_nr)
            exec_blocked = syscalls[i].action != SCMP_ACT_ALLOW;
    int gate[2];
    if (pipe2(gate, O_CLOEXEC)) goto fail;
    int handshake[2];
    if (pipe2(handshake, O_CLOEXEC)) { close(gate[0]); close(gate[1]); goto fail; }
    pid_t child = fork();
    if (child < 0) {
        close(handshake[0]);
        close(handshake[1]);
        close(gate[0]); close(gate[1]);
        goto fail;
    }
    if (!child) {
        close(handshake[0]);
        close(gate[1]);
        char start;
        ssize_t ready;
        do { ready = read(gate[0], &start, 1); } while (ready < 0 && errno == EINTR);
        close(gate[0]);
        if (ready != 1 || start != 'G') child_failure(handshake[1], EPIPE);
        close(3);
        if (export_enabled)
            close(4);
        if (dup2(5, 2) < 0)
            child_failure(handshake[1], errno);
        close(5);
        struct sigaction action = {.sa_handler = SIG_DFL};
        if (sigemptyset(&action.sa_mask) || sigaction(SIGPIPE, &action, NULL) ||
            (limits.cpu_seconds && sigaction(SIGXCPU, &action, NULL)) ||
            (limits.file_bytes && sigaction(SIGXFSZ, &action, NULL)))
            child_failure(handshake[1], errno);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != supervisor)
            child_failure(handshake[1], errno ? errno : ECHILD);
        if (enclio_resources_apply_rlimits(&limits, error, sizeof(error)) ||
            enclio_install_seccomp_rules(strict, syscalls, (size_t)syscall_count))
            child_failure(handshake[1], errno ? errno : EPERM);
        for (int i = 12; i < syscall_index; i++) {
            char *eq = strchr(argv[i], '=');
            if (!eq)
                child_failure(handshake[1], EINVAL);
            *eq = 0;
            if (setenv(argv[i], eq + 1, 1))
                child_failure(handshake[1], errno);
        }
        atomic_store_explicit(&startup->attempted, 1, memory_order_release);
        execvp(argv[command_index], &argv[command_index]);
        child_failure(handshake[1], errno);
    }
    close(gate[0]);
    /* A filter is irreversible across fork. Keep the init's fixed policy in
     * this parent, and let the target construct its independently overridden policy. */
    if (enclio_install_seccomp(0)) {
        close(gate[1]); close(handshake[0]); close(handshake[1]);
        goto fail;
    }
    if (write(gate[1], "G", 1) != 1) {
        close(gate[1]); close(handshake[0]); close(handshake[1]);
        goto fail;
    }
    close(gate[1]);
    close(5);
    close(handshake[1]);
    int exec_errno = 0;
    ssize_t n = 0;
    for (;;) {
        exec_errno = atomic_load_explicit(&startup->error, memory_order_acquire);
        if (exec_errno) { n = sizeof(exec_errno); break; }
        struct pollfd p = {.fd = handshake[0], .events = POLLIN};
        int ready = poll(&p, 1, 20);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) { exec_errno = errno; n = sizeof(exec_errno); break; }
        if (!ready) continue;
        n = read(handshake[0], &exec_errno, sizeof(exec_errno));
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    close(handshake[0]);
    int shared_error = atomic_load_explicit(&startup->error, memory_order_acquire);
    if (shared_error || (n == 0 && (exec_blocked ||
        !atomic_load_explicit(&startup->attempted, memory_order_acquire)))) {
        exec_errno = shared_error ? shared_error : EPERM;
        n = sizeof(exec_errno);
    }
    munmap(startup, sizeof(*startup));
    startup = NULL;
    if (n != 0) kill(child, SIGKILL);
    report(n == 0 ? 'S' : 'E');
    if (n > 0)
        dprintf(2, "enclio: command setup/exec: %s\n", strerror(exec_errno));
    int status = 0;
    struct rusage usage;
    for (;;) {
        pid_t done = wait4(-1, &status, 0, &usage);
        if (done == child)
            break;
        if (done < 0 && errno != EINTR) {
            report('E');
            close(3);
            return 125;
        }
    }
    unsigned char command_code =
        (unsigned char)(WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status));
    unsigned char sig = (unsigned char)(WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    unsigned char packet[] = {0, command_code, sig};
    if (n == 0)
        (void)!write(3, packet, sizeof(packet));
    if (sig == SIGKILL && limits.cpu_seconds) {
        double used = usage.ru_utime.tv_sec + usage.ru_stime.tv_sec +
                      (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1000000.0;
        if (used >= (double)limits.cpu_seconds)
            report('C');
    }
    /* PID1 must stop all descendants, including detached children, before any
     * trusted copy-out reads a workspace they could still mutate. */
    (void)kill(-1, SIGKILL);
    while (waitpid(-1, NULL, 0) > 0 || errno == EINTR) {
    }
    if (n != 0) {
        close(3);
        return 125;
    }
    if (export_enabled && command_code == 0) {
        if (enclio_workspace_export("/workspace", 4, error, sizeof(error))) {
            dprintf(2, "enclio: export: %s\n", error);
            report('E');
            close(3);
            close(4);
            return 125;
        }
    }
    close(3);
    if (export_enabled)
        close(4);
    return command_code;
fail:
    if (startup) { munmap(startup, sizeof(*startup)); startup = NULL; }
    dprintf(2, "enclio: sandbox initialization failed: %s%s%s\n", strerror(errno),
            *error ? ": " : "", error);
    report('E');
    (void)kill(-1, SIGKILL);
    return 125;
}
