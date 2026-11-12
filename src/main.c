#define _GNU_SOURCE
#include "enclio.h"
#include "proxy.h"
#include "resources.h"
#include "guardian.h"
#include "output.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mntent.h>
#include <poll.h>
#include <signal.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ENCLIO_MOUNT_MAX 32
enum network_mode { NETWORK_NONE, NETWORK_HOST, NETWORK_ISOLATED };
struct extra_mount {
    char source[PATH_MAX], destination[PATH_MAX];
    bool writable;
};
struct config {
    char workspace[PATH_MAX], export_path[PATH_MAX];
    const char *cwd, *result, *cgroup_parent, *workspace_mode;
    struct enclio_network_rule rules[ENCLIO_NETWORK_RULE_MAX];
    const char *env[ENCLIO_MAX_ENV];
    const char *syscalls[ENCLIO_SECCOMP_RULE_MAX];
    struct extra_mount mounts[ENCLIO_MOUNT_MAX];
    size_t nrules, nenv, nsyscalls, nmounts;
    enum network_mode network_mode;
    bool network_explicit;
    unsigned timeout;
    uint64_t output_bytes, tmp_bytes, disk_bytes;
    bool strict;
    struct enclio_resource_limits limits;
    char **command;
};
struct outcome {
    const char *status, *reason;
    int code, command_code, signal, report_pending;
    bool started, cleanup, resources_enforced;
    long duration;
    uint64_t output_bytes;
    struct enclio_resource_stats resources;
    struct enclio_resource_limits requested;
};
static volatile sig_atomic_t interrupted;
static int caller_fd = -1;
static bool caller_gone(void)
{
    if (caller_fd < 0)
        return false;
    struct pollfd p = {.fd = caller_fd, .events = POLLIN};
    return poll(&p, 1, 0) > 0 && (p.revents & (POLLIN | POLLHUP | POLLERR));
}
static void on_signal(int sig) { interrupted = sig; }
static int setup_signals(void)
{
    /* exec preserves the launching thread's mask and ignored dispositions.
     * Establish the management policy before unblocking pending signals. */
    sigset_t blocked, empty;
    if (sigfillset(&blocked) || sigemptyset(&empty) ||
        sigprocmask(SIG_SETMASK, &blocked, NULL))
        return -1;
    struct sigaction action = {.sa_handler = on_signal};
    if (sigemptyset(&action.sa_mask) || sigaction(SIGINT, &action, NULL) ||
        sigaction(SIGTERM, &action, NULL) || sigaction(SIGHUP, &action, NULL))
        return -1;
    action.sa_handler = SIG_DFL;
    if (sigaction(SIGCHLD, &action, NULL))
        return -1;
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, NULL))
        return -1;
    return sigprocmask(SIG_SETMASK, &empty, NULL);
}
static long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}
static void usage(FILE *f)
{
    fprintf(f, "enclio " ENCLIO_VERSION " — Linux agent sandbox\n"
               "Usage: enclio run --workspace DIR [OPTIONS] -- COMMAND [ARGS...]\n"
               "  --cwd /workspace/PATH  --timeout SECONDS  --result FILE\n"
               "  --env NAME=VALUE  --allow-host DOMAIN  --allow DOMAIN:PORT\n"
               "  --workspace-mode readwrite|readonly|tmpfs  --export EMPTY_DIR\n"
               "  --tmp-bytes N  --disk-bytes N  --output-bytes N\n"
               "  --cgroup-parent DIR  --memory-bytes N  --pids-max N  --cpu-percent N\n"
               "  --cpu-seconds N  --address-space-bytes N  --file-bytes N  --open-files N\n"
               "  --network none|host|isolated\n"
               "  --mount-ro SOURCE:DEST  --mount-rw SOURCE:DEST\n"
               "  --seccomp strict|compat  --syscall NAME=allow|deny|kill|errno:N\n"
               "       enclio doctor [--cgroup-parent DIR] | version | help\n"
               "Defaults: no network, strict seccomp, 300s, 64MiB scratch, 16MiB output.\n"
               "--disk-bytes requires readonly/tmpfs workspace; aggregate limits require delegated "
               "cgroup v2.\n");
}
static int number(const char *text, uint64_t maximum, uint64_t *value)
{
    if (!*text || *text < '0' || *text > '9')
        return -1;
    char *end;
    errno = 0;
    unsigned long long n = strtoull(text, &end, 10);
    if (errno || *end || !n || n > maximum)
        return -1;
    *value = n;
    return 0;
}
static bool within(const char *path, const char *directory)
{
    size_t n = strlen(directory);
    return !strncmp(path, directory, n) && (!path[n] || path[n] == '/');
}
/* A project directory must not smuggle host procfs or writable cgroup/device
 * control mounts into the new namespace, even through nested bind mounts. */
static bool workspace_filesystems_safe(const char *workspace)
{
    static const char *const controls[] = {
        "proc",    "sysfs",   "cgroup", "cgroup2",  "devtmpfs", "devpts",    "securityfs",
        "debugfs", "tracefs", "bpf",    "configfs", "fusectl",  "hugetlbfs", "mqueue"};
    FILE *mounts = setmntent("/proc/self/mounts", "r");
    if (!mounts)
        return false;
    bool safe = true;
    struct mntent *entry;
    while ((entry = getmntent(mounts))) {
        for (unsigned i = 0; i < sizeof(controls) / sizeof(controls[0]); i++) {
            if (!strcmp(entry->mnt_type, controls[i]) &&
                (within(workspace, entry->mnt_dir) || within(entry->mnt_dir, workspace))) {
                safe = false;
                break;
            }
        }
        if (!safe)
            break;
    }
    if (ferror(mounts))
        safe = false;
    endmntent(mounts);
    return safe;
}
/* Extra binds are directory authorizations; never shadow trusted runtime,
 * control paths, quota-managed scratch or the managed workspace. */
static int mount_parse(const char *text, bool writable, struct extra_mount *mount)
{
    const char *colon = strchr(text, ':');
    if (!colon || colon == text || strchr(colon + 1, ':') ||
        (size_t)(colon - text) >= PATH_MAX || strlen(colon + 1) >= PATH_MAX)
        return -1;
    char source[PATH_MAX];
    memcpy(source, text, (size_t)(colon - text));
    source[colon - text] = 0;
    const char *destination = colon + 1;
    size_t length = strlen(destination);
    if (length < 2 || destination[0] != '/' || destination[length - 1] == '/' ||
        strstr(destination, "//"))
        return -1;
    for (const char *part = destination + 1; *part;) {
        const char *end = strchr(part, '/');
        size_t n = end ? (size_t)(end - part) : strlen(part);
        if ((n == 1 && part[0] == '.') || (n == 2 && !strncmp(part, "..", 2)))
            return -1;
        if (!end) break;
        part = end + 1;
    }
    static const char *const managed[] = {"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc",
        "/proc", "/dev", "/.enclio", "/workspace", "/input", "/tmp", "/home", "/run", "/sys"};
    for (unsigned i = 0; i < sizeof(managed) / sizeof(managed[0]); i++)
        if (within(destination, managed[i]) || within(managed[i], destination))
            return -1;
    struct stat st;
    if (!realpath(source, mount->source) || !strcmp(mount->source, "/") ||
        stat(mount->source, &st) || !S_ISDIR(st.st_mode) ||
        !workspace_filesystems_safe(mount->source))
        return -1;
    strcpy(mount->destination, destination);
    mount->writable = writable;
    return 0;
}
static int parse(int argc, char **argv, struct config *c)
{
    c->timeout = 300;
    c->cwd = "/workspace";
    c->workspace_mode = "readwrite";
    c->strict = true;
    c->tmp_bytes = 64ULL * 1024 * 1024;
    c->output_bytes = 16ULL * 1024 * 1024;
    const char *workspace = NULL, *export_path = NULL;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--")) {
            c->command = &argv[i + 1];
            break;
        }
        if (i + 1 >= argc)
            return -1;
        const char *key = argv[i++], *val = argv[i];
        uint64_t n = 0;
        if (!strcmp(key, "--workspace"))
            workspace = val;
        else if (!strcmp(key, "--cwd"))
            c->cwd = val;
        else if (!strcmp(key, "--result"))
            c->result = val;
        else if (!strcmp(key, "--export"))
            export_path = val;
        else if (!strcmp(key, "--cgroup-parent"))
            c->cgroup_parent = val;
        else if (!strcmp(key, "--workspace-mode")) {
            if (strcmp(val, "readwrite") && strcmp(val, "readonly") && strcmp(val, "tmpfs"))
                return -1;
            c->workspace_mode = val;
        } else if (!strcmp(key, "--network")) {
            if (c->network_explicit) return -1;
            if (!strcmp(val, "none")) c->network_mode = NETWORK_NONE;
            else if (!strcmp(val, "host")) c->network_mode = NETWORK_HOST;
            else if (!strcmp(val, "isolated")) c->network_mode = NETWORK_ISOLATED;
            else return -1;
            c->network_explicit = true;
        } else if (!strcmp(key, "--mount-ro") || !strcmp(key, "--mount-rw")) {
            if (c->nmounts == ENCLIO_MOUNT_MAX ||
                mount_parse(val, !strcmp(key, "--mount-rw"), &c->mounts[c->nmounts]))
                return -1;
            for (size_t j = 0; j < c->nmounts; j++)
                if (within(c->mounts[j].destination, c->mounts[c->nmounts].destination) ||
                    within(c->mounts[c->nmounts].destination, c->mounts[j].destination))
                    return -1;
            c->nmounts++;
        } else if (!strcmp(key, "--syscall")) {
            struct enclio_seccomp_rule rule;
            if (c->nsyscalls == ENCLIO_SECCOMP_RULE_MAX || enclio_seccomp_rule_parse(val, &rule))
                return -1;
            c->syscalls[c->nsyscalls++] = val;
        } else if (!strcmp(key, "--seccomp")) {
            if (strcmp(val, "strict") && strcmp(val, "compat"))
                return -1;
            c->strict = !strcmp(val, "strict");
        } else if (!strcmp(key, "--allow") || !strcmp(key, "--allow-host")) {
            if (c->nrules == ENCLIO_NETWORK_RULE_MAX ||
                (!strcmp(key, "--allow-host") && !enclio_proxy_host_valid(val)) ||
                !enclio_proxy_rule_parse(val, &c->rules[c->nrules],
                                         !strcmp(key, "--allow-host") ? 443 : 0))
                return -1;
            c->nrules++;
        } else if (!strcmp(key, "--env")) {
            const char *eq = strchr(val, '=');
            if (c->nenv == ENCLIO_MAX_ENV || !eq || eq == val)
                return -1;
            for (const char *p = val; p < eq; p++)
                if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || *p == '_' ||
                      (p > val && *p >= '0' && *p <= '9')))
                    return -1;
            c->env[c->nenv++] = val;
        } else {
            if (number(val, 1ULL << 50, &n))
                return -1;
            if (!strcmp(key, "--timeout") && n <= 86400)
                c->timeout = (unsigned)n;
            else if (!strcmp(key, "--output-bytes"))
                c->output_bytes = n;
            else if (!strcmp(key, "--tmp-bytes"))
                c->tmp_bytes = n;
            else if (!strcmp(key, "--disk-bytes"))
                c->disk_bytes = n;
            else if (!strcmp(key, "--memory-bytes"))
                c->limits.memory_bytes = n;
            else if (!strcmp(key, "--pids-max") && n <= UINT_MAX)
                c->limits.pids_max = (unsigned)n;
            else if (!strcmp(key, "--cpu-percent") && n <= 10000)
                c->limits.cpu_percent = (unsigned)n;
            else if (!strcmp(key, "--cpu-seconds") && n <= UINT_MAX)
                c->limits.cpu_seconds = (unsigned)n;
            else if (!strcmp(key, "--address-space-bytes"))
                c->limits.address_space_bytes = n;
            else if (!strcmp(key, "--file-bytes"))
                c->limits.file_bytes = n;
            else if (!strcmp(key, "--open-files") && n <= UINT_MAX)
                c->limits.open_files = (unsigned)n;
            else
                return -1;
        }
    }
    if (!c->network_explicit && c->nrules)
        c->network_mode = NETWORK_ISOLATED; /* Preserve legacy --allow calls. */
    if ((c->network_mode == NETWORK_ISOLATED) != (c->nrules != 0)) {
        dprintf(2, "enclio: isolated network requires --allow/--allow-host; none/host reject proxy rules\n");
        return -1;
    }
    struct stat st;
    if (!workspace || !c->command || !c->command[0] || !realpath(workspace, c->workspace) ||
        stat(c->workspace, &st) || !S_ISDIR(st.st_mode) || !strcmp(c->workspace, "/"))
        return -1;
    if (strcmp(c->cwd, "/workspace") && strncmp(c->cwd, "/workspace/", 11))
        return -1;
    if (!workspace_filesystems_safe(c->workspace))
        return -1;
    if (c->cgroup_parent && !strcmp(c->workspace_mode, "readwrite")) {
        char controller[PATH_MAX];
        if (realpath(c->cgroup_parent, controller) && within(controller, c->workspace))
            return -1;
    }
    if ((c->disk_bytes && !strcmp(c->workspace_mode, "readwrite")) ||
        (!strcmp(c->workspace_mode, "tmpfs") && !c->disk_bytes))
        return -1;
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || c->tmp_bytes % (uint64_t)page || c->disk_bytes % (uint64_t)page ||
        c->limits.memory_bytes % (uint64_t)page)
        return -1;
    if (export_path) {
        if (strcmp(c->workspace_mode, "tmpfs") || !realpath(export_path, c->export_path) ||
            stat(c->export_path, &st) || !S_ISDIR(st.st_mode) ||
            within(c->export_path, c->workspace) || within(c->workspace, c->export_path))
            return -1;
        DIR *d = opendir(c->export_path);
        if (!d)
            return -1;
        struct dirent *e;
        bool empty = true;
        while ((e = readdir(d)))
            if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
                empty = false;
        closedir(d);
        if (!empty)
            return -1;
    }
    /* Explicit syscall allows must not invalidate a separately requested
     * memory quota on kernels where HugeTLB escapes memory.max accounting. */
    if (c->limits.memory_bytes) {
        const char *huge[] = {"memfd_create", "shmget", "mmap", "mmap2"};
        for (unsigned i = 0; i < sizeof(huge) / sizeof(huge[0]); i++) {
            int nr = seccomp_syscall_resolve_name(huge[i]);
            if (nr < 0) continue;
            bool allow = false;
            for (size_t j = 0; j < c->nsyscalls; j++) {
                struct enclio_seccomp_rule rule;
                if (enclio_seccomp_rule_parse(c->syscalls[j], &rule)) return -1;
                if (rule.syscall_nr == nr) allow = rule.action == SCMP_ACT_ALLOW;
            }
            if (allow) {
                dprintf(2, "enclio: custom allow of %s conflicts with requested memory quota\n", huge[i]);
                return -1;
            }
        }
    }
    for (size_t i = 0; i < c->nmounts; i++) {
        const struct extra_mount *m = &c->mounts[i];
        if ((m->writable && c->disk_bytes) ||
            (*c->export_path && (within(c->export_path, m->source) || within(m->source, c->export_path))))
            return -1;
        if (c->cgroup_parent) {
            char parent[PATH_MAX];
            if (!realpath(c->cgroup_parent, parent) || within(parent, m->source) || within(m->source, parent))
                return -1;
        }
    }
    return 0;
}
static void close_extra_fds(int keep, int second_keep, int third_keep)
{
    DIR *d = opendir("/proc/self/fd");
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            int fd = atoi(e->d_name);
            if (fd > 3 && fd != keep && fd != second_keep && fd != third_keep && fd != dirfd(d))
                close(fd);
        }
        closedir(d);
    } else {
        long max = sysconf(_SC_OPEN_MAX);
        for (int fd = 4; fd < max; fd++)
            if (fd != keep && fd != second_keep && fd != third_keep)
                close(fd);
    }
}
static int result_open(const char *path)
{
    if (!path)
        return -1;
    int fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    struct stat st;
    if (fd < 0)
        return -2;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 || ftruncate(fd, 0)) {
        close(fd);
        return -2;
    }
    return fd;
}
static bool result_outside(const struct config *c)
{
    if (!c->result)
        return true;
    char resolved[PATH_MAX], copy[PATH_MAX];
    if (strlen(c->result) >= sizeof(copy))
        return false;
    if (!realpath(c->result, resolved)) {
        strcpy(copy, c->result);
        char *slash = strrchr(copy, '/');
        const char *base = slash ? slash + 1 : copy;
        if (!*base || !strcmp(base, ".") || !strcmp(base, ".."))
            return false;
        if (slash) {
            *slash = 0;
            if (!realpath(*copy ? copy : "/", resolved))
                return false;
        } else if (!realpath(".", resolved))
            return false;
        size_t n = strlen(resolved);
        if (n + 1 + strlen(base) >= sizeof(resolved))
            return false;
        resolved[n++] = '/';
        strcpy(resolved + n, base);
    }
    for (size_t i = 0; i < c->nmounts; i++)
        if (c->mounts[i].writable && within(resolved, c->mounts[i].source))
            return false;
    return !within(resolved, c->workspace) &&
           (!*c->export_path || !within(resolved, c->export_path));
}
static int result_write(int fd, const struct outcome *o)
{
    if (fd < 0)
        return 0;
    const struct enclio_resource_stats *s = &o->resources;
    const struct enclio_resource_limits *l = &o->requested;
    bool rlimits = l->cpu_seconds || l->address_space_bytes || l->file_bytes || l->open_files;
    int n = dprintf(
        fd,
        "{\"schema_version\":1,\"status\":\"%s\",\"exit_code\":%d,\"command_exit_code\":%d,"
        "\"signal\":%d,"
        "\"duration_ms\":%ld,\"command_started\":%s,\"limit_reason\":\"%s\",\"cleanup_complete\":%"
        "s,\"output_bytes\":%llu,"
        "\"resources\":{\"enforced\":%s,\"cgroup_enforced\":%s,\"rlimits_requested\":%s,\"rlimits_"
        "applied\":%s,"
        "\"cpu_usage_usec\":%llu,\"cpu_throttled_usec\":%llu,\"memory_current\":%llu,\"memory_"
        "peak\":%llu,"
        "\"memory_peak_available\":%s,\"memory_max_events\":%llu,\"oom_kills\":%llu,\"pids_"
        "current\":%llu,"
        "\"pids_peak\":%llu,\"pids_peak_available\":%s,\"pids_max_events\":%llu,"
        "\"limits\":{\"memory_bytes\":%llu,\"pids_max\":%u,\"cpu_percent\":%u,\"cpu_seconds\":%u,"
        "\"address_space_bytes\":%llu,\"file_bytes\":%llu,\"open_files\":%u}}}\n",
        o->status, o->code, o->command_code, o->signal, o->duration, o->started ? "true" : "false",
        o->reason ? o->reason : "", o->cleanup ? "true" : "false",
        (unsigned long long)o->output_bytes, o->resources_enforced ? "true" : "false",
        o->resources_enforced ? "true" : "false", rlimits ? "true" : "false",
        rlimits && o->started ? "true" : "false", (unsigned long long)s->cpu_usage_usec,
        (unsigned long long)s->cpu_throttled_usec, (unsigned long long)s->memory_current,
        (unsigned long long)s->memory_peak, s->memory_peak_available ? "true" : "false",
        (unsigned long long)s->memory_max_events, (unsigned long long)s->oom_kills,
        (unsigned long long)s->pids_current, (unsigned long long)s->pids_peak,
        s->pids_peak_available ? "true" : "false", (unsigned long long)s->pids_max_events,
        (unsigned long long)l->memory_bytes, l->pids_max, l->cpu_percent, l->cpu_seconds,
        (unsigned long long)l->address_space_bytes, (unsigned long long)l->file_bytes,
        l->open_files);
    int rc = n < 0 || fsync(fd) < 0 ? -1 : 0;
    close(fd);
    return rc;
}
static int channels(int fd[2])
{
    if (pipe2(fd, O_CLOEXEC))
        return -1;
    int f = fcntl(fd[0], F_GETFL);
    if (f < 0 || fcntl(fd[0], F_SETFL, f | O_NONBLOCK) < 0) {
        close(fd[0]);
        close(fd[1]);
        fd[0] = fd[1] = -1;
        return -1;
    }
    return 0;
}
static void state_update(int fd, struct outcome *o, bool *failed)
{
    unsigned char state;
    while (read(fd, &state, 1) == 1) {
        if (o->report_pending == 1) {
            o->command_code = state;
            o->report_pending = 2;
            continue;
        }
        if (o->report_pending == 2) {
            o->signal = state;
            o->report_pending = 0;
            continue;
        }
        if (!state) {
            o->report_pending = 1;
            continue;
        }
        if (state == 'S')
            o->started = true;
        if (state == 'E')
            *failed = true;
        if (state == 'D') {
            o->status = "resource_limit";
            o->reason = "disk";
            o->code = 126;
        }
        if (state == 'C') {
            o->status = "resource_limit";
            o->reason = "cpu";
            o->code = 126;
        }
    }
}
static void bwrap_exec(const struct config *c, const char *self, const char *temporary, int report,
                       int export_fd, int stdin_fd, int stdout_fd, int stderr_fd, int diagnostic_fd,
                       int network_fd, pid_t parent,
                       const struct enclio_resources *resources)
{
    if (setpgid(0, 0) || prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent)
        _exit(125);
    char error[256];
    if (enclio_resources_enter(resources, error, sizeof(error))) {
        dprintf(2, "enclio: %s\n", error);
        _exit(125);
    }
    int r = fcntl(report, F_DUPFD_CLOEXEC, 20),
        e = export_fd >= 0 ? fcntl(export_fd, F_DUPFD_CLOEXEC, 20) : -1,
        target_stderr = fcntl(stderr_fd, F_DUPFD_CLOEXEC, 20),
        network = network_fd >= 0 ? fcntl(network_fd, F_DUPFD_CLOEXEC, 20) : -1;
    if (r < 0 || target_stderr < 0 || (network_fd >= 0 && network < 0) ||
        (export_fd >= 0 && e < 0) || dup2(stdin_fd, 0) < 0 ||
        dup2(stdout_fd, 1) < 0 || dup2(diagnostic_fd, 2) < 0 || dup2(r, 3) < 0 ||
        fcntl(3, F_SETFD, 0) < 0 || dup2(target_stderr, 5) < 0 || fcntl(5, F_SETFD, 0) < 0)
        _exit(125);
    if (e >= 0 && (dup2(e, 4) < 0 || fcntl(4, F_SETFD, 0) < 0))
        _exit(125);
    if (network >= 0 && (dup2(network, 6) < 0 || fcntl(6, F_SETFD, 0) < 0))
        _exit(125);
    close_extra_fds(e >= 0 ? 4 : -1, 5, network >= 0 ? 6 : -1);
    char *args[1024];
    size_t n = 0;
#define A(s)                                                                                       \
    do {                                                                                           \
        if (n >= 1023)                                                                             \
            _exit(125);                                                                            \
        args[n++] = (char *)(s);                                                                   \
    } while (0)
    char size[32], passwd[PATH_MAX], group[PATH_MAX];
    snprintf(size, sizeof(size), "%llu",
             (unsigned long long)(c->disk_bytes ? c->disk_bytes : c->tmp_bytes));
    snprintf(passwd, sizeof(passwd), "%s/passwd", temporary);
    snprintf(group, sizeof(group), "%s/group", temporary);
    A("/usr/bin/bwrap");
    A("--die-with-parent");
    A("--new-session");
    A("--unshare-user");
    A("--unshare-pid");
    A("--as-pid-1");
    A("--unshare-ipc");
    A("--unshare-uts");
    if (c->network_mode != NETWORK_HOST)
        A("--unshare-net");
    A("--disable-userns");
    A("--cap-drop");
    A("ALL");
    A("--hostname");
    A("enclio");
    A("--clearenv");
    A("--size");
    A(size);
    A("--tmpfs");
    A("/");
    const char *system[] = {"/usr", "/bin", "/sbin", "/lib", "/lib64", NULL};
    for (unsigned i = 0; system[i]; i++)
        if (!access(system[i], F_OK)) {
            A("--ro-bind");
            A(system[i]);
            A(system[i]);
        }
    A("--dir");
    A("/etc");
    A("--ro-bind");
    A(passwd);
    A("/etc/passwd");
    A("--ro-bind");
    A(group);
    A("/etc/group");
    if (!access("/etc/ssl/certs", F_OK)) {
        A("--ro-bind");
        A("/etc/ssl/certs");
        A("/etc/ssl/certs");
    }
    if (!access("/etc/alternatives", F_OK)) {
        A("--ro-bind");
        A("/etc/alternatives");
        A("/etc/alternatives");
    }
    if (!access("/etc/ld.so.cache", F_OK)) {
        A("--ro-bind");
        A("/etc/ld.so.cache");
        A("/etc/ld.so.cache");
    }
    if (c->network_mode == NETWORK_HOST) {
        const char *dns[] = {"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", NULL};
        for (unsigned i = 0; dns[i]; i++) {
            struct stat st;
            if (!stat(dns[i], &st) && S_ISREG(st.st_mode) && !access(dns[i], R_OK)) {
                A("--ro-bind"); A(dns[i]); A(dns[i]);
            }
        }
    }
    A("--proc");
    A("/proc");
    A("--dir");
    A("/dev");
    const char *devices[] = {"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom",
                             "/dev/full", "/dev/tty",  NULL};
    for (unsigned i = 0; devices[i]; i++)
        if (!access(devices[i], F_OK)) {
            A("--dev-bind");
            A(devices[i]);
            A(devices[i]);
        }
    A("--symlink");
    A("/proc/self/fd");
    A("/dev/fd");
    A("--symlink");
    A("/proc/self/fd/0");
    A("/dev/stdin");
    A("--symlink");
    A("/proc/self/fd/1");
    A("/dev/stdout");
    A("--symlink");
    A("/proc/self/fd/2");
    A("/dev/stderr");
    A("--dir");
    A("/tmp/shm");
    A("--symlink");
    A("/tmp/shm");
    A("/dev/shm");
    A("--dir");
    A("/home/agent");
    A("--dir");
    A("/run");
    A("--dir");
    A("/.enclio");
    A("--ro-bind");
    A(self);
    A("/.enclio/enclio");
    if (!strcmp(c->workspace_mode, "tmpfs")) {
        A("--ro-bind");
        A(c->workspace);
        A("/input");
        A("--dir");
        A("/workspace");
    } else {
        A(!strcmp(c->workspace_mode, "readonly") ? "--ro-bind" : "--bind");
        A(c->workspace);
        A("/workspace");
    }
    char mount_fds[ENCLIO_MOUNT_MAX][16];
    for (size_t i = 0; i < c->nmounts; i++) {
        int source = open(c->mounts[i].source, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (source < 0) _exit(125);
        int pinned = fcntl(source, F_DUPFD_CLOEXEC, 20);
        close(source);
        if (pinned < 0 || fcntl(pinned, F_SETFD, 0)) _exit(125);
        snprintf(mount_fds[i], sizeof(mount_fds[i]), "%d", pinned);
        A(c->mounts[i].writable ? "--bind-fd" : "--ro-bind-fd");
        A(mount_fds[i]); A(c->mounts[i].destination);
    }
    /* Trusted init copies input before changing to a possibly nested cwd. */
    A("--chdir");
    A("/");
    A("--setenv");
    A("PATH");
    A("/usr/local/bin:/usr/bin:/bin");
    A("--setenv");
    A("HOME");
    A("/home/agent");
    A("--setenv");
    A("LANG");
    A("C.UTF-8");
    A("--setenv");
    A("TMPDIR");
    A("/tmp");
    if (c->nrules) {
        const char *vars[] = {"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", NULL};
        for (unsigned i = 0; vars[i]; i++) {
            A("--setenv");
            A(vars[i]);
            A("http://127.0.0.1:18080");
        }
        A("--setenv");
        A("ALL_PROXY");
        A("socks5h://127.0.0.1:18080");
        A("--setenv");
        A("all_proxy");
        A("socks5h://127.0.0.1:18080");
        A("--setenv");
        A("NO_PROXY");
        A("");
        A("--setenv");
        A("no_proxy");
        A("");
    }
    char cpu[32], address[32], file[32], open_files[32], env_count[32], syscall_count[32];
    snprintf(cpu, sizeof(cpu), "%u", c->limits.cpu_seconds);
    snprintf(address, sizeof(address), "%llu", (unsigned long long)c->limits.address_space_bytes);
    snprintf(file, sizeof(file), "%llu", (unsigned long long)c->limits.file_bytes);
    snprintf(open_files, sizeof(open_files), "%u", c->limits.open_files);
    snprintf(env_count, sizeof(env_count), "%zu", c->nenv);
    snprintf(syscall_count, sizeof(syscall_count), "%zu", c->nsyscalls);
    A("--");
    A("/.enclio/enclio");
    A("--internal-init");
    A(c->nrules ? "1" : "0");
    A(c->strict ? "1" : "0");
    A(!strcmp(c->workspace_mode, "tmpfs") ? "1" : "0");
    A(e >= 0 ? "1" : "0");
    A(cpu);
    A(address);
    A(file);
    A(open_files);
    A(c->cwd);
    A(env_count);
    for (size_t i = 0; i < c->nenv; i++)
        A(c->env[i]);
    A(syscall_count);
    for (size_t i = 0; i < c->nsyscalls; i++)
        A(c->syscalls[i]);
    for (char **p = c->command; *p; p++)
        A(*p);
    args[n] = NULL;
    if (clearenv())
        _exit(125);
    execv(args[0], args);
    dprintf(2, "enclio: cannot execute bwrap: %s\n", strerror(errno));
    _exit(125);
#undef A
}
static struct outcome run(const struct config *c)
{
    struct outcome o = {.status = "setup_error",
                        .code = 125,
                        .command_code = -1,
                        .cleanup = true,
                        .requested = c->limits};
    struct enclio_resources resources = {.parent_fd = -1, .group_fd = -1};
    struct enclio_guardian guard = {.pid = -1, .fd = -1};
    struct enclio_output outputs[2] = {{.input = -1, .destination = -1},
                                       {.input = -1, .destination = -1}};
    int statusfd[2] = {-1, -1}, outfd[2] = {-1, -1}, errfd[2] = {-1, -1}, infd[2] = {-1, -1},
        diagfd[2] = {-1, -1}, networkfd[2] = {-1, -1}, export_fd = -1;
    struct enclio_output input = {.input = -1, .destination = -1};
    struct enclio_output diagnostic = {.input = -1, .destination = -1};
    uint64_t input_bytes = 0, diagnostic_bytes = 0;
    pid_t child = -1, proxy = -1, parent = getpid();
    bool reaped = false, failed = false, created = false;
    int status = 0;
    long start = now_ms();
    char temporary[] = "/tmp/enclio-XXXXXX", self[PATH_MAX],
         path[PATH_MAX], error[512];
    if (getuid() == 0 || geteuid() != getuid() || getegid() != getgid()) {
        dprintf(2, "enclio: require ordinary non-setuid user\n");
        goto done;
    }
    for (int fd = 0; fd < 3; fd++) {
        struct stat st;
        if (fstat(fd, &st) || S_ISSOCK(st.st_mode)) {
            dprintf(2, "enclio: stdio must be open and not sockets\n");
            goto done;
        }
    }
    ssize_t length = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (length < 0 || (size_t)length >= sizeof(self) - 1)
        goto done;
    self[length] = 0;
    if (access("/usr/bin/bwrap", X_OK)) {
        dprintf(2, "enclio: require /usr/bin/bwrap\n");
        goto done;
    }
    error[0] = 0;
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) ||
        enclio_guardian_start(&guard, temporary, sizeof(temporary), c->cgroup_parent, &c->limits,
                              &resources, error, sizeof(error),
                              c->timeout < 5 ? c->timeout * 1000 : 5000, caller_fd)) {
        dprintf(2, "enclio: cannot prepare guarded resources: %s%s%s\n", strerror(errno),
                *error ? ": " : "", error);
        goto done;
    }
    created = true;
    o.resources_enforced = resources.active;
    snprintf(path, sizeof(path), "%s/passwd", temporary);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        goto done;
    int n = dprintf(fd, "agent:x:%u:%u:Agent:/home/agent:/bin/sh\n", getuid(), getgid());
    close(fd);
    if (n < 0)
        goto done;
    snprintf(path, sizeof(path), "%s/group", temporary);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        goto done;
    n = dprintf(fd, "agent:x:%u:\n", getgid());
    close(fd);
    if (n < 0)
        goto done;
    if (*c->export_path) {
        export_fd = open(c->export_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (export_fd < 0)
            goto done;
    }
    if (c->nrules) {
        if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, networkfd))
            goto done;
        proxy = fork();
        if (proxy < 0)
            goto done;
        if (!proxy) {
            if (setpgid(0, 0) || prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent)
                _exit(125);
            if (enclio_resources_enter(&resources, error, sizeof(error)))
                _exit(125);
            (void)prctl(PR_SET_NAME, "enclio-proxy");
            signal(SIGTERM, SIG_DFL);
            signal(SIGINT, SIG_DFL);
            signal(SIGHUP, SIG_DFL);
            int control = fcntl(networkfd[0], F_DUPFD_CLOEXEC, 20);
            if (control < 0 || dup2(control, 3) < 0)
                _exit(125);
            close_extra_fds(-1, -1, -1);
            if (clearenv())
                _exit(125);
            _exit(enclio_proxy_serve_control(3, c->rules, c->nrules, c->timeout * 1000) ? 125 : 0);
        }
        setpgid(proxy, proxy);
        if (enclio_guardian_track(&guard, proxy))
            goto done;
        close(networkfd[0]);
        networkfd[0] = -1;
    }
    if (channels(statusfd) || channels(outfd) || channels(errfd) || channels(diagfd) ||
        pipe2(infd, O_CLOEXEC))
        goto done;
    child = fork();
    if (child < 0)
        goto done;
    if (!child)
        bwrap_exec(c, self, temporary, statusfd[1], export_fd, infd[0], outfd[1], errfd[1],
                   diagfd[1], networkfd[1], parent, &resources);
    if (networkfd[1] >= 0) {
        close(networkfd[1]);
        networkfd[1] = -1;
    }
    setpgid(child, child);
    if (enclio_guardian_track(&guard, child))
        goto done;
    close(statusfd[1]);
    statusfd[1] = -1;
    close(outfd[1]);
    outfd[1] = -1;
    close(errfd[1]);
    errfd[1] = -1;
    close(diagfd[1]);
    diagfd[1] = -1;
    if (enclio_output_open(&outputs[0], outfd[0], 1))
        goto done;
    outfd[0] = -1;
    if (enclio_output_open(&outputs[1], errfd[0], 2))
        goto done;
    errfd[0] = -1;
    if (enclio_output_open(&diagnostic, diagfd[0], 2))
        goto done;
    diagfd[0] = -1;
    close(infd[0]);
    infd[0] = -1;
    if (enclio_input_open(&input, infd[1]))
        goto done;
    infd[1] = -1;
    for (;;) {
        state_update(statusfd[0], &o, &failed);
        if (caller_gone())
            interrupted = SIGTERM;
        if (!reaped) {
            pid_t rc = waitpid(child, &status, WNOHANG);
            if (rc == child)
                reaped = true;
            else if (rc < 0 && errno != EINTR)
                goto done;
        }
        if (interrupted) {
            o.status = "cancelled";
            o.code = 128 + interrupted;
            o.signal = interrupted;
            goto done;
        }
        if (now_ms() - start >= (long)c->timeout * 1000) {
            o.status = "timeout";
            o.code = 124;
            goto done;
        }
        if (guard.pid > 0) {
            int gstatus = 0;
            pid_t g = waitpid(guard.pid, &gstatus, WNOHANG | WUNTRACED);
            if (g == guard.pid) {
                if (!WIFSTOPPED(gstatus))
                    guard.pid = -1;
                dprintf(2, "enclio: cleanup guardian failed\n");
                goto done;
            }
        }
        if (proxy > 0 && waitpid(proxy, NULL, WNOHANG) == proxy) {
            proxy = -1;
            dprintf(2, "enclio: proxy exited unexpectedly\n");
            goto done;
        }
        struct pollfd p[9] = {{.fd = statusfd[0], .events = POLLIN}};
        for (int i = 0; i < 2; i++) {
            p[1 + i * 2] = (struct pollfd){
                .fd = outputs[i].eof || outputs[i].begin != outputs[i].end ? -1 : outputs[i].input,
                .events = POLLIN};
            p[2 + i * 2] = (struct pollfd){
                .fd = outputs[i].begin != outputs[i].end ? outputs[i].destination : -1,
                .events = POLLOUT};
        }
        if (reaped && outputs[0].eof && outputs[1].eof && outputs[0].begin == outputs[0].end &&
            outputs[1].begin == outputs[1].end && diagnostic.eof &&
            diagnostic.begin == diagnostic.end)
            break;
        if (input.eof && input.begin == input.end && input.destination >= 0) {
            close(input.destination);
            input.destination = -1;
        }
        p[5] = (struct pollfd){.fd = input.eof || input.begin != input.end ? -1 : input.input,
                               .events = POLLIN};
        p[6] = (struct pollfd){.fd = input.begin != input.end ? input.destination : -1,
                               .events = POLLOUT};
        p[7] = (struct pollfd){.fd = diagnostic.eof || diagnostic.begin != diagnostic.end
                                        ? -1 : diagnostic.input,
                               .events = POLLIN};
        p[8] = (struct pollfd){.fd = diagnostic.begin != diagnostic.end
                                        ? diagnostic.destination : -1,
                               .events = POLLOUT};
        int rc = poll(p, 9, 10);
        if (rc < 0 && errno != EINTR)
            goto done;
        if (p[5].revents & (POLLIN | POLLHUP | POLLERR))
            if (enclio_output_read(&input, &input_bytes, UINT64_MAX) < 0)
                goto done;
        if (p[6].revents & (POLLOUT | POLLERR | POLLHUP)) {
            if (enclio_output_write(&input)) {
                enclio_output_close(&input);
                input.eof = true;
                input.begin = input.end = 0;
            }
        }
        if (p[8].revents & (POLLOUT | POLLERR | POLLHUP))
            if (enclio_output_write(&diagnostic))
                goto done;
        /* Trusted setup/exec/export diagnostics use a separate pipe. Retain at
         * most 16KiB, consume any excess, and never charge the target budget. */
        if (p[7].revents & (POLLIN | POLLHUP | POLLERR))
            if (enclio_output_read(&diagnostic, &diagnostic_bytes, 16384) < 0)
                goto done;
        for (int i = 0; i < 2; i++) {
            if (p[2 + i * 2].revents & (POLLOUT | POLLERR | POLLHUP))
                if (enclio_output_write(&outputs[i]))
                    goto done;
            if (p[1 + i * 2].revents & (POLLIN | POLLHUP | POLLERR)) {
                int r = enclio_output_read(&outputs[i], &o.output_bytes, c->output_bytes);
                /* Both captured streams now have target-only writers. This
                 * also confirms a fast stderr-only producer before init's S. */
                if (r > 0 || outputs[i].end > outputs[i].begin)
                    o.started = true;
                if (r < 0)
                    goto done;
                if (r > 0) {
                    o.status = "resource_limit";
                    o.reason = "output";
                    o.code = 126;
                    goto done;
                }
            }
        }
    }
    state_update(statusfd[0], &o, &failed);
    if (o.started && !failed && !o.reason) {
        o.status = "exited";
        o.code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        if (WIFSIGNALED(status))
            o.signal = WTERMSIG(status);
    }
done:
    if (!strcmp(o.status, "setup_error") && now_ms() - start >= (long)c->timeout * 1000) {
        o.status = "timeout";
        o.code = 124;
    }
    if (interrupted) {
        o.status = "cancelled";
        o.signal = interrupted;
        o.code = 128 + interrupted;
    }
    if (child > 0 && !reaped) {
        kill(-child, SIGKILL);
        kill(child, SIGKILL);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
        }
        reaped = true;
    }
    if (child > 0 && reaped) {
        if (statusfd[0] >= 0)
            state_update(statusfd[0], &o, &failed);
    }
    if (proxy > 0) {
        kill(-proxy, SIGKILL);
        kill(proxy, SIGKILL);
        while (waitpid(proxy, NULL, 0) < 0 && errno == EINTR) {
        }
    }
    if (resources.active) {
        if (enclio_resources_stats(&resources, &o.resources, error, sizeof(error))) {
            dprintf(2, "enclio: resource stats: %s\n", error);
            o.cleanup = false;
        }
        if (!interrupted && strcmp(o.status, "timeout") && !o.reason) {
            if (o.resources.oom_kills) {
                o.status = "resource_limit";
                o.reason = "memory";
                o.code = 126;
            } else if (o.resources.pids_max_events) {
                o.status = "resource_limit";
                o.reason = "pids";
                o.code = 126;
            }
        }
        if (enclio_resources_cleanup(&resources, error, sizeof(error))) {
            dprintf(2, "enclio: cgroup cleanup: %s\n", error);
            o.cleanup = false;
        }
    }
    if (!interrupted && !o.reason && c->limits.cpu_seconds && o.signal == SIGXCPU) {
        o.status = "resource_limit";
        o.reason = "cpu";
        o.code = 126;
    }
    if (!interrupted && !o.reason && c->limits.file_bytes && o.signal == SIGXFSZ) {
        o.status = "resource_limit";
        o.reason = "file";
        o.code = 126;
    }
    /* Give already budgeted output a bounded drain window, never block cleanup
     * on an unresponsive caller. Timeout/cancellation may discard pending bytes. */
    long drain = now_ms() + 250;
    struct enclio_output *drains[] = {&outputs[0], &outputs[1], &diagnostic};
    for (;;) {
        bool pending = false;
        for (int i = 0; i < 3; i++)
            if (drains[i]->begin != drains[i]->end)
                pending = true;
        if (!pending || now_ms() >= drain)
            break;
        struct pollfd p[3];
        for (int i = 0; i < 3; i++)
            p[i] = (struct pollfd){.fd = drains[i]->begin != drains[i]->end
                                            ? drains[i]->destination : -1,
                                   .events = POLLOUT};
        (void)poll(p, 3, 10);
        for (int i = 0; i < 3; i++)
            if (p[i].revents & POLLOUT)
                (void)enclio_output_write(drains[i]);
    }
    enclio_output_close(&input);
    for (int i = 0; i < 3; i++)
        enclio_output_close(drains[i]);
    /* Never reap the guardian as an anonymous adopted child: stop() owns its
     * exit status, including allocation failures before the ready handshake. */
    for (int attempt = 0; attempt < 100; attempt++) {
        char children_path[96];
        snprintf(children_path, sizeof(children_path), "/proc/self/task/%ld/children",
                 (long)getpid());
        FILE *children = fopen(children_path, "r");
        if (!children) {
            o.cleanup = false;
            break;
        }
        long adopted;
        bool remaining = false;
        while (fscanf(children, "%ld", &adopted) == 1) {
            if (adopted == (long)guard.pid)
                continue;
            pid_t child_done = waitpid((pid_t)adopted, NULL, WNOHANG);
            if (!child_done || (child_done < 0 && errno == EINTR))
                remaining = true;
        }
        fclose(children);
        if (!remaining)
            break;
        if (attempt == 99)
            o.cleanup = false;
        usleep(10000);
    }
    int *pairs[] = {statusfd, outfd, errfd, infd, diagfd, networkfd};
    for (unsigned i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++)
        for (int j = 0; j < 2; j++)
            if (pairs[i][j] >= 0)
                close(pairs[i][j]);
    if (export_fd >= 0)
        close(export_fd);
    if (created) {
        snprintf(path, sizeof(path), "%s/passwd", temporary);
        unlink(path);
        snprintf(path, sizeof(path), "%s/group", temporary);
        unlink(path);
        if (rmdir(temporary) && errno != ENOENT)
            o.cleanup = false;
    }
    if (enclio_guardian_stop(&guard, created && o.cleanup))
        o.cleanup = false;
    if (!o.cleanup) {
        o.status = "setup_error";
        o.code = 125;
    }
    o.duration = now_ms() - start;
    return o;
}
int main(int argc, char **argv)
{
    pid_t caller = getppid();
    if (argc >= 2 && !strcmp(argv[1], "--internal-init"))
        return enclio_internal_main(argc, argv);
    if (argc == 2 && (!strcmp(argv[1], "version") || !strcmp(argv[1], "--version"))) {
        puts("enclio " ENCLIO_VERSION);
        return 0;
    }
    if (argc < 2 || !strcmp(argv[1], "help") || !strcmp(argv[1], "--help")) {
        usage(stdout);
        return argc < 2 ? 2 : 0;
    }
    if (setup_signals()) {
        dprintf(2, "enclio: cannot initialize signal policy: %s\n", strerror(errno));
        return 125;
    }
    if (prctl(PR_SET_PDEATHSIG, 0)) {
        dprintf(2, "enclio: cannot initialize caller lifetime monitor\n");
        return 125;
    }
    if (caller > 0) {
        caller_fd = (int)syscall(SYS_pidfd_open, caller, 0);
        if (caller_fd < 0 && errno != ESRCH) {
            dprintf(2, "enclio: caller pidfd unavailable: %s\n", strerror(errno));
            return 125;
        }
        if (caller_fd < 0 || getppid() != caller)
            interrupted = SIGTERM;
    }
    struct config c = {0};
    if (!strcmp(argv[1], "doctor")) {
        if (argc != 2 && (argc != 4 || strcmp(argv[2], "--cgroup-parent"))) {
            usage(stderr);
            return 2;
        }
        strcpy(c.workspace, "/tmp");
        c.cwd = "/workspace";
        c.timeout = 5;
        c.strict = true;
        c.workspace_mode = "readonly";
        c.disk_bytes = 4 * 1024 * 1024;
        c.tmp_bytes = c.disk_bytes;
        c.output_bytes = 1024 * 1024;
        if (argc == 4) {
            c.cgroup_parent = argv[3];
            c.limits.memory_bytes = 64 * 1024 * 1024;
            c.limits.pids_max = 64;
            c.limits.cpu_percent = 100;
        }
        char *command[] = {"/bin/true", NULL};
        c.command = command;
        struct outcome o = run(&c);
        struct utsname u;
        memset(&u, 0, sizeof(u));
        uname(&u);
        struct statfs fs;
        bool cg = !statfs("/sys/fs/cgroup", &fs) && (unsigned long)fs.f_type == 0x63677270UL;
        printf("{\"schema_version\":1,\"ready\":%s,\"architecture\":\"%s\",\"kernel\":\"%s\","
               "\"bwrap\":\"/usr/bin/bwrap\","
               "\"sandbox_probe\":\"%s\",\"strict_seccomp\":%s,\"bounded_tmpfs\":%s,\"cgroup_v2\":%"
               "s,\"cgroup_limits_probed\":%s,\"cleanup_complete\":%s}\n",
               o.started && !o.code ? "true" : "false", u.machine, u.release, o.status,
               o.started ? "true" : "false", o.started ? "true" : "false", cg ? "true" : "false",
               o.resources_enforced && !o.code ? "true" : "false", o.cleanup ? "true" : "false");
        return o.code;
    }
    if (strcmp(argv[1], "run") || parse(argc, argv, &c)) {
        dprintf(2, "enclio: invalid arguments/workspace/limit combination; see 'enclio help'\n");
        return 2;
    }
    if (!result_outside(&c)) {
        dprintf(2, "enclio: result must be outside workspace and export directories\n");
        return 2;
    }
    int fd = result_open(c.result);
    if (fd == -2) {
        dprintf(2, "enclio: cannot open regular result file: %s\n", strerror(errno));
        return 125;
    }
    struct outcome o = run(&c);
    if (result_write(fd, &o)) {
        dprintf(2, "enclio: result write failed\n");
        return 125;
    }
    return o.code;
}
