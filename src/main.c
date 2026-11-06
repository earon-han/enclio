#define _GNU_SOURCE
#include "tegum.h"
#include "proxy.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct config {
    char workspace[PATH_MAX];
    const char *cwd, *result;
    const char *hosts[TG_MAX_HOSTS], *env[TG_MAX_ENV];
    size_t nhosts, nenv;
    unsigned timeout;
    char **command;
};
struct outcome { const char *status; int code, signal; bool started; long duration; };
static volatile sig_atomic_t interrupted;
static void on_signal(int sig) { interrupted = sig; }
static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}
static void usage(FILE *f) {
    fprintf(f, "tegum " TG_VERSION " — Linux agent sandbox\n"
        "Usage: tegum run --workspace DIR [--timeout SECONDS] [--result FILE]\n"
        "       [--cwd /workspace/PATH] [--allow-host DOMAIN] [--env NAME=VALUE]\n"
        "       -- COMMAND [ARGS...]\n"
        "       tegum doctor | version | help\n"
        "Default: no external network, 300s timeout. --allow-host permits CONNECT to port 443.\n");
}
static int parse(int argc, char **argv, struct config *c) {
    c->timeout = 300; c->cwd = "/workspace";
    const char *workspace = NULL;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--")) { c->command = &argv[i+1]; break; }
        if (i + 1 >= argc) return -1;
        const char *key = argv[i++], *val = argv[i];
        if (!strcmp(key, "--workspace")) workspace = val;
        else if (!strcmp(key, "--cwd")) c->cwd = val;
        else if (!strcmp(key, "--result")) c->result = val;
        else if (!strcmp(key, "--timeout")) {
            char *end; errno = 0;
            unsigned long n = strtoul(val, &end, 10);
            if (errno || !*val || *end || n < 1 || n > 86400) return -1;
            c->timeout = (unsigned)n;
        } else if (!strcmp(key, "--allow-host")) {
            if (c->nhosts == TG_MAX_HOSTS || !tg_proxy_host_valid(val)) return -1;
            c->hosts[c->nhosts++] = val;
        } else if (!strcmp(key, "--env")) {
            const char *eq = strchr(val, '=');
            if (c->nenv == TG_MAX_ENV || !eq || eq == val) return -1;
            for (const char *p = val; p < eq; p++)
                if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
                    (*p == '_') || (p > val && *p >= '0' && *p <= '9'))) return -1;
            c->env[c->nenv++] = val;
        } else return -1;
    }
    struct stat st;
    if (!workspace || !c->command || !c->command[0] ||
        !realpath(workspace, c->workspace) || stat(c->workspace, &st) || !S_ISDIR(st.st_mode))
        return -1;
    /* Do not allow accidental exposure of the complete host root. */
    if (!strcmp(c->workspace, "/") ||
        (strcmp(c->cwd, "/workspace") && strncmp(c->cwd, "/workspace/", 11))) return -1;
    return 0;
}
static void close_extra_fds(void) {
    DIR *dir = opendir("/proc/self/fd");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            int fd = atoi(entry->d_name);
            if (fd > 3 && fd != dirfd(dir)) close(fd);
        }
        closedir(dir);
    } else {
        long n = sysconf(_SC_OPEN_MAX);
        for (int fd = 4; fd < n; fd++) close(fd);
    }
}
static void kill_group(pid_t pid) {
    if (pid <= 0) return;
    kill(-pid, SIGTERM);
    usleep(100000);
    kill(-pid, SIGKILL);
}
static int result_open(const char *path) {
    if (!path) return -1;
    int fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    struct stat st;
    if (fd < 0) return -2;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 || ftruncate(fd, 0)) {
        close(fd); return -2;
    }
    return fd;
}
static bool result_outside_workspace(const struct config *c) {
    if (!c->result) return true;
    char resolved[PATH_MAX], copy[PATH_MAX];
    if (strlen(c->result) >= sizeof(copy)) return false;
    if (!realpath(c->result, resolved)) {
        strcpy(copy, c->result);
        char *slash = strrchr(copy, '/');
        const char *base = slash ? slash + 1 : copy;
        if (!*base || !strcmp(base, ".") || !strcmp(base, "..")) return false;
        if (slash) { *slash = 0; if (!realpath(*copy ? copy : "/", resolved)) return false; }
        else if (!realpath(".", resolved)) return false;
        size_t len = strlen(resolved);
        if (len + 1 + strlen(base) >= sizeof(resolved)) return false;
        resolved[len++] = '/'; strcpy(resolved + len, base);
    }
    size_t n = strlen(c->workspace);
    return strncmp(resolved, c->workspace, n) || (resolved[n] && resolved[n] != '/');
}
static int result_write(int fd, const struct outcome *o) {
    if (fd < 0) return 0;
    int n = dprintf(fd, "{\"schema_version\":1,\"status\":\"%s\",\"exit_code\":%d,"
        "\"signal\":%d,\"duration_ms\":%ld,\"command_started\":%s}\n",
        o->status, o->code, o->signal, o->duration, o->started ? "true" : "false");
    int rc = n < 0 || fsync(fd) < 0 ? -1 : 0;
    close(fd); return rc;
}

static void bwrap_exec(const struct config *c, const char *self, const char *temp, int report_fd,
                       pid_t parent)
{
    if (setpgid(0, 0) || prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(125);
    if (dup2(report_fd, 3) < 0 || fcntl(3, F_SETFD, 0) < 0) _exit(125);
    close_extra_fds();
    char *args[1024]; size_t n = 0;
#define A(s) do { if (n >= 1023) _exit(125); args[n++] = (char *)(s); } while (0)
    A("/usr/bin/bwrap"); A("--die-with-parent"); A("--new-session");
    A("--unshare-user"); A("--unshare-pid"); A("--as-pid-1"); A("--unshare-ipc");
    A("--unshare-uts"); A("--unshare-net"); A("--disable-userns");
    A("--cap-drop"); A("ALL"); A("--hostname"); A("tegum");
    A("--clearenv");
    const char *system[] = {"/usr", "/bin", "/sbin", "/lib", "/lib64", NULL};
    for (unsigned i = 0; system[i]; i++) {
        if (!access(system[i], F_OK)) { A("--ro-bind"); A(system[i]); A(system[i]); }
    }
    A("--dir"); A("/etc");
    char passwd_path[PATH_MAX], group_path[PATH_MAX];
    snprintf(passwd_path, sizeof(passwd_path), "%s/passwd", temp);
    snprintf(group_path, sizeof(group_path), "%s/group", temp);
    A("--ro-bind"); A(passwd_path); A("/etc/passwd");
    A("--ro-bind"); A(group_path); A("/etc/group");
    if (!access("/etc/ssl/certs", F_OK)) { A("--ro-bind"); A("/etc/ssl/certs"); A("/etc/ssl/certs"); }
    if (!access("/etc/ld.so.cache", F_OK)) { A("--ro-bind"); A("/etc/ld.so.cache"); A("/etc/ld.so.cache"); }
    A("--proc"); A("/proc"); A("--dev"); A("/dev"); A("--tmpfs"); A("/tmp");
    A("--tmpfs"); A("/home"); A("--dir"); A("/home/agent");
    A("--dir"); A("/run"); A("--dir"); A("/.tegum");
    A("--ro-bind"); A(self); A("/.tegum/tegum");
    if (c->nhosts) { A("--ro-bind"); A(temp); A("/.tegum/proxy"); }
    A("--bind"); A(c->workspace); A("/workspace");
    A("--chdir"); A(c->cwd);
    A("--setenv"); A("PATH"); A("/usr/local/bin:/usr/bin:/bin");
    A("--setenv"); A("HOME"); A("/home/agent");
    A("--setenv"); A("LANG"); A("C.UTF-8");
    A("--setenv"); A("TMPDIR"); A("/tmp");
    if (c->nhosts) {
        const char *vars[] = {"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", NULL};
        for (unsigned i = 0; vars[i]; i++) { A("--setenv"); A(vars[i]); A("http://127.0.0.1:18080"); }
        A("--setenv"); A("NO_PROXY"); A(""); A("--setenv"); A("no_proxy"); A("");
    }
    A("--"); A("/.tegum/tegum"); A("--internal-init"); A(c->nhosts ? "1" : "0");
    char env_count[24]; snprintf(env_count, sizeof(env_count), "%zu", c->nenv);
    A(env_count);
    for (size_t i = 0; i < c->nenv; i++) A(c->env[i]);
    for (char **p = c->command; *p; p++) A(*p);
    args[n] = NULL;
    if (clearenv()) _exit(125);
    execv(args[0], args);
    dprintf(2, "tegum: cannot execute /usr/bin/bwrap: %s\n", strerror(errno));
    _exit(125);
#undef A
}

static struct outcome run(const struct config *c)
{
    struct outcome o = {.status = "setup_error", .code = 125};
    long start = now_ms();
    char temp[] = "/tmp/tegum-XXXXXX", socket_path[PATH_MAX], self[PATH_MAX];
    pid_t proxy = -1, child = -1;
    int pipefd[2] = {-1, -1};
    bool temp_created = false, reaped = false, failed = false;
    pid_t parent = getpid();
    if (getuid() == 0 || geteuid() != getuid() || getegid() != getgid()) {
        dprintf(2, "tegum: run as an ordinary, non-setuid user (also inside Docker)\n"); goto done;
    }
    for (int fd = 0; fd <= 2; fd++) {
        struct stat st;
        if (fstat(fd, &st) || S_ISSOCK(st.st_mode)) {
            dprintf(2, "tegum: stdio must be open and cannot be a socket\n"); goto done;
        }
    }
    ssize_t length = readlink("/proc/self/exe", self, sizeof(self)-1);
    if (length < 0 || (size_t)length >= sizeof(self)-1) goto done;
    self[length] = 0;
    if (access("/usr/bin/bwrap", X_OK) || !mkdtemp(temp)) {
        dprintf(2, "tegum: require /usr/bin/bwrap and writable /tmp\n"); goto done;
    }
    temp_created = true;
    snprintf(socket_path, sizeof(socket_path), "%s/egress.sock", temp);
    char metadata[PATH_MAX];
    snprintf(metadata, sizeof(metadata), "%s/passwd", temp);
    int mfd = open(metadata, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (mfd < 0) goto done;
    int written = dprintf(mfd, "agent:x:%u:%u:Agent:/home/agent:/bin/sh\n", getuid(), getgid());
    close(mfd); if (written < 0) goto done;
    snprintf(metadata, sizeof(metadata), "%s/group", temp);
    mfd = open(metadata, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (mfd < 0) goto done;
    written = dprintf(mfd, "agent:x:%u:\n", getgid());
    close(mfd); if (written < 0) goto done;
    if (prctl(PR_SET_CHILD_SUBREAPER, 1)) goto done;
    if (c->nhosts) {
        proxy = fork();
        if (proxy < 0) goto done;
        if (!proxy) {
            if (setpgid(0, 0) || prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(125);
            signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL); signal(SIGHUP, SIG_DFL);
            /* Proxy never receives the caller's environment or inherited FDs. */
            close(3); close_extra_fds();
            if (clearenv()) _exit(125);
            _exit(tg_proxy_serve(socket_path, c->hosts, c->nhosts) ? 125 : 0);
        }
        setpgid(proxy, proxy);
        bool ready = false;
        for (int i = 0; i < 200 && !interrupted; i++) {
            if (now_ms() - start >= (long)c->timeout * 1000) {
                o.status = "timeout"; o.code = 124; goto done;
            }
            struct stat st;
            if (!lstat(socket_path, &st) && S_ISSOCK(st.st_mode)) { ready = true; break; }
            if (waitpid(proxy, NULL, WNOHANG) == proxy) { proxy = -1; break; }
            usleep(10000);
        }
        if (!ready) { dprintf(2, "tegum: proxy failed to start\n"); goto done; }
    }
    if (pipe2(pipefd, O_CLOEXEC | O_NONBLOCK)) goto done;
    child = fork();
    if (child < 0) goto done;
    if (!child) { close(pipefd[0]); bwrap_exec(c, self, temp, pipefd[1], parent); }
    setpgid(child, child);
    close(pipefd[1]); pipefd[1] = -1;
    int status = 0;
    for (;;) {
        unsigned char state;
        while (read(pipefd[0], &state, 1) == 1) {
            if (state == 'S') o.started = true;
            if (state == 'E') failed = true;
            if (state > 128 && state < 193) o.signal = state - 128;
        }
        pid_t rc = waitpid(child, &status, WNOHANG);
        if (rc == child) { reaped = true; break; }
        if (rc < 0 && errno != EINTR) goto done;
        if (interrupted) { o.status = "cancelled"; o.signal = interrupted; o.code = 128 + interrupted; goto done; }
        if (now_ms() - start >= (long)c->timeout * 1000) { o.status = "timeout"; o.code = 124; goto done; }
        if (proxy > 0 && waitpid(proxy, NULL, WNOHANG) == proxy) {
            proxy = -1; dprintf(2, "tegum: proxy exited unexpectedly\n"); goto done;
        }
        usleep(10000);
    }
    /* Drain the readiness marker when a very short command already exited. */
    unsigned char state;
    while (read(pipefd[0], &state, 1) == 1) {
        if (state == 'S') o.started = true;
        if (state == 'E') failed = true;
        if (state > 128 && state < 193) o.signal = state - 128;
    }
    if (o.started && !failed) {
        o.status = "exited";
        if (WIFSIGNALED(status)) o.signal = WTERMSIG(status);
        o.code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + o.signal;
    }
done:
    if (interrupted) { o.status = "cancelled"; o.signal = interrupted; o.code = 128 + interrupted; }
    if (child > 0) {
        if (!reaped) kill_group(child);
        if (!reaped) while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    }
    if (proxy > 0) { kill_group(proxy); while (waitpid(proxy, NULL, 0) < 0 && errno == EINTR) {} }
    /* Namespace PID 1 and PDEATHSIG dispose of descendants; subreaper reaps them. */
    for (int i = 0; i < 100; i++) {
        pid_t p = waitpid(-1, NULL, WNOHANG);
        if (p < 0 && errno == ECHILD) break;
        if (p == 0) usleep(10000);
    }
    if (pipefd[0] >= 0) close(pipefd[0]);
    if (pipefd[1] >= 0) close(pipefd[1]);
    if (temp_created) {
        unlink(socket_path);
        snprintf(metadata, sizeof(metadata), "%s/passwd", temp); unlink(metadata);
        snprintf(metadata, sizeof(metadata), "%s/group", temp); unlink(metadata);
        rmdir(temp);
    }
    o.duration = now_ms() - start;
    return o;
}

int main(int argc, char **argv)
{
    pid_t caller = getppid();
    if (argc >= 2 && !strcmp(argv[1], "--internal-init")) return tg_internal_main(argc, argv);
    if (argc == 2 && (!strcmp(argv[1], "version") || !strcmp(argv[1], "--version"))) {
        puts("tegum " TG_VERSION); return 0;
    }
    if (argc < 2 || !strcmp(argv[1], "help") || !strcmp(argv[1], "--help")) {
        usage(stdout); return argc < 2 ? 2 : 0;
    }
    struct sigaction sa = {.sa_handler = on_signal};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL); sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    /* Agent death cancels its task. Install the handler before arming the
     * parent-death signal, and close the race with an exact parent check. */
    if (prctl(PR_SET_PDEATHSIG, SIGTERM)) {
        dprintf(2, "tegum: cannot supervise caller lifetime\n"); return 125;
    }
    if (getppid() != caller) interrupted = SIGTERM;
    struct config c = {0};
    if (argc == 2 && !strcmp(argv[1], "doctor")) {
        char tmp[] = "/tmp/tegum-doctor-XXXXXX";
        if (!mkdtemp(tmp)) return 125;
        strcpy(c.workspace, tmp); c.cwd = "/workspace"; c.timeout = 5;
        char *cmd[] = {"/bin/true", NULL}; c.command = cmd;
        struct outcome o = run(&c);
        rmdir(tmp);
        struct utsname u; memset(&u, 0, sizeof(u)); uname(&u);
        printf("{\"schema_version\":1,\"ready\":%s,\"architecture\":\"%s\",\"kernel\":\"%s\","
               "\"bwrap\":\"/usr/bin/bwrap\",\"sandbox_probe\":\"%s\"}\n",
               o.started && !o.code ? "true" : "false", u.machine, u.release, o.status);
        return o.code;
    }
    if (strcmp(argv[1], "run") || parse(argc, argv, &c)) {
        dprintf(2, "tegum: invalid arguments or workspace; see 'tegum help'\n"); return 2;
    }
    if (!result_outside_workspace(&c)) {
        dprintf(2, "tegum: result must reside outside the writable workspace\n"); return 2;
    }
    int fd = result_open(c.result);
    if (fd == -2) { dprintf(2, "tegum: cannot open regular result file: %s\n", strerror(errno)); return 125; }
    struct outcome o = run(&c);
    if (result_write(fd, &o)) { dprintf(2, "tegum: result write failed\n"); return 125; }
    return o.code;
}
