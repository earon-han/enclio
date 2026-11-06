#define _GNU_SOURCE
#include "tegum.h"
#include "proxy.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static void report(char c) { (void)!write(3, &c, 1); }
static void child_failure(int fd, int error) {
    (void)!write(fd, &error, sizeof(error));
    _exit(127);
}

int tg_internal_main(int argc, char **argv)
{
    /* Same-UID payloads must not open the trusted supervisor/relay's procfs
     * memory or control FDs. This is inherited by the relay, reset on exec. */
    if (prctl(PR_SET_DUMPABLE, 0) < 0) return 125;
    if (argc < 5 || (strcmp(argv[2], "0") && strcmp(argv[2], "1"))) return 125;
    char *end;
    long env_count = strtol(argv[3], &end, 10);
    if (*end || env_count < 0 || env_count > TG_MAX_ENV || argc <= 4 + env_count) return 125;
    int command_index = 4 + (int)env_count;
    int network = !strcmp(argv[2], "1");
    pid_t relay = -1;
    pid_t supervisor = getpid();
    signal(SIGPIPE, SIG_IGN);
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core) < 0) goto fail;
    if (network) {
        relay = fork();
        if (relay < 0) goto fail;
        if (!relay) {
            close(3);
            if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != supervisor) _exit(125);
            _exit(tg_relay_serve("/.tegum/proxy/egress.sock", TG_PROXY_PORT) ? 125 : 0);
        }
        int ready = 0;
        for (int i = 0; i < 200; i++) {
            int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            struct sockaddr_in addr = {.sin_family = AF_INET,
                .sin_port = htons(TG_PROXY_PORT), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
            if (fd >= 0) {
                ready = connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0;
                close(fd);
            }
            if (ready) break;
            if (waitpid(relay, NULL, WNOHANG) == relay) goto fail;
            usleep(10000);
        }
        if (!ready) goto fail;
    }
    /* Apply to supervisor and command, after the trusted relay was forked. */
    if (tg_install_seccomp() < 0) goto fail;
    int handshake[2];
    if (pipe2(handshake, O_CLOEXEC) < 0) goto fail;
    pid_t child = fork();
    if (child < 0) { close(handshake[0]); close(handshake[1]); goto fail; }
    if (!child) {
        close(handshake[0]);
        close(3);
        signal(SIGPIPE, SIG_DFL);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != supervisor)
            child_failure(handshake[1], errno ? errno : ECHILD);
        /* User environment is applied only after the security filter is active.
         * In particular LD_PRELOAD must never reach the trusted init/relay. */
        for (int i = 4; i < command_index; i++) {
            char *eq = strchr(argv[i], '=');
            if (!eq) child_failure(handshake[1], EINVAL);
            *eq = 0;
            if (setenv(argv[i], eq + 1, 1)) child_failure(handshake[1], errno);
        }
        execvp(argv[command_index], &argv[command_index]);
        int saved = errno;
        dprintf(2, "tegum: command exec: %s\n", strerror(saved));
        child_failure(handshake[1], saved);
    }
    close(handshake[1]);
    int exec_errno = 0;
    ssize_t n;
    do { n = read(handshake[0], &exec_errno, sizeof(exec_errno)); } while (n < 0 && errno == EINTR);
    close(handshake[0]);
    report(n == 0 ? 'S' : 'E');
    int status;
    for (;;) {
        pid_t done = waitpid(-1, &status, 0);
        if (done == child) break;
        if (done == relay) {
            relay = -1;
            report('E'); close(3);
            kill(child, SIGKILL); waitpid(child, NULL, 0);
            return 125;
        }
        if (done < 0 && errno != EINTR) { report('E'); close(3); return 125; }
    }
    if (WIFSIGNALED(status)) report((char)(128 + WTERMSIG(status)));
    close(3);
    if (relay > 0) { kill(relay, SIGTERM); while (waitpid(relay, NULL, 0) < 0 && errno == EINTR) {} }
    if (n != 0) return 125;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
fail:
    dprintf(2, "tegum: sandbox initialization failed: %s\n", strerror(errno));
    report('E');
    if (relay > 0) { kill(relay, SIGKILL); waitpid(relay, NULL, 0); }
    return 125;
}
