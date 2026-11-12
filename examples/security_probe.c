#define _GNU_SOURCE
/* Finite demonstration payload: all writes stay in caller-authorized mounts
 * or the sandbox scratch filesystem. Run via examples/security_demo.py. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int check(int good, const char *name)
{
    printf("%s %s\n", good ? "PASS" : "FAIL", name);
    return good ? 0 : 1;
}
static int write_all(int fd, const void *data, size_t size)
{
    const char *p = data;
    while (size) {
        ssize_t n = write(fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n; size -= (size_t)n;
    }
    return 0;
}
static int policy_denied(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    struct timeval timeout = {.tv_sec = 3};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
        close(fd); return 0;
    }
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(18080),
                            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    const char request[] = "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n";
    char response[12]; size_t used = 0;
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) ||
        write_all(fd, request, sizeof(request) - 1)) { close(fd); return 0; }
    while (used < sizeof(response)) {
        ssize_t n = read(fd, response + used, sizeof(response) - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(fd); return 0; }
        used += (size_t)n;
    }
    close(fd);
    return !memcmp(response, "HTTP/1.1 403", sizeof(response));
}
static int direct_denied(void)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return 0;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(443)};
    if (inet_pton(AF_INET, "1.1.1.1", &a.sin_addr) != 1) { close(fd); return 0; }
    errno = 0;
    int rc = connect(fd, (struct sockaddr *)&a, sizeof(a));
    int error = errno;
    close(fd);
    /* A real socket/connect must execute and fail because there is no route. */
    return rc < 0 && (error == ENETUNREACH || error == EHOSTUNREACH);
}
static int main_checks(const char *secret)
{
    int failures = 0, fd; char data[64] = {0};
    fd = open("/data/input/message.txt", O_RDONLY);
    ssize_t n = fd < 0 ? -1 : read(fd, data, sizeof(data) - 1);
    if (fd >= 0) close(fd);
    failures += check(n > 0 && !strcmp(data, "READ_ONLY_INPUT\n"), "READ_AUTHORIZED_INPUT");
    errno = 0; fd = open("/data/input/message.txt", O_WRONLY);
    int error = errno; if (fd >= 0) close(fd);
    failures += check(fd < 0 && error == EROFS, "READONLY_WRITE_DENIED_EROFS");
    fd = open("/data/output/result.txt", O_CREAT | O_WRONLY | O_EXCL, 0600);
    int wrote = fd >= 0 && !write_all(fd, "AUTHORIZED_OUTPUT\n", 18);
    if (fd >= 0) close(fd);
    failures += check(wrote, "WRITE_AUTHORIZED_OUTPUT");
    errno = 0; fd = open(secret, O_RDONLY); error = errno;
    if (fd >= 0) close(fd);
    failures += check(fd < 0 && error == ENOENT, "UNMOUNTED_HOST_SECRET_HIDDEN");
    failures += check(!getenv("ENCLIO_DEMO_PRIVATE") && getenv("DEMO_MESSAGE") &&
        !strcmp(getenv("DEMO_MESSAGE"), "hello-from-caller"), "ENVIRONMENT_ALLOWLIST");
    errno = 0; long parent = syscall(SYS_getppid); error = errno;
    failures += check(parent == -1 && error == 42, "CUSTOM_GETPPID_ERRNO_42");
    struct rlimit limit;
    failures += check(!getrlimit(RLIMIT_AS, &limit) && limit.rlim_cur == 268435456,
                      "ADDRESS_SPACE_LIMIT_256MIB");
    failures += check(!getrlimit(RLIMIT_CPU, &limit) && limit.rlim_cur == 5 && limit.rlim_max == 6,
                      "PER_PROCESS_CPU_LIMIT_5_SECONDS");
    int files[128], count = 0;
    if (getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_cur != 64) return 1;
    while (count < 128) {
        fd = open("/dev/null", O_RDONLY);
        if (fd < 0) break;
        files[count++] = fd;
    }
    error = errno;
    for (int i = 0; i < count; i++) close(files[i]);
    failures += check(count < 128 && error == EMFILE, "OPEN_FILES_LIMIT_EMFILE");
    if (signal(SIGXFSZ, SIG_IGN) == SIG_ERR) return 1;
    char block[4096] = {0};
    fd = open("/tmp/limited-file", O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (fd < 0) return 1;
    size_t total = 0; error = 0;
    while (total < 131072) {
        ssize_t w = write(fd, block, sizeof(block));
        if (w < 0) { error = errno; break; }
        if (!w) break;
        total += (size_t)w;
    }
    close(fd);
    failures += check(total == 65536 && error == EFBIG, "FILE_SIZE_LIMIT_EFBIG");
    failures += check(policy_denied(), "UNLISTED_HOST_HTTP_403");
    failures += check(direct_denied(), "DIRECT_IP_HAS_NO_ROUTE");
    pid_t curl = fork();
    if (curl < 0) return 1;
    if (!curl) {
        execlp("curl", "curl", "--fail", "--silent", "--show-error", "--max-time", "30",
               "--output", "/tmp/example.html", "https://example.com/", (char *)NULL);
        _exit(127);
    }
    int status;
    while (waitpid(curl, &status, 0) < 0) if (errno != EINTR) return 1;
    struct stat st;
    failures += check(WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                      !stat("/tmp/example.html", &st) && st.st_size > 0,
                      "ALLOWED_HTTPS_FETCH_SUCCEEDED");
    return failures ? 1 : 0;
}
static int disk_and_export(void)
{
    int fd = open("/workspace/answer.txt", O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (fd < 0 || write_all(fd, "EXPORT_OK\n", 10)) return 1;
    close(fd);
    fd = open("/tmp/fill", O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (fd < 0) return 1;
    char block[4096] = {0}; size_t total = 0; int error = 0;
    while (total < 33554432) {
        ssize_t n = write(fd, block, sizeof(block));
        if (n < 0) { error = errno; break; }
        if (!n) break;
        total += (size_t)n;
    }
    close(fd);
    if (unlink("/tmp/fill")) return 1; /* Release scratch before trusted export. */
    return check(total < 8388608 && (error == ENOSPC || error == EDQUOT),
                 "SHARED_TMPFS_QUOTA_ENOSPC");
}
static int pids(void)
{
    pid_t children[64]; int count = 0, error = 0;
    while (count < 64) {
        pid_t child = fork();
        if (child < 0) { error = errno; break; }
        if (!child) { for (;;) pause(); }
        children[count++] = child;
    }
    for (int i = 0; i < count; i++) (void)kill(children[i], SIGKILL);
    for (int i = 0; i < count; i++)
        while (waitpid(children[i], NULL, 0) < 0 && errno == EINTR) {}
    return check(count < 64 && error == EAGAIN, "AGGREGATE_PIDS_LIMIT_EAGAIN");
}
int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0); puts("PROBE_EXECUTED");
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "check") && argc == 3) return main_checks(argv[2]);
    if (!strcmp(argv[1], "disk")) return disk_and_export();
    if (!strcmp(argv[1], "pids")) return pids();
    if (!strcmp(argv[1], "timeout")) { sleep(10); return 1; }
    if (!strcmp(argv[1], "output")) {
        char data[4096]; memset(data, 'X', sizeof(data));
        for (unsigned i = 0; i < 256; i++) if (write_all(1, data, sizeof(data))) return 1;
        return 1;
    }
    if (!strcmp(argv[1], "memory")) {
        volatile unsigned char *pages[16];
        for (int i = 0; i < 16; i++) {
            pages[i] = malloc(8388608);
            if (!pages[i]) return 1;
            for (size_t j = 0; j < 8388608; j += 4096) pages[i][j] = (unsigned char)i;
        }
        puts("FAIL MEMORY_LIMIT_NOT_TRIGGERED"); return 1;
    }
    return 2;
}
