#define _GNU_SOURCE
#include <errno.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static int denied(long value, int err) {
    return value == -1 && errno == err ? 0 : 1;
}
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("PROBE_EXECUTED");
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "seccomp")) {
        if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
            prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 2) return 10;
        if (denied(socket(AF_PACKET, SOCK_DGRAM, 0), EPERM)) return 11;
        if (denied(socket(AF_VSOCK, SOCK_STREAM, 0), EPERM)) return 12;
        if (denied(socket(AF_INET, SOCK_RAW, 1), EPERM)) return 13;
        if (denied(unshare(CLONE_NEWUSER), EPERM)) return 14;
#ifdef SYS_clone3
        struct clone_args args = {0};
        if (denied(syscall(SYS_clone3, &args, sizeof(args)), ENOSYS)) return 15;
#endif
#ifdef SYS_io_uring_setup
        if (denied(syscall(SYS_io_uring_setup, 1, NULL), EPERM)) return 16;
#endif
#ifdef SYS_keyctl
        if (denied(syscall(SYS_keyctl, 0, 0, 0, 0, 0), EPERM)) return 17;
#endif
        if (denied(syscall(SYS_ioctl, -1, 0x100005412ULL, NULL), EPERM)) return 18;
        return 0;
    }
    if (!strcmp(argv[1], "control")) {
        DIR *proc = opendir("/proc");
        if (!proc) return 40;
        struct dirent *entry;
        int found = 0, found_one = 0;
        while ((entry = readdir(proc))) {
            char *end;
            long pid = strtol(entry->d_name, &end, 10);
            if (*end || pid <= 0 || pid == getpid()) continue;
            char path[80];
            snprintf(path, sizeof(path), "/proc/%ld/status", pid);
            int fd = open(path, O_RDONLY);
            if (fd < 0) return 41;
            close(fd);
            found++; if (pid == 1) found_one = 1;
            snprintf(path, sizeof(path), "/proc/%ld/mem", pid);
            fd = open(path, O_RDWR);
            if (fd >= 0) { close(fd); return 42; }
            if (errno != EACCES && errno != EPERM) return 43;
            snprintf(path, sizeof(path), "/proc/%ld/fd/3", pid);
            fd = open(path, O_WRONLY);
            if (fd >= 0) { close(fd); return 44; }
            if (errno != EACCES && errno != EPERM && errno != ENOENT) return 45;
        }
        closedir(proc);
        printf("TRUSTED_PROCESSES_CHECKED=%d\n", found);
        return found_one && found >= 1 ? 0 : 46;
    }
    if (!strcmp(argv[1], "fds")) {
        for (int fd = 3; fd < 1024; fd++) {
            errno = 0;
            if (fcntl(fd, F_GETFD) >= 0 || errno != EBADF) {
                fprintf(stderr, "unexpected inherited fd: %d\n", fd);
                return 20;
            }
        }
        return 0;
    }
    if (!strcmp(argv[1], "env")) {
        if (getenv("ENCLIO_HOST_SECRET") || getenv("SSH_AUTH_SOCK") ||
            getenv("LD_PRELOAD") || getenv("BASH_ENV")) return 21;
        return getenv("EXPLICIT_TEST") &&
            !strcmp(getenv("EXPLICIT_TEST"), "hello world") ? 0 : 22;
    }
    if (!strcmp(argv[1], "filesystem") && argc == 3) {
        int fd = open("/workspace/authorized", O_CREAT | O_WRONLY, 0600);
        if (fd < 0 || write(fd, "allowed", 7) != 7) return 30;
        close(fd);
        fd = open("/usr/enclio-must-not-write", O_CREAT | O_WRONLY, 0600);
        if (fd >= 0) { close(fd); return 31; }
        if (errno != EROFS && errno != EACCES) return 32;
        fd = open(argv[2], O_RDONLY);
        if (fd >= 0) { close(fd); return 33; }
        fd = open("/workspace/escape", O_RDONLY);
        if (fd >= 0) { close(fd); return 34; }
        fd = open("/workspace/../../etc/shadow", O_RDONLY);
        if (fd >= 0) { close(fd); return 35; }
        return 0;
    }
    if ((!strcmp(argv[1], "daemon") || !strcmp(argv[1], "daemon-hold")) && argc == 3) {
        int ready[2];
        if (pipe(ready) < 0) return 60;
        pid_t daemon = fork();
        if (daemon < 0) { close(ready[0]); close(ready[1]); return 61; }
        if (daemon > 0) {
            char marker = 0;
            close(ready[1]);
            ssize_t n = read(ready[0], &marker, 1);
            close(ready[0]);
            if (n != 1 || marker != 'R') return 62;
            if (!strcmp(argv[1], "daemon-hold")) { puts("CHILD_SPAWNED"); sleep(20); }
            return 0;
        }
        close(ready[0]);
        if (setsid() < 0) { close(ready[1]); _exit(63); }
        if (write(ready[1], "R", 1) != 1) _exit(64);
        close(ready[1]);
        usleep(750000);
        int fd = open(argv[2], O_CREAT | O_WRONLY, 0600);
        if (fd >= 0) { (void)!write(fd, "LEAK", 4); close(fd); }
        _exit(0);
    }
    if (!strcmp(argv[1], "listener-hold")) {
        /* The payload inherits neither listener nor handoff channel. */
        for (int fd = 3; fd < 1024; fd++)
            if (fcntl(fd, F_GETFD) >= 0 || errno != EBADF) return 50;
        struct stat st;
        if (!stat("/.enclio/proxy", &st) || errno != ENOENT) return 51;
        DIR *proc = opendir("/proc");
        if (!proc) return 52;
        struct dirent *entry;
        while ((entry = readdir(proc))) {
            char *end, path[80], name[64] = {0};
            long pid = strtol(entry->d_name, &end, 10);
            if (*end || pid <= 0) continue;
            snprintf(path, sizeof(path), "/proc/%ld/comm", pid);
            FILE *f = fopen(path, "r");
            if (!f) { closedir(proc); return 53; }
            if (!fgets(name, sizeof(name), f)) { fclose(f); closedir(proc); return 53; }
            fclose(f);
            if (!strncmp(name, "enclio-relay", 12)) { closedir(proc); return 54; }
        }
        closedir(proc);
        FILE *tcp = fopen("/proc/net/tcp", "r");
        if (!tcp) return 55;
        char line[512]; unsigned long inode = 0;
        while (fgets(line, sizeof(line), tcp)) {
            unsigned ip, port, state; unsigned long candidate;
            if (sscanf(line, "%*u: %x:%x %*s %x %*s %*s %*s %*s %*s %lu",
                       &ip, &port, &state, &candidate) == 4 &&
                ip == 0x0100007fU && port == 18080 && state == 0x0a) inode = candidate;
        }
        fclose(tcp);
        if (!inode) return 56;
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(18080),
                                     .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        if (fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof(address))) return 57;
        char request[512], response[13] = {0};
        const char *denied_host = argc == 3 ? argv[2] : "unlisted.invalid";
        int length = snprintf(request, sizeof(request),
                              "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n",
                              denied_host, denied_host);
        if (length <= 0 || (size_t)length >= sizeof(request) ||
            write(fd, request, (size_t)length) != length) { close(fd); return 58; }
        size_t received = 0;
        while (received < 12) {
            ssize_t n = read(fd, response + received, 12 - received);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { close(fd); return 59; }
            received += (size_t)n;
        }
        if (strcmp(response, "HTTP/1.1 403")) { close(fd); return 59; }
        close(fd);
        printf("LISTENER_INODE=%lu\n", inode);
        puts("POLICY_DENIED");
        sleep(20);
        return 0;
    }
    return 2;
}
