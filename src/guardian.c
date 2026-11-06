#define _GNU_SOURCE
#include "guardian.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int cleanup_files(const char *directory)
{
    const char *files[] = {"passwd", "group", NULL};
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) {
        for (unsigned i = 0; files[i]; i++)
            (void)unlinkat(fd, files[i], 0);
        close(fd);
    }
    return !rmdir(directory) || errno == ENOENT ? 0 : -1;
}
static void guardian_loop(int control, const char *temporary, struct enclio_resources resources,
                          int caller_fd, int owner_fd)
{
    int children[8], count = 0;
    if (prctl(PR_SET_DUMPABLE, 0) || prctl(PR_SET_NAME, "enclio-guard"))
        _exit(125);
    signal(SIGPIPE, SIG_IGN);
    /* Do not hold any descriptor that keeps the caller's output or control
     * write end alive after caller death. Only explicit cleanup handles stay. */
    DIR *directory = opendir("/proc/self/fd");
    if (!directory)
        _exit(125);
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        int fd = 0;
        if (sscanf(entry->d_name, "%d", &fd) != 1)
            continue;
        if (fd != control && fd != dirfd(directory) && fd != resources.parent_fd &&
            fd != resources.group_fd && fd != caller_fd && fd != owner_fd)
            close(fd);
    }
    closedir(directory);
    bool caller_dead = false;
    long caller_deadline = 0;
    for (;;) {
        struct pollfd sources[2] = {{.fd = control, .events = POLLIN},
                                    {.fd = caller_fd, .events = POLLIN}};
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long milliseconds = now.tv_sec * 1000L + now.tv_nsec / 1000000L;
        if (caller_dead && milliseconds >= caller_deadline) {
            (void)syscall(SYS_pidfd_send_signal, owner_fd, SIGKILL, NULL, 0);
            break;
        }
        int wait_ms = caller_dead ? (int)(caller_deadline - milliseconds) : -1;
        int ready = poll(sources, 2, wait_ms);
        if (!ready)
            continue;
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready < 0 || (sources[0].revents & POLLNVAL) || (sources[1].revents & POLLNVAL))
            break;
        if (sources[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            /* A pidfd without PIDFD_THREAD observes the caller process, not
             * merely the worker thread that happened to launch this CLI. */
            for (int i = 0; i < count; i++)
                (void)syscall(SYS_pidfd_send_signal, children[i], SIGKILL, NULL, 0);
            if (syscall(SYS_pidfd_send_signal, owner_fd, SIGTERM, NULL, 0))
                break;
            caller_dead = true;
            clock_gettime(CLOCK_MONOTONIC, &now);
            caller_deadline = now.tv_sec * 1000L + now.tv_nsec / 1000000L + 5000;
            close(caller_fd);
            caller_fd = -1;
        }
        if (!(sources[0].revents & (POLLIN | POLLHUP | POLLERR)))
            continue;
        char command = 0;
        struct iovec iov = {.iov_base = &command, .iov_len = 1};
        union {
            struct cmsghdr align;
            char data[CMSG_SPACE(sizeof(int))];
        } ancillary;
        memset(&ancillary, 0, sizeof(ancillary));
        struct msghdr msg = {.msg_iov = &iov,
                             .msg_iovlen = 1,
                             .msg_control = ancillary.data,
                             .msg_controllen = sizeof(ancillary.data)};
        ssize_t n = recvmsg(control, &msg, MSG_CMSG_CLOEXEC);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        if (command == 'Q') {
            for (int i = 0; i < count; i++)
                close(children[i]);
            _exit(0);
        }
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        if (command != 'P' || !c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
            c->cmsg_len != CMSG_LEN(sizeof(int)) || count == 8)
            break;
        memcpy(&children[count++], CMSG_DATA(c), sizeof(int));
        if (caller_dead)
            (void)syscall(SYS_pidfd_send_signal, children[count - 1], SIGKILL, NULL, 0);
        if (send(control, "A", 1, MSG_NOSIGNAL) != 1)
            break;
    }
    /* pidfds bind signals to the registered process identity, even if a numeric
     * PID has since been reused. Descendants are tied to PID1/PDEATHSIG/cgroup. */
    for (int i = 0; i < count; i++)
        (void)syscall(SYS_pidfd_send_signal, children[i], SIGKILL, NULL, 0);
    char error[256];
    bool failed = false;
    if (resources.active && enclio_resources_cleanup(&resources, error, sizeof(error)))
        failed = true;
    struct pollfd waits[8];
    for (int i = 0; i < count; i++)
        waits[i] = (struct pollfd){.fd = children[i], .events = POLLIN};
    for (int attempt = 0; attempt < 100; attempt++) {
        bool complete = true;
        for (int i = 0; i < count; i++)
            if (waits[i].fd >= 0)
                complete = false;
        if (complete)
            break;
        (void)poll(waits, (nfds_t)count, 50);
        for (int i = 0; i < count; i++)
            if (waits[i].revents & (POLLIN | POLLHUP | POLLERR))
                waits[i].fd = -1;
    }
    for (int i = 0; i < count; i++) {
        if (waits[i].fd >= 0)
            failed = true;
        close(children[i]);
    }
    if (cleanup_files(temporary))
        failed = true;
    _exit(failed ? 1 : 0);
}
struct guard_ready {
    int error_code;
    bool active;
    char temporary[64], group[96], error[256];
};
int enclio_guardian_start(struct enclio_guardian *guard, char *temporary, size_t temporary_size,
                          const char *cgroup_parent, const struct enclio_resource_limits *limits,
                          struct enclio_resources *resources, char *error, size_t error_size,
                          unsigned startup_timeout_ms, int caller_fd)
{
    int channel[2];
    guard->pid = -1;
    guard->fd = -1;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel))
        return -1;
    pid_t owner = getpid();
    pid_t pid = fork();
    if (pid < 0) {
        close(channel[0]);
        close(channel[1]);
        return -1;
    }
    if (!pid) {
        close(channel[0]);
        int owner_fd = (int)syscall(SYS_pidfd_open, owner, 0);
        if (owner_fd < 0 || getppid() != owner)
            _exit(125);
        struct enclio_resources owned = {.parent_fd = -1, .group_fd = -1};
        struct guard_ready ready = {0};
        (void)prctl(PR_SET_DUMPABLE, 0);
        (void)prctl(PR_SET_NAME, "enclio-guard");
        signal(SIGPIPE, SIG_IGN);
        /* The guardian owns allocations from their first instant, including a
         * caller killed while it is still preparing the job's cgroup. */
        bool created = mkdtemp(temporary) != NULL;
        if (!created)
            ready.error_code = errno;
        else if (enclio_resources_prepare(cgroup_parent, limits, &owned, ready.error,
                                          sizeof(ready.error)))
            ready.error_code = errno ? errno : EPERM;
        snprintf(ready.temporary, sizeof(ready.temporary), "%s", temporary);
        snprintf(ready.group, sizeof(ready.group), "%s", owned.name);
        ready.active = owned.active;
        struct iovec iov = {.iov_base = &ready, .iov_len = sizeof(ready)};
        union {
            struct cmsghdr align;
            char data[CMSG_SPACE(2 * sizeof(int))];
        } control;
        memset(&control, 0, sizeof(control));
        struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
        if (owned.active) {
            msg.msg_control = control.data;
            msg.msg_controllen = sizeof(control.data);
            struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
            c->cmsg_level = SOL_SOCKET;
            c->cmsg_type = SCM_RIGHTS;
            c->cmsg_len = CMSG_LEN(2 * sizeof(int));
            int descriptors[] = {owned.parent_fd, owned.group_fd};
            memcpy(CMSG_DATA(c), descriptors, sizeof(descriptors));
        }
        if (sendmsg(channel[1], &msg, MSG_NOSIGNAL) != (ssize_t)sizeof(ready) || ready.error_code) {
            char reason[256];
            bool failed = false;
            if (owned.active && enclio_resources_cleanup(&owned, reason, sizeof(reason)))
                failed = true;
            if (created && cleanup_files(temporary))
                failed = true;
            _exit(failed ? 1 : 0);
        }
        guardian_loop(channel[1], temporary, owned, caller_fd, owner_fd);
    }
    close(channel[1]);
    guard->pid = pid;
    guard->fd = channel[0];
    struct pollfd wait = {.fd = guard->fd, .events = POLLIN};
    if (poll(&wait, 1, (int)startup_timeout_ms) != 1) {
        errno = ETIMEDOUT;
        return -1;
    }
    struct guard_ready ready = {0};
    struct iovec iov = {.iov_base = &ready, .iov_len = sizeof(ready)};
    union {
        struct cmsghdr align;
        char data[CMSG_SPACE(2 * sizeof(int))];
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr msg = {.msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = control.data,
                         .msg_controllen = sizeof(control.data)};
    if (recvmsg(guard->fd, &msg, MSG_CMSG_CLOEXEC) != (ssize_t)sizeof(ready))
        return -1;
    if (ready.error_code) {
        snprintf(error, error_size, "%s", *ready.error ? ready.error : strerror(ready.error_code));
        errno = ready.error_code;
        return -1;
    }
    if (strlen(ready.temporary) >= temporary_size)
        return -1;
    strcpy(temporary, ready.temporary);
    if (ready.active) {
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
            c->cmsg_len != CMSG_LEN(2 * sizeof(int)))
            return -1;
        int descriptors[2];
        memcpy(descriptors, CMSG_DATA(c), sizeof(descriptors));
        resources->parent_fd = descriptors[0];
        resources->group_fd = descriptors[1];
        resources->active = true;
        strcpy(resources->name, ready.group);
    }
    return 0;
}
int enclio_guardian_track(struct enclio_guardian *guard, pid_t process)
{
    int fd = (int)syscall(SYS_pidfd_open, process, 0);
    if (fd < 0)
        return -1;
    char command = 'P';
    struct iovec iov = {.iov_base = &command, .iov_len = 1};
    union {
        struct cmsghdr align;
        char data[CMSG_SPACE(sizeof(int))];
    } ancillary;
    memset(&ancillary, 0, sizeof(ancillary));
    struct msghdr msg = {.msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = ancillary.data,
                         .msg_controllen = sizeof(ancillary.data)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(fd));
    ssize_t n = sendmsg(guard->fd, &msg, MSG_NOSIGNAL);
    close(fd);
    if (n != 1)
        return -1;
    struct pollfd ready = {.fd = guard->fd, .events = POLLIN};
    if (poll(&ready, 1, 2000) != 1)
        return -1;
    char ack;
    return recv(guard->fd, &ack, 1, 0) == 1 && ack == 'A' ? 0 : -1;
}
int enclio_guardian_stop(struct enclio_guardian *guard, bool disarm)
{
    int result = 0;
    /* Q is a disarm token, valid only after the parent has itself confirmed all
     * cleanup. An aborted startup must close the channel and let EOF recover
     * allocations whose handles the parent has not received yet. */
    if (guard->fd >= 0) {
        if (disarm && send(guard->fd, "Q", 1, MSG_NOSIGNAL) != 1)
            result = -1;
        close(guard->fd);
        guard->fd = -1;
    }
    if (guard->pid <= 0)
        return result;
    (void)kill(guard->pid, SIGCONT);
    int status = 0;
    pid_t done = 0;
    for (int i = 0; i < 1200; i++) {
        done = waitpid(guard->pid, &status, WNOHANG);
        if (done == guard->pid || (done < 0 && errno != EINTR))
            break;
        usleep(10000);
    }
    if (done == 0) {
        kill(guard->pid, SIGKILL);
        do {
            done = waitpid(guard->pid, &status, 0);
        } while (done < 0 && errno == EINTR);
        result = -1;
    }
    if (done != guard->pid || !WIFEXITED(status) || WEXITSTATUS(status))
        result = -1;
    guard->pid = -1;
    return result;
}
