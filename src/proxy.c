#define _POSIX_C_SOURCE 200809L
#include "proxy.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#define TG_MAX_WORKERS 32
#define TG_HEADER_MAX 8192
#define TG_BUFFER_SIZE 16384
#define TG_IDLE_MS 30000
#define TG_CONNECT_MS 10000
#define TG_LIFETIME_SECONDS 300

static volatile sig_atomic_t active_workers;

static int protect_server(void)
{
#ifdef __linux__
    /* The sandbox command shares a UID with the relay. Deny /proc/PID/mem and
     * ptrace-style access to the unfiltered trusted relay and its workers. */
    if (prctl(PR_SET_DUMPABLE, 0) < 0)
        return -1;
#endif
    return 0;
}

static int64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
        return -1;
    return 0;
}

static int await_io(int fd, short events, int64_t deadline)
{
    struct pollfd item = { .fd = fd, .events = events };
    for (;;) {
        int64_t remaining = deadline - monotonic_ms();
        if (remaining <= 0)
            return -1;
        int ready = poll(&item, 1, remaining > TG_IDLE_MS ? TG_IDLE_MS : (int)remaining);
        if (ready > 0)
            return (item.revents & events) ? 0 : -1;
        if (ready == 0 || errno != EINTR)
            return -1;
    }
}

static int send_all(int fd, const char *data, size_t length)
{
    int64_t deadline = monotonic_ms() + TG_IDLE_MS;
    while (length) {
        ssize_t written = send(fd, data, length, 0);
        if (written > 0) {
            data += written;
            length -= (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (await_io(fd, POLLOUT, deadline) != 0)
                return -1;
        } else {
            return -1;
        }
    }
    return 0;
}

int tg_proxy_host_valid(const char *host)
{
    size_t length = host ? strlen(host) : 0;
    size_t label = 0;
    int numeric = 1;
    if (!length || length > 253)
        return 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)host[i];
        if (c == '.') {
            if (!label || host[i - 1] == '-')
                return 0;
            label = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-'))
                return 0;
            if (!label && c == '-')
                return 0;
            if (++label > 63)
                return 0;
            if (!(c >= '0' && c <= '9'))
                numeric = 0;
        }
    }
    if (!label || host[length - 1] == '-' || numeric)
        return 0;
    /* AI_NUMERICHOST performs no DNS lookup and catches libc's legacy numeric
     * forms, including hexadecimal IPv4 such as 0x08080808. */
    struct addrinfo hint = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM,
                             .ai_flags = AI_NUMERICHOST };
    struct addrinfo *literal = NULL;
    int result = getaddrinfo(host, NULL, &hint, &literal);
    if (result == 0) {
        freeaddrinfo(literal);
        return 0;
    }
    return result == EAI_NONAME;
}

int tg_proxy_address_public(const struct sockaddr *address)
{
    if (!address)
        return 0;
    if (address->sa_family == AF_INET) {
        uint32_t ip = ntohl(((const struct sockaddr_in *)address)->sin_addr.s_addr);
        unsigned int a = ip >> 24, b = (ip >> 16) & 255, c = (ip >> 8) & 255;
        if (a == 0 || a == 10 || a == 127 || a >= 224 ||
            (a == 100 && b >= 64 && b <= 127) ||
            (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) ||
            (a == 192 && b == 168) ||
            (a == 192 && b == 0 && (c == 0 || c == 2)) ||
            (a == 192 && b == 88 && c == 99) ||
            (a == 198 && (b == 18 || b == 19)) ||
            (a == 198 && b == 51 && c == 100) ||
            (a == 203 && b == 0 && c == 113))
            return 0;
        return 1;
    }
    if (address->sa_family == AF_INET6) {
        const unsigned char *ip = ((const struct sockaddr_in6 *)address)->sin6_addr.s6_addr;
        /* Global unicast only. Reject transition ranges as they can embed
         * otherwise forbidden IPv4 destinations. Fail closed for future space. */
        if ((ip[0] & 0xe0) != 0x20 ||
            (ip[0] == 0x20 && ip[1] == 0x01 && ip[2] <= 1) ||
            (ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8) ||
            (ip[0] == 0x20 && ip[1] == 0x02) ||
            (ip[0] == 0x3f && ip[1] == 0xff && (ip[2] & 0xf0) == 0))
            return 0;
        return 1;
    }
    return 0;
}

static int connect_deadline(int fd, const struct sockaddr *address, socklen_t length)
{
    if (nonblocking(fd) < 0)
        return -1;
    if (connect(fd, address, length) == 0)
        return 0;
    if (errno != EINPROGRESS ||
        await_io(fd, POLLOUT, monotonic_ms() + TG_CONNECT_MS) < 0)
        return -1;
    int error = 0;
    socklen_t size = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) < 0 || error) {
        errno = error ? error : errno;
        return -1;
    }
    return 0;
}

static int public_connection(const char *host)
{
    struct addrinfo hint = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM,
                             .ai_protocol = IPPROTO_TCP };
    struct addrinfo *addresses = NULL;
    int fd = -1;
    /* A bounded worker lifetime also bounds blocking libc/NSS resolution. */
    alarm(20);
    if (getaddrinfo(host, "443", &hint, &addresses) != 0)
        return -1;
    for (const struct addrinfo *a = addresses; a; a = a->ai_next) {
        if (!tg_proxy_address_public(a->ai_addr)) {
            freeaddrinfo(addresses);
            return -1;
        }
    }
    for (const struct addrinfo *a = addresses; a; a = a->ai_next) {
        fd = socket(a->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0)
            continue;
        if (connect_deadline(fd, a->ai_addr, a->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    alarm(TG_LIFETIME_SECONDS);
    return fd;
}

static void reply(int fd, const char *status)
{
    char message[256];
    int length = snprintf(message, sizeof(message),
                          "HTTP/1.1 %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", status);
    if (length > 0 && (size_t)length < sizeof(message))
        (void)send_all(fd, message, (size_t)length);
}

/* Read one byte at a time: TLS bytes following the headers must remain in the
 * socket for the tunnel. Header size and the entire header deadline are bounded. */
static int read_headers(int fd, char *buffer, size_t capacity)
{
    int64_t deadline = monotonic_ms() + TG_CONNECT_MS;
    size_t used = 0;
    while (used + 1 < capacity) {
        ssize_t count = recv(fd, buffer + used, 1, 0);
        if (count == 1) {
            unsigned char c = (unsigned char)buffer[used++];
            if ((!c || c == 127 || (c < 32 && c != '\r' && c != '\n' && c != '\t')))
                return -1;
            if (used >= 4 && memcmp(buffer + used - 4, "\r\n\r\n", 4) == 0) {
                buffer[used] = '\0';
                return 0;
            }
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (await_io(fd, POLLIN, deadline) < 0)
                return -1;
        } else {
            return -1;
        }
        if (monotonic_ms() >= deadline)
            return -1;
    }
    return -1;
}

static int header_token(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

static int parse_connect(char *headers, char host[254])
{
    char *line_end = strstr(headers, "\r\n");
    if (!line_end || strncmp(headers, "CONNECT ", 8) != 0)
        return -1;
    *line_end = '\0';
    char *target = headers + 8;
    char *version = strchr(target, ' ');
    if (!version)
        return -1;
    *version++ = '\0';
    if (strcmp(version, "HTTP/1.1") != 0 && strcmp(version, "HTTP/1.0") != 0)
        return -1;
    char *colon = strchr(target, ':');
    if (!colon || strcmp(colon, ":443") != 0 || colon == target ||
        (size_t)(colon - target) > 253)
        return -1;
    memcpy(host, target, (size_t)(colon - target));
    host[colon - target] = '\0';
    if (!tg_proxy_host_valid(host))
        return -1;
    int seen_host = 0;
    for (char *line = line_end + 2; *line; line = line_end + 2) {
        line_end = strstr(line, "\r\n");
        if (!line_end)
            return -1;
        *line_end = '\0';
        if (!*line)
            return 0;
        char *separator = strchr(line, ':');
        if (!separator || separator == line)
            return -1;
        for (char *p = line; p < separator; ++p)
            if (!header_token((unsigned char)*p))
                return -1;
        *separator++ = '\0';
        while (*separator == ' ' || *separator == '\t')
            ++separator;
        char *value_end = separator + strlen(separator);
        while (value_end > separator && (value_end[-1] == ' ' || value_end[-1] == '\t'))
            *--value_end = '\0';
        for (char *p = separator; *p; ++p)
            if (*p == '\r' || *p == '\n')
                return -1;
        if (strcasecmp(line, "Content-Length") == 0 ||
            strcasecmp(line, "Transfer-Encoding") == 0)
            return -1;
        if (strcasecmp(line, "Host") == 0) {
            if (seen_host++ || strcasecmp(separator, target) != 0)
                return -1;
        }
    }
    return -1;
}

struct channel {
    unsigned char bytes[TG_BUFFER_SIZE];
    size_t start;
    size_t end;
    int eof;
    int shut;
};

static void tunnel(int left, int right)
{
    struct channel channels[2] = {0};
    int fds[2] = { left, right };
    int64_t last_activity = monotonic_ms();
    while (!(channels[0].shut && channels[1].shut)) {
        struct pollfd items[2] = {{ .fd = left }, { .fd = right }};
        for (int i = 0; i < 2; ++i) {
            struct channel *out = &channels[i], *in = &channels[1 - i];
            if (!out->eof && out->end < sizeof(out->bytes))
                items[i].events |= POLLIN;
            if (in->start < in->end)
                items[i].events |= POLLOUT;
            if (out->eof && out->start == out->end && !out->shut) {
                (void)shutdown(fds[1 - i], SHUT_WR);
                out->shut = 1;
            }
            if (!items[i].events)
                items[i].fd = -1;
        }
        if (channels[0].shut && channels[1].shut)
            return;
        int64_t remaining = TG_IDLE_MS - (monotonic_ms() - last_activity);
        if (remaining <= 0)
            return;
        int ready = poll(items, 2, (int)remaining);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0)
            return;
        for (int i = 0; i < 2; ++i) {
            struct channel *out = &channels[i], *in = &channels[1 - i];
            if (items[i].revents & (POLLERR | POLLNVAL))
                return;
            if ((items[i].revents & (POLLIN | POLLHUP)) && !out->eof &&
                out->end < sizeof(out->bytes)) {
                ssize_t n = recv(fds[i], out->bytes + out->end,
                                 sizeof(out->bytes) - out->end, 0);
                if (n > 0) {
                    out->end += (size_t)n;
                    last_activity = monotonic_ms();
                } else if (n == 0) {
                    out->eof = 1;
                } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    return;
                }
            }
            if ((items[i].revents & POLLOUT) && in->start < in->end) {
                ssize_t n = send(fds[i], in->bytes + in->start, in->end - in->start, 0);
                if (n > 0) {
                    in->start += (size_t)n;
                    if (in->start == in->end)
                        in->start = in->end = 0;
                    last_activity = monotonic_ms();
                } else if (n < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    return;
                }
            }
        }
    }
}

static void proxy_client(int client, const char *const *allowed_hosts, size_t host_count)
{
    char request[TG_HEADER_MAX], host[254];
    if (read_headers(client, request, sizeof(request)) < 0 || parse_connect(request, host) < 0) {
        reply(client, "400 Bad Request");
        return;
    }
    int allowed = 0;
    for (size_t i = 0; i < host_count; ++i)
        if (strcasecmp(host, allowed_hosts[i]) == 0)
            allowed = 1;
    if (!allowed) {
        reply(client, "403 Forbidden");
        return;
    }
    int remote = public_connection(host);
    if (remote < 0) {
        reply(client, "502 Bad Gateway");
        return;
    }
    static const char established[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
    if (send_all(client, established, sizeof(established) - 1) == 0)
        tunnel(client, remote);
    close(remote);
}

static int unix_address(const char *path, struct sockaddr_un *address)
{
    if (!path || !*path || strlen(path) >= sizeof(address->sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    memcpy(address->sun_path, path, strlen(path) + 1);
    return 0;
}

static void relay_client(int client, const char *unix_path)
{
    struct sockaddr_un address;
    if (unix_address(unix_path, &address) < 0)
        return;
    int remote = socket(AF_UNIX, SOCK_STREAM, 0);
    if (remote < 0)
        return;
    if (connect_deadline(remote, (const struct sockaddr *)&address, sizeof(address)) == 0)
        tunnel(client, remote);
    close(remote);
}

static void reap_workers(int signal_number)
{
    (void)signal_number;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        if (active_workers > 0)
            --active_workers;
    errno = saved_errno;
}

static int serve(int listener, const char *unix_path,
                 const char *const *allowed_hosts, size_t host_count, int relay)
{
    struct sigaction child_action = { .sa_handler = reap_workers, .sa_flags = SA_RESTART | SA_NOCLDSTOP };
    sigemptyset(&child_action.sa_mask);
    if (sigaction(SIGCHLD, &child_action, NULL) < 0)
        return -1;
    (void)signal(SIGPIPE, SIG_IGN);
    active_workers = 0;
    for (;;) {
        int client = accept(listener, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR || errno == ECONNABORTED)
                continue;
            return -1;
        }
        if (nonblocking(client) < 0) {
            close(client);
            continue;
        }
        sigset_t blocked, previous;
        sigemptyset(&blocked);
        sigaddset(&blocked, SIGCHLD);
        if (sigprocmask(SIG_BLOCK, &blocked, &previous) < 0) {
            close(client);
            return -1;
        }
        pid_t parent = getpid();
        pid_t child = active_workers >= TG_MAX_WORKERS ? -1 : fork();
        if (child == 0) {
            (void)sigprocmask(SIG_SETMASK, &previous, NULL);
            (void)signal(SIGCHLD, SIG_DFL);
            (void)signal(SIGALRM, SIG_DFL);
            (void)signal(SIGTERM, SIG_DFL);
            (void)signal(SIGINT, SIG_DFL);
            close(listener);
#ifdef __linux__
            if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != parent)
                _exit(1);
#else
            (void)parent;
#endif
            alarm(TG_LIFETIME_SECONDS);
            if (relay)
                relay_client(client, unix_path);
            else
                proxy_client(client, allowed_hosts, host_count);
            close(client);
            _exit(0);
        }
        if (child > 0)
            ++active_workers;
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
        close(client);
    }
}

int tg_proxy_serve(const char *unix_path, const char *const *allowed_hosts, size_t host_count)
{
    struct sockaddr_un address;
    if (protect_server() < 0 || unix_address(unix_path, &address) < 0 || !allowed_hosts || !host_count)
        return -1;
    for (size_t i = 0; i < host_count; ++i)
        if (!tg_proxy_host_valid(allowed_hosts[i])) {
            errno = EINVAL;
            return -1;
        }
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0)
        return -1;
    mode_t old_mask = umask(0077);
    int bound = bind(listener, (const struct sockaddr *)&address, sizeof(address));
    umask(old_mask);
    if (bound < 0 || listen(listener, TG_MAX_WORKERS) < 0) {
        close(listener);
        if (bound == 0)
            unlink(unix_path);
        return -1;
    }
    (void)fcntl(listener, F_SETFD, FD_CLOEXEC);
    int result = serve(listener, unix_path, allowed_hosts, host_count, 0);
    close(listener);
    unlink(unix_path);
    return result;
}

int tg_relay_serve(const char *unix_path, unsigned short port)
{
    struct sockaddr_un check;
    if (protect_server() < 0 || !port || unix_address(unix_path, &check) < 0)
        return -1;
    int listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener < 0)
        return -1;
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(port),
                                  .sin_addr = { .s_addr = htonl(0x7f000001U) } };
    if (bind(listener, (const struct sockaddr *)&address, sizeof(address)) < 0 ||
        listen(listener, TG_MAX_WORKERS) < 0) {
        close(listener);
        return -1;
    }
    (void)fcntl(listener, F_SETFD, FD_CLOEXEC);
    int result = serve(listener, unix_path, NULL, 0, 1);
    close(listener);
    return result;
}
