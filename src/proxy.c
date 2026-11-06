#define _GNU_SOURCE
#include "enclio.h"
#include "proxy.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>
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
#include <seccomp.h>
#endif

#ifdef ENCLIO_PROXY_TESTING
#define ENCLIO_MAX_WORKERS 4
#define ENCLIO_IDLE_MS 500
#define ENCLIO_CONNECT_MS 250
#define ENCLIO_LIFETIME_SECONDS 5
#define ENCLIO_DNS_SECONDS 1
#else
#define ENCLIO_MAX_WORKERS 32
#define ENCLIO_IDLE_MS 30000
#define ENCLIO_CONNECT_MS 10000
#define ENCLIO_LIFETIME_SECONDS 300
#define ENCLIO_DNS_SECONDS 20
#endif
#define ENCLIO_HEADER_MAX 8192
#define ENCLIO_BUFFER_SIZE 16384
static volatile sig_atomic_t active_workers;

static int protect_server(void)
{
#ifdef __linux__
    /* Deny /proc/PID/mem and ptrace-style access to trusted proxy workers,
     * including when a caller runs them with the workload's host UID. */
    if (prctl(PR_SET_DUMPABLE, 0) < 0)
        return -1;
#endif
    return 0;
}

/* Install after creating the listener. This filter confines trusted transport
 * processes as well as their forked workers. DNS/NSS may read configuration and
 * load modules; writes, execution and kernel administration are forbidden. */
static int transport_filter(void)
{
#ifdef __linux__
    static const char *const denied[] = {
        "execve", "execveat", "mount", "umount2", "pivot_root", "chroot",
        "unshare", "setns", "ptrace", "process_vm_readv", "process_vm_writev",
        "pidfd_getfd", "bpf", "perf_event_open", "userfaultfd", "keyctl",
        "add_key", "request_key", "io_uring_setup", "io_uring_enter",
        "io_uring_register", "open_by_handle_at", "name_to_handle_at",
        "kexec_load", "kexec_file_load", "reboot", "init_module",
        "finit_module", "delete_module", "swapon", "swapoff", "fsopen",
        "fsconfig", "fsmount", "move_mount", "open_tree", "mount_setattr",
        "creat", "openat2", "unlink", "unlinkat", "rename", "renameat",
        "renameat2", "mkdir", "mkdirat", "rmdir", "link", "linkat",
        "symlink", "symlinkat", "mknod", "mknodat", "truncate", "ftruncate",
        "chmod", "fchmod", "fchmodat", "fchmodat2", "chown", "fchown", "lchown",
        "fchownat", "utime", "utimes", "utimensat", "futimesat",
        "setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr",
        "fremovexattr", "fanotify_init", "acct", "quotactl", "ioctl"
    };
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) return -1;
    if (seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS) < 0)
        goto fail;
    for (size_t i = 0; i < sizeof(denied)/sizeof(denied[0]); ++i) {
        int nr = seccomp_syscall_resolve_name(denied[i]);
        /* This syscall is 452 on both supported 64-bit ABIs. Older libseccomp
         * databases must still deny it when running on a newer kernel. */
        if (nr == __NR_SCMP_ERROR && !strcmp(denied[i], "fchmodat2")) {
#if defined(__x86_64__) || defined(__aarch64__)
            nr = 452;
#else
            goto fail;
#endif
        }
        if (nr != __NR_SCMP_ERROR &&
            seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), nr, 0) < 0) goto fail;
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0) < 0)
        goto fail;
    const unsigned long namespaces = 0x7e020080UL;
    for (unsigned long bit = 1; bit; bit <<= 1)
        if ((namespaces & bit) && seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
            SCMP_SYS(clone), 1, SCMP_A0(SCMP_CMP_MASKED_EQ, bit, bit)) < 0)
            goto fail;
    const char *opens[] = { "open", "openat" };
    for (unsigned i = 0; i < 2; ++i) {
        int nr = seccomp_syscall_resolve_name(opens[i]);
        if (nr == __NR_SCMP_ERROR) continue;
        unsigned arg = i ? 2 : 1;
        struct scmp_arg_cmp test = { .arg = arg, .op = SCMP_CMP_MASKED_EQ,
                                    .datum_a = O_ACCMODE, .datum_b = O_WRONLY };
        if (seccomp_rule_add_array(ctx, SCMP_ACT_ERRNO(EPERM), nr, 1, &test) < 0)
            goto fail;
        test.datum_b = O_RDWR;
        if (seccomp_rule_add_array(ctx, SCMP_ACT_ERRNO(EPERM), nr, 1, &test) < 0)
            goto fail;
        const unsigned bits[] = { O_CREAT, O_TRUNC };
        for (unsigned j = 0; j < 2; ++j) {
            test.datum_a = test.datum_b = bits[j];
            if (seccomp_rule_add_array(ctx, SCMP_ACT_ERRNO(EPERM), nr, 1, &test) < 0)
                goto fail;
        }
    }
    for (int family = 0; family < AF_MAX; ++family) {
        if (family == AF_UNIX || family == AF_INET || family == AF_INET6 ||
            family == AF_NETLINK) continue;
        if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
                            SCMP_A0(SCMP_CMP_EQ, family)) < 0) goto fail;
    }
    /* Read-only file descriptors still permit metadata-changing ioctls.
     * Transport code needs none; reject the entire syscall, including aliases. */
    const int ip_families[] = { AF_INET, AF_INET6 };
    for (unsigned i = 0; i < 2; ++i)
        if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 2,
                            SCMP_A0(SCMP_CMP_EQ, ip_families[i]),
                            SCMP_A1(SCMP_CMP_MASKED_EQ, 0xf, SOCK_RAW)) < 0)
            goto fail;
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
                        SCMP_A0(SCMP_CMP_GE, AF_MAX)) < 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 || seccomp_load(ctx) < 0)
        goto fail;
    seccomp_release(ctx);
    return 0;
fail:
    seccomp_release(ctx);
    return -1;
#else
    return 0;
#endif
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
        int ready = poll(&item, 1, remaining > ENCLIO_IDLE_MS ? ENCLIO_IDLE_MS : (int)remaining);
        if (ready > 0)
            return (item.revents & events) ? 0 : -1;
        if (ready == 0 || errno != EINTR)
            return -1;
    }
}

static int send_all(int fd, const char *data, size_t length)
{
    int64_t deadline = monotonic_ms() + ENCLIO_IDLE_MS;
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

int enclio_proxy_host_valid(const char *host)
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

int enclio_proxy_rule_parse(const char *text, struct enclio_network_rule *rule,
                           unsigned short default_port)
{
    if (!text || !rule) return 0;
    const char *colon = strchr(text, ':');
    size_t length = colon ? (size_t)(colon - text) : strlen(text);
    if (!length || length > ENCLIO_NETWORK_HOST_MAX) return 0;
    char host[ENCLIO_NETWORK_HOST_MAX + 1];
    memcpy(host, text, length); host[length] = 0;
    if (!enclio_proxy_host_valid(host)) return 0;
    unsigned port = default_port;
    if (colon) {
        const char *p = colon + 1;
        if (!*p) return 0;
        port = 0;
        for (; *p; ++p) {
            if (*p < '0' || *p > '9' || port > 6553) return 0;
            port = port * 10 + (unsigned)(*p - '0');
            if (port > 65535) return 0;
        }
    }
    if (!port) return 0;
    for (size_t i = 0; i <= length; ++i)
        rule->host[i] = host[i] >= 'A' && host[i] <= 'Z' ? host[i] + ('a'-'A') : host[i];
    rule->port = (unsigned short)port;
    return 1;
}

static int rule_allowed(const struct enclio_network_rule *target,
                        const struct enclio_network_rule *rules, size_t count)
{
    for (size_t i = 0; i < count; ++i)
        if (target->port == rules[i].port && !strcasecmp(target->host, rules[i].host))
            return 1;
    return 0;
}

/* Conservative, fixed destination policy for the isolated-mode proxy.
 * Reject special/local/transition ranges before connecting any DNS result;
 * accepting an address here is not proof of global routability. This is not
 * a complete, live copy of the IANA special-purpose registries. In particular,
 * broad protocol-assignment exclusions deliberately also reject exceptions
 * that IANA marks globally reachable. Keep ranges in sync with policy review.
 * Reference: https://www.iana.org/assignments/iana-ipv4-special-registry/
 *            https://www.iana.org/assignments/iana-ipv6-special-registry/ */
int enclio_proxy_address_public(const struct sockaddr *address)
{
    if (!address)
        return 0;
    if (address->sa_family == AF_INET) {
        uint32_t ip = ntohl(((const struct sockaddr_in *)address)->sin_addr.s_addr);
        unsigned int a = ip >> 24, b = (ip >> 16) & 255, c = (ip >> 8) & 255;
        /* 0/8: this network; 10/8: private; 127/8: loopback.
         * >=224 rejects multicast 224/4 and reserved 240/4, including broadcast. */
        if (a == 0 || a == 10 || a == 127 || a >= 224 ||
            (a == 100 && b >= 64 && b <= 127) || /* 100.64/10: shared/CGNAT */
            (a == 169 && b == 254) ||           /* 169.254/16: link-local */
            (a == 172 && b >= 16 && b <= 31) || /* 172.16/12: private */
            (a == 192 && b == 168) ||          /* 192.168/16: private */
            /* 192.0.0/24: protocol assignments; 192.0.2/24: TEST-NET-1. */
            (a == 192 && b == 0 && (c == 0 || c == 2)) ||
            (a == 192 && b == 88 && c == 99) || /* 192.88.99/24: deprecated 6to4 relay */
            (a == 198 && (b == 18 || b == 19)) || /* 198.18/15: benchmarking */
            (a == 198 && b == 51 && c == 100) || /* 198.51.100/24: TEST-NET-2 */
            (a == 203 && b == 0 && c == 113))    /* 203.0.113/24: TEST-NET-3 */
            return 0;
        return 1;
    }
    if (address->sa_family == AF_INET6) {
        const unsigned char *ip = ((const struct sockaddr_in6 *)address)->sin6_addr.s6_addr;
        /* Accept only 2000::/3 global-unicast space, then exclude:
         * 2001::/23 IETF protocol assignments (includes Teredo/benchmarking),
         * 2001:db8::/32 documentation, 2002::/16 6to4, and
         * 3fff::/20 documentation. Transition addresses can encode IPv4
         * destinations; rejecting the whole ranges avoids embedded-IP bypass.
         * The 2000::/3 gate also rejects unspecified/loopback, IPv4-mapped,
         * translation prefixes, unique-local, link-local and multicast space. */
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
        await_io(fd, POLLOUT, monotonic_ms() + ENCLIO_CONNECT_MS) < 0)
        return -1;
    int error = 0;
    socklen_t size = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) < 0 || error) {
        errno = error ? error : errno;
        return -1;
    }
    return 0;
}

static int public_connection(const struct enclio_network_rule *target)
{
    struct addrinfo hint = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM,
                             .ai_protocol = IPPROTO_TCP };
    struct addrinfo *addresses = NULL;
    int fd = -1;
    /* A bounded worker lifetime also bounds blocking libc/NSS resolution. */
    char service[6];
    snprintf(service, sizeof(service), "%u", target->port);
    alarm(ENCLIO_DNS_SECONDS);
    if (getaddrinfo(target->host, service, &hint, &addresses) != 0)
        return -1;
    for (const struct addrinfo *a = addresses; a; a = a->ai_next) {
        if (!a->ai_addr || (a->ai_family != AF_INET && a->ai_family != AF_INET6) ||
            a->ai_family != a->ai_addr->sa_family ||
            a->ai_addrlen < (a->ai_family == AF_INET ? sizeof(struct sockaddr_in) :
                                                        sizeof(struct sockaddr_in6)) ||
            !enclio_proxy_address_public(a->ai_addr)) {
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
    alarm(ENCLIO_LIFETIME_SECONDS);
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
static int read_headers(int fd, char *buffer, size_t capacity, int64_t deadline)
{
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

#define ENCLIO_HEADER_FIELDS 128
struct http_header { char *name, *value; };
struct http_request {
    struct enclio_network_rule target;
    int connect, chunked;
    uint64_t length;
    char rewritten[ENCLIO_HEADER_MAX * 2];
    size_t rewritten_size;
};

static int append_header(struct http_request *request, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    size_t remaining = sizeof(request->rewritten) - request->rewritten_size;
    int n = vsnprintf(request->rewritten + request->rewritten_size, remaining, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= remaining) return -1;
    request->rewritten_size += (size_t)n;
    return 0;
}

static int decimal_length(const char *value, uint64_t *length)
{
    if (!*value) return -1;
    uint64_t n = 0;
    for (; *value; ++value) {
        if (*value < '0' || *value > '9' || n > ENCLIO_HTTP_BODY_MAX/10)
            return -1;
        n = n * 10 + (unsigned)(*value - '0');
        if (n > ENCLIO_HTTP_BODY_MAX) return -1;
    }
    *length = n;
    return 0;
}

static int connection_has(const char *value, const char *name)
{
    while (*value) {
        while (*value == ' ' || *value == '\t') ++value;
        const char *start = value;
        while (*value && *value != ',' && *value != ' ' && *value != '\t') {
            if (!header_token((unsigned char)*value)) return -1;
            ++value;
        }
        size_t length = (size_t)(value-start);
        if (!length) return -1;
        if (strlen(name) == length && !strncasecmp(start, name, length)) return 1;
        while (*value == ' ' || *value == '\t') ++value;
        if (*value && *value != ',') return -1;
        if (*value == ',') { ++value; if (!*value) return -1; }
    }
    return 0;
}

static int hop_header(const char *name)
{
    const char *const names[] = { "Connection", "Proxy-Connection", "Keep-Alive", "TE",
        "Trailer", "Upgrade", "Proxy-Authorization", "Proxy-Authenticate",
        "Proxy-Authentication-Info", "Host", "Content-Length", "Transfer-Encoding" };
    for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); ++i)
        if (!strcasecmp(name, names[i])) return 1;
    return 0;
}

static int parse_http(char *headers, struct http_request *request)
{
    memset(request, 0, sizeof(*request));
    char *line_end = strstr(headers, "\r\n");
    if (!line_end) return -1;
    *line_end = 0;
    char *method = headers, *target = strchr(method, ' ');
    if (!target || target == method || (size_t)(target-method) > 32) return -1;
    *target++ = 0;
    for (char *p = method; *p; ++p) if (!header_token((unsigned char)*p)) return -1;
    char *version = strchr(target, ' ');
    if (!version || version == target) return -1;
    *version++ = 0;
    if (strcmp(version, "HTTP/1.1") && strcmp(version, "HTTP/1.0")) return -1;
    for (char *p = target; *p; ++p)
        if ((unsigned char)*p <= 32 || (unsigned char)*p == 127 || *p == '#') return -1;
    request->connect = !strcmp(method, "CONNECT");
    char *path = NULL;
    char query_path[ENCLIO_HEADER_MAX];
    if (request->connect) {
        if (!enclio_proxy_rule_parse(target, &request->target, 0)) return -1;
    } else {
        if (strncasecmp(target, "http://", 7)) return -1;
        char *authority = target + 7;
        char *delimiter = strpbrk(authority, "/?");
        char separator = delimiter ? *delimiter : 0;
        if (delimiter) *delimiter = 0;
        if (!enclio_proxy_rule_parse(authority, &request->target, 80)) return -1;
        if (delimiter) {
            *delimiter = separator;
            if (separator == '?') {
                if (strlen(delimiter) + 2 > sizeof(query_path)) return -1;
                query_path[0] = '/'; strcpy(query_path + 1, delimiter); path = query_path;
            } else path = delimiter;
        } else path = "/";
        if (!strcmp(method, "OPTIONS") && !delimiter) path = "*";
    }
    struct http_header fields[ENCLIO_HEADER_FIELDS];
    size_t count = 0;
    int host_seen = 0, cl_seen = 0, te_seen = 0;
    char *connection = NULL;
    char *line = line_end + 2;
    for (;;) {
        line_end = strstr(line, "\r\n");
        if (!line_end) return -1;
        *line_end = 0;
        if (!*line) break;
        if (count == ENCLIO_HEADER_FIELDS) return -1;
        char *colon = strchr(line, ':');
        if (!colon || colon == line) return -1;
        for (char *p = line; p < colon; ++p)
            if (!header_token((unsigned char)*p)) return -1;
        *colon++ = 0;
        while (*colon == ' ' || *colon == '\t') ++colon;
        char *tail = colon + strlen(colon);
        while (tail > colon && (tail[-1] == ' ' || tail[-1] == '\t')) *--tail = 0;
        for (char *p = colon; *p; ++p)
            if ((unsigned char)*p < 32 && *p != '\t') return -1;
        fields[count++] = (struct http_header){line, colon};
        if (!strcasecmp(line, "Host")) {
            struct enclio_network_rule host;
            if (host_seen++ || !enclio_proxy_rule_parse(colon, &host,
                    request->connect ? request->target.port : 80) ||
                host.port != request->target.port || strcmp(host.host, request->target.host))
                return -1;
        } else if (!strcasecmp(line, "Content-Length")) {
            if (cl_seen++ || request->connect || decimal_length(colon, &request->length)) return -1;
        } else if (!strcasecmp(line, "Transfer-Encoding")) {
            if (te_seen++ || request->connect || strcasecmp(colon, "chunked") ||
                !strcmp(version, "HTTP/1.0")) return -1;
            request->chunked = 1;
        } else if (!strcasecmp(line, "Connection")) {
            if (connection || !*colon) return -1;
            connection = colon;
            /* Validate the complete token list, including tokens after a match. */
            if (connection_has(colon, "") < 0) return -1;
            const char *critical[] = {"Host", "Content-Length", "Transfer-Encoding"};
            for (unsigned i = 0; i < 3; ++i)
                if (connection_has(colon, critical[i])) return -1;
        } else if (!strcasecmp(line, "Expect") || !strcasecmp(line, "Upgrade") ||
                   !strcasecmp(line, "Trailer")) return -1;
        line = line_end + 2;
    }
    if (cl_seen && te_seen) return -1;
    if (!request->connect && !strcmp(version, "HTTP/1.1") && !host_seen) return -1;
    if (request->connect) return 0;
    if (append_header(request, "%s %s HTTP/1.1\r\nHost: %s:%u\r\n", method,
                      path, request->target.host, request->target.port)) return -1;
    for (size_t i = 0; i < count; ++i) {
        if (hop_header(fields[i].name) ||
            (connection && connection_has(connection, fields[i].name))) continue;
        if (append_header(request, "%s: %s\r\n", fields[i].name, fields[i].value)) return -1;
    }
    if (request->chunked) {
        if (append_header(request, "Transfer-Encoding: chunked\r\n")) return -1;
    } else if (cl_seen && append_header(request, "Content-Length: %" PRIu64 "\r\n", request->length))
        return -1;
    return append_header(request, "Connection: close\r\n\r\n");
}

#ifdef ENCLIO_PROXY_TESTING
int enclio_proxy_fuzz_request(const unsigned char *data, size_t size)
{
    if (!data || size >= ENCLIO_HEADER_MAX || memchr(data, 0, size)) return -1;
    char buffer[ENCLIO_HEADER_MAX];
    memcpy(buffer, data, size); buffer[size] = 0;
    struct http_request request;
    return parse_http(buffer, &request);
}
#endif

struct channel {
    unsigned char bytes[ENCLIO_BUFFER_SIZE];
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
        int64_t remaining = ENCLIO_IDLE_MS - (monotonic_ms() - last_activity);
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

static int receive_exact(int fd, void *output, size_t size, int64_t deadline)
{
    unsigned char *buffer = output;
    while (size) {
        ssize_t n = recv(fd, buffer, size, 0);
        if (n > 0) { buffer += n; size -= (size_t)n; }
        else if (n < 0 && errno == EINTR) continue;
        else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (await_io(fd, POLLIN, deadline)) return -1;
        } else return -1;
    }
    return 0;
}

static int stream_bytes(int from, int to, uint64_t length)
{
    char buffer[ENCLIO_BUFFER_SIZE];
    while (length) {
        size_t wanted = length > sizeof(buffer) ? sizeof(buffer) : (size_t)length;
        ssize_t n = recv(from, buffer, wanted, 0);
        if (n > 0) {
            if (send_all(to, buffer, (size_t)n)) return -1;
            length -= (uint64_t)n;
        } else if (n < 0 && errno == EINTR) continue;
        else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (await_io(from, POLLIN, monotonic_ms() + ENCLIO_IDLE_MS)) return -1;
        } else return -1;
    }
    return 0;
}

static int stream_chunks(int client, int remote)
{
    uint64_t total = 0;
    for (;;) {
        char line[32]; size_t size = 0;
        int64_t deadline = monotonic_ms() + ENCLIO_IDLE_MS;
        do {
            if (size + 1 >= sizeof(line) || receive_exact(client, line + size, 1, deadline)) return -1;
            ++size;
        } while (size < 2 || line[size-2] != '\r' || line[size-1] != '\n');
        line[size-2] = 0;
        if (!line[0]) return -1;
        uint64_t length = 0;
        for (const char *p = line; *p; ++p) {
            unsigned digit;
            if (*p >= '0' && *p <= '9') digit = (unsigned)(*p-'0');
            else if (*p >= 'a' && *p <= 'f') digit = (unsigned)(*p-'a'+10);
            else if (*p >= 'A' && *p <= 'F') digit = (unsigned)(*p-'A'+10);
            else return -1; /* Chunk extensions and trailers are unsupported. */
            if (length > ENCLIO_HTTP_BODY_MAX/16) return -1;
            length = length * 16 + digit;
            if (length > ENCLIO_HTTP_BODY_MAX-total) return -1;
        }
        if (!length) {
            char ending[2];
            if (receive_exact(client, ending, 2, deadline) || memcmp(ending, "\r\n", 2)) return -1;
            return send_all(remote, "0\r\n\r\n", 5);
        }
        total += length;
        char canonical[32];
        int n = snprintf(canonical, sizeof(canonical), "%" PRIx64 "\r\n", length);
        if (n <= 0 || send_all(remote, canonical, (size_t)n) || stream_bytes(client, remote, length))
            return -1;
        char ending[2];
        if (receive_exact(client, ending, 2, monotonic_ms()+ENCLIO_IDLE_MS) ||
            memcmp(ending, "\r\n", 2) || send_all(remote, "\r\n", 2)) return -1;
    }
}

/* A separate bounded upload process permits an origin to return 4xx/413 or
 * informational responses while the client is still uploading. Only the upload
 * process reads request bytes; only this process writes response bytes. */
static void forward_http(int client, int remote, const struct http_request *request)
{
    int control[2];
    if (pipe(control) < 0) { reply(client, "502 Bad Gateway"); return; }
    if (nonblocking(control[0]) < 0 || nonblocking(control[1]) < 0) {
        close(control[0]); close(control[1]); reply(client, "502 Bad Gateway"); return;
    }
    pid_t parent = getpid();
    pid_t uploader = fork();
    if (uploader < 0) {
        close(control[0]); close(control[1]); reply(client, "502 Bad Gateway"); return;
    }
    if (!uploader) {
        close(control[0]);
#ifdef __linux__
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != parent) _exit(1);
#else
        (void)parent;
#endif
        alarm(ENCLIO_LIFETIME_SECONDS);
        int rc = request->chunked ? stream_chunks(client, remote) :
                                   stream_bytes(client, remote, request->length);
        /* HTTP framing already marks a complete request. Keep the parent's
         * write side open while it receives the response: some origins close
         * without replying when a successfully framed request is followed by
         * an unnecessary TCP FIN. An incomplete upload must still end its
         * write side, rather than leave an origin waiting for missing bytes. */
        if (rc) (void)shutdown(remote, SHUT_WR);
        char state = rc ? 'E' : 'D';
        (void)!write(control[1], &state, 1);
        close(control[1]); close(remote); close(client);
        _exit(rc ? 1 : 0);
    }
    close(control[1]);
    int uploading = 1, response_started = 0;
    int64_t last_activity = monotonic_ms();
    for (;;) {
        struct pollfd fds[2] = {{.fd=remote, .events=POLLIN},
                               {.fd=uploading ? control[0] : -1, .events=POLLIN}};
        int64_t remaining = ENCLIO_IDLE_MS - (monotonic_ms()-last_activity);
        if (remaining <= 0 && !uploading) break;
        int ready = poll(fds, 2, uploading ? ENCLIO_IDLE_MS : (int)remaining);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) break;
        if (!ready) { if (uploading) continue; break; }
        /* Read origin bytes first: an early origin error takes precedence over
         * a broken request-side pipe after that response was already sent. */
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            char buffer[ENCLIO_BUFFER_SIZE];
            ssize_t n = recv(remote, buffer, sizeof(buffer), 0);
            if (n > 0) {
                if (send_all(client, buffer, (size_t)n)) break;
                response_started = 1; last_activity = monotonic_ms();
            } else if (!n || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
                if (!response_started) reply(client, "502 Bad Gateway");
                break;
            }
        }
        if (uploading && fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            char state = 'E';
            ssize_t n = read(control[0], &state, 1);
            uploading = 0; last_activity = monotonic_ms();
            if ((n != 1 || state != 'D') && !response_started) {
                reply(client, "400 Bad Request");
                break;
            }
        }
    }
    close(control[0]);
    /* The origin may finish before the request. Do not retain an uploader that
     * waits for client bytes after the response connection is gone. */
    kill(uploader, SIGKILL);
    while (waitpid(uploader, NULL, 0) < 0 && errno == EINTR) {}
}

static void socks_reply(int client, unsigned char status)
{
    unsigned char message[10] = {5, status, 0, 1, 0, 0, 0, 0, 0, 0};
    (void)send_all(client, (const char *)message, sizeof(message));
}

static void socks_client(int client, const struct enclio_network_rule *rules, size_t count,
                         int64_t deadline)
{
    unsigned char greeting[2], methods[255];
    if (receive_exact(client, greeting, 2, deadline) || greeting[0] != 5 || !greeting[1] ||
        receive_exact(client, methods, greeting[1], deadline)) return;
    int no_auth = 0;
    for (unsigned i = 0; i < greeting[1]; ++i) if (!methods[i]) no_auth = 1;
    const char accepted[2] = {5, 0}, rejected[2] = {5, (char)255};
    if (!no_auth) { (void)send_all(client, rejected, 2); return; }
    if (send_all(client, accepted, 2)) return;
    unsigned char header[4];
    if (receive_exact(client, header, 4, deadline) || header[0] != 5 || header[2]) return;
    if (header[1] != 1) { socks_reply(client, 7); return; }
    if (header[3] != 3) { socks_reply(client, 8); return; }
    unsigned char length, port_bytes[2];
    char host[254];
    if (receive_exact(client, &length, 1, deadline) || !length || length > 253 ||
        receive_exact(client, host, length, deadline) || memchr(host, 0, length) ||
        receive_exact(client, port_bytes, 2, deadline)) return;
    host[length] = 0;
    struct enclio_network_rule target;
    unsigned short port = (unsigned short)((unsigned)port_bytes[0] * 256 + port_bytes[1]);
    if (!enclio_proxy_host_valid(host) ||
        !enclio_proxy_rule_parse(host, &target, port) || !rule_allowed(&target, rules, count)) {
        socks_reply(client, 2); return;
    }
    int remote = public_connection(&target);
    if (remote < 0) { socks_reply(client, 5); return; }
    unsigned char established[10] = {5,0,0,1,0,0,0,0,0,0};
    if (!send_all(client, (const char *)established, sizeof(established))) tunnel(client, remote);
    close(remote);
}

static void proxy_client(int client, const struct enclio_network_rule *rules, size_t count)
{
    unsigned char first;
    int64_t deadline = monotonic_ms() + ENCLIO_CONNECT_MS;
    if (await_io(client, POLLIN, deadline) ||
        recv(client, &first, 1, MSG_PEEK) != 1) return;
    if (first == 5) { socks_client(client, rules, count, deadline); return; }
    char headers[ENCLIO_HEADER_MAX];
    struct http_request request;
    if (read_headers(client, headers, sizeof(headers), deadline) || parse_http(headers, &request)) {
        reply(client, "400 Bad Request"); return;
    }
    if (!rule_allowed(&request.target, rules, count)) {
        reply(client, "403 Forbidden"); return;
    }
    int remote = public_connection(&request.target);
    if (remote < 0) { reply(client, "502 Bad Gateway"); return; }
    if (request.connect) {
        static const char established[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
        if (!send_all(client, established, sizeof(established)-1)) tunnel(client, remote);
    } else if (!send_all(remote, request.rewritten, request.rewritten_size)) {
        forward_http(client, remote, &request);
    }
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

static void reap_workers(int signal_number)
{
    (void)signal_number;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        if (active_workers > 0)
            --active_workers;
    errno = saved_errno;
}

static int serve(int listener, const struct enclio_network_rule *rules, size_t rule_count)
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
        pid_t child = active_workers >= ENCLIO_MAX_WORKERS ? -1 : fork();
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
            alarm(ENCLIO_LIFETIME_SECONDS);
            proxy_client(client, rules, rule_count);
            close(client);
            _exit(0);
        }
        if (child > 0)
            ++active_workers;
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
        close(client);
    }
}

/* A private socketpair carries one versioned listener record, then one ACK.
 * Ancillary data is never accepted from workload-visible endpoints. */
static int valid_control_channel(int control)
{
    int type = 0;
    socklen_t size = sizeof(type);
    struct sockaddr_storage address;
    socklen_t length = sizeof(address);
    if (getsockopt(control, SOL_SOCKET, SO_TYPE, &type, &size) || type != SOCK_SEQPACKET ||
        getsockname(control, (struct sockaddr *)&address, &length) ||
        address.ss_family != AF_UNIX) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int control_wait(int control, short events, int64_t deadline)
{
    struct pollfd p = {.fd = control, .events = events};
    for (;;) {
        int64_t remaining = deadline - monotonic_ms();
        if (remaining <= 0) { errno = ETIMEDOUT; return -1; }
        int ready = poll(&p, 1, remaining > 2147483647 ? 2147483647 : (int)remaining);
        if (ready > 0) {
            if (p.revents & events) return 0;
            errno = ECONNRESET;
            return -1;
        }
        if (ready < 0 && errno != EINTR) return -1;
    }
}

static int send_control(int control, const char tag[4], int descriptor, int64_t deadline)
{
    struct iovec iov = {.iov_base = (void *)tag, .iov_len = 4};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } ancillary;
    memset(&ancillary, 0, sizeof(ancillary));
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
    if (descriptor >= 0) {
        message.msg_control = ancillary.bytes;
        message.msg_controllen = sizeof(ancillary.bytes);
        struct cmsghdr *c = CMSG_FIRSTHDR(&message);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &descriptor, sizeof(descriptor));
    }
    for (;;) {
        if (control_wait(control, POLLOUT, deadline)) return -1;
        ssize_t n = sendmsg(control, &message, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n == 4) return 0;
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n >= 0) errno = EPROTO;
        return -1;
    }
}

static int receive_control(int control, const char tag[4], int want_descriptor,
                           int64_t deadline)
{
    char record[4];
    struct iovec iov = {.iov_base = record, .iov_len = sizeof(record)};
    union { struct cmsghdr align; char bytes[CMSG_SPACE(16 * sizeof(int))]; } ancillary;
    struct msghdr message;
    ssize_t n;
    for (;;) {
        if (control_wait(control, POLLIN, deadline)) return -1;
        memset(&message, 0, sizeof(message));
        memset(&ancillary, 0, sizeof(ancillary));
        message.msg_iov = &iov;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.bytes;
        message.msg_controllen = sizeof(ancillary.bytes);
        n = recvmsg(control, &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        break;
    }
    if (n < 0) return -1;
    int descriptors[16], count = 0, records = 0;
    int invalid = n != 4 || memcmp(record, tag, 4) ||
                  (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
        ++records;
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
            c->cmsg_len < CMSG_LEN(0)) { invalid = 1; continue; }
        size_t payload = c->cmsg_len - CMSG_LEN(0);
        if (payload % sizeof(int)) invalid = 1;
        for (size_t i = 0; i < payload / sizeof(int); ++i) {
            int fd;
            memcpy(&fd, CMSG_DATA(c) + i * sizeof(int), sizeof(fd));
            if (count < 16) descriptors[count++] = fd;
            else { close(fd); invalid = 1; }
        }
    }
    if (count != want_descriptor || records != want_descriptor) invalid = 1;
    if (invalid) {
        for (int i = 0; i < count; ++i) close(descriptors[i]);
        errno = EPROTO;
        return -1;
    }
    return want_descriptor ? descriptors[0] : 0;
}

static int receive_listener(int control, unsigned timeout_ms)
{
    if (valid_control_channel(control)) return -1;
    int fd = receive_control(control, "EL01", 1, monotonic_ms() + timeout_ms);
    if (fd < 0) return -1;
    int type = 0, accepting = 0, protocol = 0;
    socklen_t size = sizeof(int);
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    memset(&address, 0, sizeof(address));
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) || type != SOCK_STREAM ||
        getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &size) || !accepting ||
        getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &size) || protocol != IPPROTO_TCP ||
        getsockname(fd, (struct sockaddr *)&address, &length) || length != sizeof(address) ||
        address.sin_family != AF_INET || address.sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
        address.sin_port != htons(ENCLIO_PROXY_PORT)) {
        close(fd);
        errno = EPROTO;
        return -1;
    }
    return fd;
}

int enclio_proxy_send_listener(int control, unsigned short port, unsigned timeout_ms)
{
    int64_t deadline = monotonic_ms() + timeout_ms;
    if (port != ENCLIO_PROXY_PORT || valid_control_channel(control)) {
        errno = EINVAL;
        return -1;
    }
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (listener < 0) return -1;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port),
                                  .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    int result = -1;
    if (!bind(listener, (struct sockaddr *)&address, sizeof(address)) &&
        !listen(listener, ENCLIO_MAX_WORKERS) &&
        !send_control(control, "EL01", listener, deadline) &&
        receive_control(control, "EA01", 0, deadline) == 0)
        result = 0;
    int saved_errno = errno;
    close(listener);
    errno = saved_errno;
    return result;
}

int enclio_proxy_serve_control(int control, const struct enclio_network_rule *rules,
                              size_t rule_count, unsigned timeout_ms)
{
    int result = -1, listener = -1;
    int64_t deadline = monotonic_ms() + timeout_ms;
    if (protect_server() || !rules || !rule_count || rule_count > ENCLIO_NETWORK_RULE_MAX)
        goto done;
    for (size_t i = 0; i < rule_count; ++i)
        if (!memchr(rules[i].host, 0, sizeof(rules[i].host)) ||
            !enclio_proxy_host_valid(rules[i].host) || !rules[i].port) {
            errno = EINVAL;
            goto done;
        }
    listener = receive_listener(control, timeout_ms);
    if (listener < 0 || transport_filter() || send_control(control, "EA01", -1, deadline))
        goto done;
    close(control);
    control = -1;
    result = serve(listener, rules, rule_count);
done:
    if (listener >= 0) close(listener);
    if (control >= 0) close(control);
    return result;
}

int enclio_proxy_serve_rules(const char *unix_path,
                            const struct enclio_network_rule *rules, size_t rule_count)
{
    struct sockaddr_un address;
    if (protect_server() < 0 || unix_address(unix_path, &address) < 0 || !rules || !rule_count ||
        rule_count > ENCLIO_NETWORK_RULE_MAX)
        return -1;
    for (size_t i = 0; i < rule_count; ++i)
        if (!memchr(rules[i].host, 0, sizeof(rules[i].host)) ||
            !enclio_proxy_host_valid(rules[i].host) || !rules[i].port) {
            errno = EINVAL;
            return -1;
        }
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0)
        return -1;
    mode_t old_mask = umask(0077);
    int bound = bind(listener, (const struct sockaddr *)&address, sizeof(address));
    umask(old_mask);
    if (bound < 0 || listen(listener, ENCLIO_MAX_WORKERS) < 0) {
        close(listener);
        if (bound == 0)
            unlink(unix_path);
        return -1;
    }
    (void)fcntl(listener, F_SETFD, FD_CLOEXEC);
    if (transport_filter() < 0) { close(listener); unlink(unix_path); return -1; }
    int result = serve(listener, rules, rule_count);
    close(listener);
    unlink(unix_path);
    return result;
}

int enclio_proxy_serve(const char *unix_path, const char *const *allowed_hosts,
                       size_t host_count)
{
    if (!allowed_hosts || !host_count || host_count > ENCLIO_NETWORK_RULE_MAX) return -1;
    struct enclio_network_rule rules[ENCLIO_NETWORK_RULE_MAX];
    for (size_t i = 0; i < host_count; ++i) {
        if (!enclio_proxy_host_valid(allowed_hosts[i]) ||
            !enclio_proxy_rule_parse(allowed_hosts[i], &rules[i], 443)) return -1;
    }
    return enclio_proxy_serve_rules(unix_path, rules, host_count);
}
