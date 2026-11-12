#define _GNU_SOURCE
#include "proxy.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

/* Test-only linker wrappers: the production binary has no private-address or
 * resolver override. Keep validation on fake public sockaddrs, then connect the
 * harness to its loopback peer after recording what the proxy actually chose. */
int __real_getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
int __real_connect(int, const struct sockaddr *, socklen_t);

int __wrap_getaddrinfo(const char *name, const char *service,
                       const struct addrinfo *hints, struct addrinfo **result)
{
    if (!name || (hints && (hints->ai_flags & AI_NUMERICHOST)))
        return __real_getaddrinfo(name, service, hints, result);
    if (!strcasecmp(name, "missing.test")) return EAI_NONAME;
    static unsigned flip_queries;
    int flip_private = !strcasecmp(name, "flip.test") && ++flip_queries > 1;
    const char *ip = flip_private ? "127.0.0.1" : !strcasecmp(name, "refused.test") ? "8.8.4.4" :
                     !strcasecmp(name, "private.test") ? "127.0.0.1" : "8.8.8.8";
    struct addrinfo literal = hints ? *hints : (struct addrinfo){0};
    literal.ai_flags |= AI_NUMERICHOST;
    literal.ai_family = AF_INET;
    int rc = __real_getaddrinfo(ip, service, &literal, result);
    if (!rc && !strcasecmp(name, "mixed.test")) {
        struct addrinfo *private = NULL;
        rc = __real_getaddrinfo("127.0.0.1", service, &literal, &private);
        if (!rc) (*result)->ai_next = private;
    }
    return rc;
}

int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length)
{
    if (address && address->sa_family == AF_INET) {
        const struct sockaddr_in *actual = (const struct sockaddr_in *)address;
        const char *audit = getenv("ENCLIO_CONNECT_AUDIT_FD");
        if (audit) {
            char ip[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &actual->sin_addr, ip, sizeof(ip))) {
                char line[128];
                int n = snprintf(line, sizeof(line), "%s:%u\n", ip, ntohs(actual->sin_port));
                if (n > 0) (void)!write(atoi(audit), line, (size_t)n);
            }
        }
        if (ntohl(actual->sin_addr.s_addr) == 0x08080404U) {
            errno = ECONNREFUSED; return -1;
        }
        if (ntohl(actual->sin_addr.s_addr) == 0x08080808U) {
            struct sockaddr_in local = *actual;
            local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            return __real_connect(fd, (const struct sockaddr *)&local, sizeof(local));
        }
    }
    return __real_connect(fd, address, length);
}

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 66) return 2;
    struct enclio_network_rule rules[64];
    for (int i = 2; i < argc; i++)
        if (!enclio_proxy_rule_parse(argv[i], &rules[i - 2], 0)) return 2;
    signal(SIGPIPE, SIG_IGN);
    return enclio_proxy_serve_rules(argv[1], rules, (size_t)(argc - 2)) ? 1 : 0;
}
