#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include "../src/proxy.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void address_case(const char *text, int expected)
{
    struct sockaddr_storage address;
    memset(&address, 0, sizeof(address));
    if (strchr(text, ':')) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&address;
        v6->sin6_family = AF_INET6;
        assert(inet_pton(AF_INET6, text, &v6->sin6_addr) == 1);
    } else {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&address;
        v4->sin_family = AF_INET;
        assert(inet_pton(AF_INET, text, &v4->sin_addr) == 1);
    }
    assert(tg_proxy_address_public((struct sockaddr *)&address) == expected);
}

static int unix_connect(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    assert(strlen(path) < sizeof(address.sun_path));
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void request_case(const char *path, const char *request, const char *status)
{
    int fd = unix_connect(path);
    assert(fd >= 0);
    size_t length = strlen(request), sent = 0;
    while (sent < length) {
        ssize_t n = write(fd, request + sent, length - sent);
        assert(n > 0);
        sent += (size_t)n;
    }
    char response[256];
    ssize_t n = read(fd, response, sizeof(response) - 1);
    assert(n > 0);
    response[n] = '\0';
    if (strncmp(response, status, strlen(status)) != 0) {
        fprintf(stderr, "request %s: expected %s; got %s\n", request, status, response);
        abort();
    }
    close(fd);
}

int main(void)
{
    alarm(30);
    const char *valid[] = { "example.com", "EXAMPLE.com", "a", "x-y.example" };
    const char *invalid[] = { "", "127.0.0.1", "2130706433", "[::1]", "example.com.",
                              "*.example.com", "-a.example", "a-.example", "a..b", "a/b", "a:b", "a\nb",
                              "0x7f000001", "0x08080808", "0177.0.0.1", "127.1" };
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i)
        assert(tg_proxy_host_valid(valid[i]));
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        assert(!tg_proxy_host_valid(invalid[i]));
    const char *blocked[] = { "0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254",
                              "172.16.0.1", "172.31.255.255", "192.168.1.1", "192.0.2.1", "198.18.0.1",
                              "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255", "::1",
                              "::ffff:127.0.0.1", "fe80::1", "fc00::1", "64:ff9b::7f00:1",
                              "2001::1", "2001:db8::1", "2002:7f00:1::1", "3fff::1" };
    for (size_t i = 0; i < sizeof(blocked) / sizeof(blocked[0]); ++i)
        address_case(blocked[i], 0);
    address_case("1.1.1.1", 1);
    address_case("8.8.8.8", 1);
    address_case("2606:4700:4700::1111", 1);
    address_case("2001:4860:4860::8888", 1);

    char directory[] = "/tmp/tegum-proxy-test-XXXXXX";
    assert(mkdtemp(directory));
    char path[108];
    assert(snprintf(path, sizeof(path), "%s/proxy.sock", directory) > 0);
    pid_t server = fork();
    assert(server >= 0);
    if (!server) {
        const char *allowed[] = { "localhost" };
        int result = tg_proxy_serve(path, allowed, 1);
        fprintf(stderr, "proxy server stopped: %s\n", strerror(errno));
        _exit(result == 0 ? 0 : 1);
    }
    int ready = 0;
    for (int i = 0; i < 200; ++i) {
        int fd = unix_connect(path);
        if (fd >= 0) {
            close(fd);
            ready = 1;
            break;
        }
        struct timespec wait = { .tv_nsec = 10000000 };
        nanosleep(&wait, NULL);
    }
    assert(ready);
    request_case(path, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", "HTTP/1.1 403");
    request_case(path, "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n", "HTTP/1.1 502");
    const char *malformed[] = {
        "GET http://example.com/ HTTP/1.1\r\n\r\n",
        "CONNECT localhost:80 HTTP/1.1\r\n\r\n",
        "CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n",
        "CONNECT localhost:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\nHost: localhost:443\r\n\r\n",
        "CONNECT localhost:443 HTTP/1.1\r\nContent-Length: 2\r\n\r\nxx",
        "CONNECT localhost:443 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "CONNECT localhost:443 HTTP/1.1\r\n X-Header: x\r\n\r\n",
        "CONNECT localhost:443 HTTP/1.1\r\nX-Test: a\nb\r\n\r\n"
    };
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i)
        request_case(path, malformed[i], "HTTP/1.1 400");
    assert(kill(server, SIGTERM) == 0);
    assert(waitpid(server, NULL, 0) == server);
    unlink(path);
    assert(rmdir(directory) == 0);
    puts("proxy unit: address policy, host policy, CONNECT rejection PASS");
    return 0;
}
