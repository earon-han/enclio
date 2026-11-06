#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Host-side fault injection only. It is not linked into any Enclio artifact. */
ssize_t sendmsg(int fd, const struct msghdr *message, int flags)
{
    static int delayed;
    char name[16] = {0};
    (void)prctl(PR_GET_NAME, name);
    if (!delayed && !strcmp(name, "enclio-guard")) {
        delayed = 1;
        struct timespec delay = {.tv_sec=1,.tv_nsec=500000000};
        while (nanosleep(&delay, &delay) != 0) {}
    }
    typedef ssize_t (*original)(int, const struct msghdr *, int);
    original function;
    *(void **)(&function) = dlsym(RTLD_NEXT, "sendmsg");
    return function(fd, message, flags);
}
