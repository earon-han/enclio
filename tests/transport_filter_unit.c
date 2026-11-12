#define _GNU_SOURCE
/* This test includes the implementation to exercise the private filter in an
 * isolated child; it does not add a test-only API to the production binary. */
#include <seccomp.h>
#include <string.h>
static int legacy_database;
static int test_resolve(const char *name)
{
    if (legacy_database && !strcmp(name, "fchmodat2")) return __NR_SCMP_ERROR;
    return seccomp_syscall_resolve_name(name);
}
#define seccomp_syscall_resolve_name test_resolve
#include "../src/proxy.c"
#undef seccomp_syscall_resolve_name
#include <assert.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <sys/syscall.h>

int main(void)
{
#ifndef __linux__
    puts("transport filter: Linux required");
    return 77;
#else
    char path[] = "/tmp/enclio-transport-filter-XXXXXX";
    int temporary = mkstemp(path);
    assert(temporary >= 0); close(temporary);
    int chmod_syscall = seccomp_syscall_resolve_name("fchmodat2");
#if defined(__x86_64__) || defined(__aarch64__)
    if (chmod_syscall == __NR_SCMP_ERROR) chmod_syscall = 452;
#endif
    assert(chmod_syscall >= 0);
    errno = 0;
    long supported = syscall(chmod_syscall, AT_FDCWD, path, 0640, 0);
    assert(supported == 0 || (supported == -1 && errno == ENOSYS));
    struct stat baseline;
    assert(stat(path, &baseline) == 0);
    int metadata = open(path, O_RDONLY);
    assert(metadata >= 0);
    int original_flags = 0;
    int flags_available = ioctl(metadata, FS_IOC_GETFLAGS, &original_flags) == 0;
    for (int legacy = 0; legacy < 2; legacy++) {
        pid_t child = fork();
        assert(child >= 0);
        if (!child) {
            legacy_database = legacy;
            assert(protect_server() == 0);
            assert(transport_filter() == 0);
            assert(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
            assert(prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 2);
            errno = 0;
            assert(open(path, O_WRONLY) == -1 && errno == EPERM);
            errno = 0;
            assert(open(path, O_RDONLY | O_CREAT, 0600) == -1 && errno == EPERM);
            errno = 0;
            assert(ioctl(-1, 0x5412, NULL) == -1 && errno == EPERM);
            int changed_flags = original_flags ^ FS_NODUMP_FL;
            errno = 0;
            assert(ioctl(metadata, FS_IOC_SETFLAGS, &changed_flags) == -1 && errno == EPERM);
#if defined(__x86_64__) || defined(__aarch64__)
            errno = 0;
            assert(ioctl(metadata, (unsigned long)FS_IOC_SETFLAGS | (1UL << 32),
                         &changed_flags) == -1 && errno == EPERM);
#endif
            errno = 0;
            assert(unlink(path) == -1 && errno == EPERM);
            errno = 0;
            assert(syscall(chmod_syscall, AT_FDCWD, path, 0644, 0) == -1 && errno == EPERM);
            struct stat after;
            assert(stat(path, &after) == 0 && after.st_mode == baseline.st_mode);
            int readable = open(path, O_RDONLY);
            assert(readable >= 0); close(readable);
            struct addrinfo *addresses = NULL;
            struct addrinfo hint = {.ai_family=AF_UNSPEC, .ai_socktype=SOCK_STREAM};
            assert(getaddrinfo("localhost", "443", &hint, &addresses) == 0);
            freeaddrinfo(addresses);
            char *args[] = {"/bin/true", NULL};
            errno = 0;
            assert(execv(args[0], args) == -1 && errno == EPERM);
            _exit(0);
        }
        int status;
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        if (flags_available) {
            int after_flags = 0;
            assert(ioctl(metadata, FS_IOC_GETFLAGS, &after_flags) == 0 &&
                   after_flags == original_flags);
        }
    }
    close(metadata);
    assert(unlink(path) == 0);
    puts("transport filter: no_new_privs/seccomp, writes/ioctl/exec denied, read/NSS allowed PASS");
    return 0;
#endif
}
