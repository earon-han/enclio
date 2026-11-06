#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("PROBE_EXECUTED");
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "strict-unknown") || !strcmp(argv[1], "compat-unknown")) {
#ifdef SYS_getcpu
        unsigned cpu = 0, node = 0;
        errno = 0;
        long result = syscall(SYS_getcpu, &cpu, &node, NULL);
        printf("UNKNOWN_SYSCALL_RESULT=%ld ERRNO=%d\n", result, errno);
        return !strcmp(argv[1], "strict-unknown") ?
            !(result == -1 && errno == EPERM) : result != 0;
#else
        return 77;
#endif
    }
    if (!strcmp(argv[1], "compat-abi")) {
#if defined(__x86_64__)
        __asm__ volatile ("movl $20, %%eax; int $0x80" ::: "eax", "memory");
        return 22;
#else
        return 77;
#endif
    }
    if (!strcmp(argv[1], "stdin-write")) {
        errno = 0;
        ssize_t n = write(STDIN_FILENO, "MUST_NOT_REACH_HOST", 19);
        printf("STDIN_WRITE=%ld ERRNO=%d\n", (long)n, errno);
        return n == -1 && errno == EBADF ? 0 : 23;
    }
    if (!strcmp(argv[1], "hugetlb")) {
#ifdef SYS_memfd_create
        errno = 0;
        int fd = (int)syscall(SYS_memfd_create, "quota-bypass", MFD_HUGETLB);
        if (fd >= 0) { close(fd); return 24; }
        if (errno != EPERM) return 25;
#endif
        errno = 0;
        void *p = mmap(NULL, 2UL * 1024 * 1024, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
        if (p != MAP_FAILED) { munmap(p, 2UL * 1024 * 1024); return 26; }
        printf("HUGETLB_MMAP_ERRNO=%d\n", errno);
        return errno == EPERM ? 0 : 27;
    }
    if (!strcmp(argv[1], "memory")) {
        for (;;) {
            void *memory = malloc(1024 * 1024);
            if (!memory) { perror("malloc"); return 10; }
            memset(memory, 0x5a, 1024 * 1024);
            /* Retain one address from every block so the compiler cannot erase
             * these actual resident-page writes as dead allocations. */
            printf("ALLOCATED=%p\n", memory);
        }
    }
    if (!strcmp(argv[1], "pids")) {
        pid_t children[4096]; size_t count = 0;
        for (; count < sizeof(children) / sizeof(children[0]); count++) {
            pid_t p = fork();
            if (p < 0) break;
            if (!p) { for (;;) pause(); }
            children[count] = p;
        }
        int saved = errno;
        printf("CHILDREN=%zu FORK_ERRNO=%d\n", count, saved);
        for (size_t i = 0; i < count; i++) kill(children[i], SIGKILL);
        for (size_t i = 0; i < count; i++) waitpid(children[i], NULL, 0);
        return count > 0 && count < 4096 && saved == EAGAIN ? 0 : 11;
    }
    if (!strcmp(argv[1], "cpu")) {
        volatile unsigned long counter = 0;
        for (;;) counter++;
    }
    if (!strcmp(argv[1], "output")) {
        char block[4096]; memset(block, 'x', sizeof(block));
        for (;;) {
            if (write(1, block, sizeof(block)) < 0) return 0;
            if (write(2, block, sizeof(block)) < 0) return 0;
        }
    }
    if (!strcmp(argv[1], "disk")) {
        const char *paths[] = {"/workspace/fill", "/tmp/fill", "/home/agent/fill",
                               "/run/fill", "/dev/shm/fill", "/outside-workspace-fill"};
        char block[65536]; memset(block, 'd', sizeof(block));
        unsigned long total = 0;
        dev_t first = 0;
        for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
            int fd = open(paths[i], O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (fd < 0) { perror(paths[i]); return 12; }
            struct stat st;
            if (fstat(fd, &st)) return 13;
            if (!i) first = st.st_dev;
            if (st.st_dev != first) return 14;
            ssize_t n;
            while ((n = write(fd, block, sizeof(block))) > 0) total += (unsigned long)n;
            int saved = errno; close(fd);
            printf("DISK_PATH=%s ERRNO=%d TOTAL=%lu\n", paths[i], saved, total);
            if (saved != ENOSPC) return 15;
        }
        return total > 0 ? 0 : 16;
    }
    if (!strcmp(argv[1], "address")) {
        void *p = mmap(NULL, 128UL * 1024 * 1024, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) { munmap(p, 128UL * 1024 * 1024); return 17; }
        printf("ADDRESS_ERRNO=%d\n", errno);
        return errno == ENOMEM ? 0 : 18;
    }
    if (!strcmp(argv[1], "files")) {
        int fds[4096]; size_t count = 0;
        for (; count < sizeof(fds) / sizeof(fds[0]); count++) {
            fds[count] = open("/dev/null", O_RDONLY);
            if (fds[count] < 0) break;
        }
        int saved = errno;
        for (size_t i = 0; i < count; i++) close(fds[i]);
        printf("OPEN_FILES=%zu ERRNO=%d\n", count, saved);
        return count > 0 && count < 4096 && saved == EMFILE ? 0 : 19;
    }
    if (!strcmp(argv[1], "file-size")) {
        signal(SIGXFSZ, SIG_IGN);
        int fd = open("/workspace/large-file", O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) return 20;
        char block[4096]; memset(block, 'f', sizeof(block));
        ssize_t n; unsigned long total = 0;
        while ((n = write(fd, block, sizeof(block))) > 0) total += (unsigned long)n;
        int saved = errno; close(fd);
        printf("FILE_BYTES=%lu ERRNO=%d\n", total, saved);
        return total > 0 && saved == EFBIG ? 0 : 21;
    }
    return 2;
}
