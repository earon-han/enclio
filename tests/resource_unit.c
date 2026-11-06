#define _GNU_SOURCE
#include "../src/resources.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int remove_entry(const char *path, const struct stat *st, int kind, struct FTW *walk)
{
    (void)st; (void)kind; (void)walk;
    return remove(path);
}
static void write_file(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    assert(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
    assert(close(fd) == 0);
}
static void checked_path(char *output, size_t size, const char *root, const char *name)
{
    int length = snprintf(output, size, "%s/%s", root, name);
    assert(length > 0 && (size_t)length < size);
}
static void workspace_cases(const char *root)
{
    char source[1024], destination[1024], exported[1024], path[1024], other[1024], error[256];
    checked_path(source, sizeof(source), root, "source");
    checked_path(destination, sizeof(destination), root, "destination");
    checked_path(exported, sizeof(exported), root, "exported");
    assert(!mkdir(source, 0700) && !mkdir(destination, 0700) && !mkdir(exported, 0700));
    checked_path(path, sizeof(path), source, "data"); write_file(path, "workspace data\n");
    assert(chmod(path, 06755) == 0);
    checked_path(path, sizeof(path), source, "link"); assert(symlink("/etc/passwd", path) == 0);
    checked_path(path, sizeof(path), source, "nested"); assert(!mkdir(path, 0700));
    checked_path(path, sizeof(path), source, "nested/file"); write_file(path, "nested data\n");
    assert(enclio_workspace_copy(source, destination, error, sizeof(error)) == 0);
    checked_path(path, sizeof(path), destination, "data");
    struct stat st; assert(!stat(path, &st) && !(st.st_mode & 06000));
    char buffer[128]; int fd = open(path, O_RDONLY); assert(fd >= 0);
    ssize_t count = read(fd, buffer, sizeof(buffer)); assert(count == 15); close(fd);
    assert(!memcmp(buffer, "workspace data\n", 15));
    checked_path(path, sizeof(path), destination, "link");
    count = readlink(path, buffer, sizeof(buffer));
    assert(count == 11 && !memcmp(buffer, "/etc/passwd", 11));
    fd = open(exported, O_RDONLY | O_DIRECTORY); assert(fd >= 0);
    assert(!enclio_workspace_export(source, fd, error, sizeof(error))); close(fd);
    assert(enclio_workspace_export(source, -1, error, sizeof(error)) == -1);

    char collision[1024], single[1024], victim[1024];
    checked_path(collision, sizeof(collision), root, "collision"); assert(!mkdir(collision, 0700));
    checked_path(single, sizeof(single), root, "single"); assert(!mkdir(single, 0700));
    checked_path(victim, sizeof(victim), root, "victim"); write_file(victim, "KEEP");
    checked_path(path, sizeof(path), single, "data"); write_file(path, "do not follow destination link");
    checked_path(path, sizeof(path), collision, "data"); assert(symlink(victim, path) == 0);
    assert(enclio_workspace_copy(single, collision, error, sizeof(error)) == -1 && errno == EEXIST);
    fd = open(victim, O_RDONLY); assert(fd >= 0); assert(read(fd, buffer, sizeof(buffer)) == 4); close(fd);
    assert(!memcmp(buffer, "KEEP", 4));

    checked_path(other, sizeof(other), root, "special"); assert(!mkdir(other, 0700));
    checked_path(path, sizeof(path), other, "fifo"); assert(!mkfifo(path, 0600));
    assert(enclio_workspace_copy(other, destination, error, sizeof(error)) == -1 && errno == EINVAL);
    checked_path(path, sizeof(path), root, "source-link"); assert(!symlink(source, path));
    assert(enclio_workspace_copy(path, destination, error, sizeof(error)) == -1);
    char sparse_source[1024], sparse_output[1024];
    checked_path(sparse_source, sizeof(sparse_source), root, "sparse-source");
    checked_path(sparse_output, sizeof(sparse_output), root, "sparse-output");
    assert(!mkdir(sparse_source, 0700) && !mkdir(sparse_output, 0700));
    checked_path(path, sizeof(path), sparse_source, "huge");
    fd = open(path, O_WRONLY|O_CREAT|O_EXCL, 0600); assert(fd >= 0);
    assert(!ftruncate(fd, (off_t)1024*1024*1024*1024)); close(fd);
    assert(enclio_workspace_copy(sparse_source, sparse_output, error, sizeof(error)) < 0 && errno == EFBIG);
    fd = open(sparse_output, O_RDONLY|O_DIRECTORY); assert(fd >= 0);
    assert(enclio_workspace_export(sparse_source, fd, error, sizeof(error)) < 0 && errno == EFBIG);
    close(fd);
    checked_path(path, sizeof(path), sparse_output, "huge");
    assert(lstat(path, &st) < 0 && errno == ENOENT);
    puts("resource unit: workspace copy/export, links, modes, collisions, special and 1TiB sparse files PASS");
}
static void rlimit_cases(const char *root)
{
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        struct rlimit zero = {0, 0}; assert(!setrlimit(RLIMIT_CORE, &zero));
        struct enclio_resource_limits limits = {.address_space_bytes = 64U*1024U*1024U,
            .file_bytes = 4096, .open_files = 32};
        char error[256];
        if (enclio_resources_apply_rlimits(&limits, error, sizeof(error))) {
            fprintf(stderr, "%s\n", error); _exit(1);
        }
        void *memory = mmap(NULL, 128U*1024U*1024U, PROT_READ|PROT_WRITE,
                            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        assert(memory == MAP_FAILED && errno == ENOMEM);
        signal(SIGXFSZ, SIG_IGN);
        char path[1024], bytes[8192] = {0}; checked_path(path, sizeof(path), root, "limited-file");
        int fd = open(path, O_WRONLY|O_CREAT|O_EXCL, 0600); assert(fd >= 0);
        assert(write(fd, bytes, sizeof(bytes)) == 4096);
        assert(write(fd, bytes, 1) < 0 && errno == EFBIG); close(fd);
        int descriptors[64], n = 0;
        while (n < 64 && (descriptors[n] = open("/dev/null", O_RDONLY)) >= 0) n++;
        assert(n < 32 && errno == EMFILE);
        while (n) close(descriptors[--n]);
        _exit(0);
    }
    int status; assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    puts("resource unit: real address-space, file-size and descriptor hard limits PASS");
}
static void cpu_rlimit_cases(void)
{
    for (unsigned ignore = 0; ignore < 2; ignore++) {
        pid_t child = fork(); assert(child >= 0);
        if (!child) {
            struct enclio_resource_limits limits = {.cpu_seconds = 1};
            char error[256];
            signal(SIGXCPU, ignore ? SIG_IGN : SIG_DFL);
            alarm(5);
            if (enclio_resources_apply_rlimits(&limits, error, sizeof(error))) _exit(2);
            volatile unsigned long work = 0;
            for (;;) work++;
        }
        int status;
        assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status));
        assert(WTERMSIG(status) == (ignore ? SIGKILL : SIGXCPU));
    }
    puts("resource unit: CPU soft SIGXCPU and ignored-signal hard SIGKILL PASS");
}
static long milliseconds(void)
{
    struct timespec value; assert(!clock_gettime(CLOCK_MONOTONIC, &value));
    return value.tv_sec*1000L + value.tv_nsec/1000000L;
}
static void cgroup_cases(const char *parent)
{
    char error[512];
    struct enclio_resources resources;
    struct enclio_resource_limits limits = {.memory_bytes = 64U*1024U*1024U, .pids_max = 8, .cpu_percent = 25};
    if (enclio_resources_prepare(parent, &limits, &resources, error, sizeof(error))) {
        fprintf(stderr, "%s\n", error); exit(1);
    }
    int ready[2]; assert(!pipe(ready));
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        close(ready[0]);
        if (enclio_resources_enter(&resources, error, sizeof(error))) {
            fprintf(stderr, "%s\n", error); _exit(2);
        }
        unsigned created = 0;
        for (; created < 32; created++) {
            pid_t next = fork();
            if (!next) { close(ready[1]); for (;;) pause(); }
            if (next < 0) break;
        }
        char state = created < 32 && errno == EAGAIN ? 'P' : 'F';
        assert(write(ready[1], &state, 1) == 1);
        for (;;) pause();
    }
    close(ready[1]); char state = 0;
    assert(read(ready[0], &state, 1) == 1 && state == 'P'); close(ready[0]);
    struct enclio_resource_stats stats;
    assert(!enclio_resources_stats(&resources, &stats, error, sizeof(error)));
    assert(stats.pids_current == 8 && stats.pids_max_events > 0);
    assert(!enclio_resources_cleanup(&resources, error, sizeof(error)));
    while (waitpid(-1, NULL, 0) > 0) {}
    puts("resource unit: cgroup pids enforcement and atomic subtree cleanup PASS");

    assert(!enclio_resources_prepare(parent, &limits, &resources, error, sizeof(error)));
    child = fork(); assert(child >= 0);
    if (!child) {
        if (enclio_resources_enter(&resources, error, sizeof(error))) _exit(2);
        long end = milliseconds() + 1200;
        volatile unsigned long work = 0;
        while (milliseconds() < end) work++;
        _exit(work == 0);
    }
    int status; assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(!enclio_resources_stats(&resources, &stats, error, sizeof(error)));
    assert(stats.cpu_usage_usec > 0 && stats.cpu_throttled_usec > 0);
    assert(!enclio_resources_cleanup(&resources, error, sizeof(error)));
    puts("resource unit: cgroup CPU bandwidth throttling PASS");

    limits.memory_bytes = 16U*1024U*1024U;
    assert(!enclio_resources_prepare(parent, &limits, &resources, error, sizeof(error)));
    child = fork(); assert(child >= 0);
    if (!child) {
        if (enclio_resources_enter(&resources, error, sizeof(error))) _exit(2);
        size_t length = 128U*1024U*1024U;
        volatile char *memory = mmap(NULL, length, PROT_READ|PROT_WRITE,
                                    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (memory == MAP_FAILED) _exit(3);
        for (size_t n = 0; n < length; n += 4096) memory[n] = 1;
        _exit(4);
    }
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    assert(!enclio_resources_stats(&resources, &stats, error, sizeof(error)) && stats.oom_kills > 0);
    assert(!enclio_resources_cleanup(&resources, error, sizeof(error)));
    puts("resource unit: cgroup memory OOM enforcement PASS");
}
int main(int argc, char **argv)
{
    alarm(30);
    assert(!prctl(PR_SET_CHILD_SUBREAPER, 1));
    char root[] = "/tmp/enclio-resource-unit-XXXXXX";
    assert(mkdtemp(root));
    workspace_cases(root); rlimit_cases(root); cpu_rlimit_cases();
    struct enclio_resources resources; char error[256];
    struct enclio_resource_limits limits = {.memory_bytes=64U*1024U*1024U};
    assert(enclio_resources_prepare(NULL, &limits, &resources, error, sizeof(error)) < 0);
    assert(enclio_resources_prepare(root, &limits, &resources, error, sizeof(error)) < 0 && errno == ENOTSUP);
    puts("resource unit: missing delegation and non-cgroup parents fail closed PASS");
    if (argc == 2) cgroup_cases(argv[1]);
    assert(nftw(root, remove_entry, 20, FTW_DEPTH|FTW_PHYS) == 0);
    puts("resource unit PASS");
    return 0;
}
