#define _GNU_SOURCE
#include "resources.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

static int resource_error(char *error, size_t size, const char *operation)
{
    int saved = errno;
    if (error && size) snprintf(error, size, "%s: %s", operation, strerror(saved));
    errno = saved;
    return -1;
}

static int write_control(int directory, const char *name, const char *value)
{
    int fd = openat(directory, name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    size_t size = strlen(value);
    ssize_t written;
    do { written = write(fd, value, size); } while (written < 0 && errno == EINTR);
    int saved = written < 0 ? errno : EIO;
    int result = written == (ssize_t)size ? 0 : -1;
    if (close(fd) < 0 && !result) return -1;
    if (result) errno = saved;
    return result;
}

/* 1: available; 0: missing; -1: other failure. */
static int read_control(int directory, const char *name, char *buffer, size_t size)
{
    int fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    size_t used = 0;
    while (used + 1 < size) {
        ssize_t n = read(fd, buffer + used, size - 1 - used);
        if (n > 0) used += (size_t)n;
        else if (!n) break;
        else if (errno != EINTR) { int saved = errno; close(fd); errno = saved; return -1; }
    }
    if (used + 1 == size) {
        char extra;
        ssize_t n;
        do { n = read(fd, &extra, 1); } while (n < 0 && errno == EINTR);
        if (n != 0) { int saved = n < 0 ? errno : EOVERFLOW; close(fd); errno = saved; return -1; }
    }
    close(fd);
    buffer[used] = 0;
    return 1;
}

static int number(const char *text, uint64_t *value)
{
    if (!*text || *text < '0' || *text > '9') { errno = EPROTO; return -1; }
    errno = 0;
    char *end;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno) return -1;
    while (*end == ' ' || *end == '\n' || *end == '\t') end++;
    if (*end) { errno = EPROTO; return -1; }
    *value = parsed;
    return 0;
}

static int stat_value(int directory, const char *name, uint64_t *value, bool *available)
{
    char buffer[128];
    int result = read_control(directory, name, buffer, sizeof(buffer));
    if (result < 0) return -1;
    if (available) *available = result == 1;
    return result ? number(buffer, value) : 0;
}

static int stat_key(int directory, const char *name, const char *key, uint64_t *value)
{
    char buffer[4096];
    int result = read_control(directory, name, buffer, sizeof(buffer));
    if (result <= 0) return result < 0 ? -1 : 0;
    size_t length = strlen(key);
    for (char *line = buffer; *line;) {
        char *end = strchr(line, '\n');
        if (end) *end = 0;
        if (!strncmp(line, key, length) && line[length] == ' ')
            return number(line + length + 1, value);
        if (!end) break;
        line = end + 1;
    }
    return 0;
}

int enclio_resources_prepare(const char *parent,
    const struct enclio_resource_limits *limits, struct enclio_resources *resources,
    char *error, size_t error_size)
{
    if (!resources || !limits) { errno = EINVAL; return resource_error(error, error_size, "resource arguments"); }
    memset(resources, 0, sizeof(*resources));
    resources->parent_fd = resources->group_fd = -1;
    bool aggregate = limits->memory_bytes || limits->pids_max || limits->cpu_percent;
    if (!parent || !*parent) {
        if (!aggregate) return 0;
        errno = ENOTSUP;
        return resource_error(error, error_size, "aggregate limits require a delegated cgroup parent");
    }
    long page = sysconf(_SC_PAGESIZE);
    if ((limits->memory_bytes && (page <= 0 || limits->memory_bytes % (uint64_t)page)) ||
        limits->cpu_percent > 102400) {
        errno = EINVAL;
        return resource_error(error, error_size, "memory limit must be page aligned; CPU limit maximum is 102400 percent");
    }
    resources->parent_fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (resources->parent_fd < 0) return resource_error(error, error_size, "open delegated cgroup parent");
    struct statfs fs;
    if (fstatfs(resources->parent_fd, &fs) < 0) goto fail;
    if (fs.f_type != CGROUP2_SUPER_MAGIC) { errno = ENOTSUP; goto fail; }
    uint64_t random;
    ssize_t received;
    do { received = getrandom(&random, sizeof(random), 0); } while (received < 0 && errno == EINTR);
    if (received != (ssize_t)sizeof(random)) { if (received >= 0) errno = EIO; goto fail; }
    snprintf(resources->name, sizeof(resources->name), "enclio-%ld-%016" PRIx64, (long)getpid(), random);
    if (mkdirat(resources->parent_fd, resources->name, 0700) < 0) goto fail;
    resources->active = true;
    resources->group_fd = openat(resources->parent_fd, resources->name,
                                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (resources->group_fd < 0) goto fail;
    /* Atomic subtree termination is mandatory. Never silently downgrade to a
     * process-list race or a global/UID-scoped rlimit. */
    int kill_fd = openat(resources->group_fd, "cgroup.kill", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (kill_fd < 0) goto fail;
    close(kill_fd);
    char value[96];
    if (limits->memory_bytes) {
        snprintf(value, sizeof(value), "%" PRIu64 "\n", limits->memory_bytes);
        if (write_control(resources->group_fd, "memory.max", value) < 0 ||
            write_control(resources->group_fd, "memory.swap.max", "0\n") < 0 ||
            write_control(resources->group_fd, "memory.oom.group", "1\n") < 0) goto fail;
        uint64_t readback;
        bool available;
        if (stat_value(resources->group_fd, "memory.max", &readback, &available) < 0 ||
            !available || readback != limits->memory_bytes) { errno = EIO; goto fail; }
    }
    if (limits->pids_max) {
        snprintf(value, sizeof(value), "%u\n", limits->pids_max);
        if (write_control(resources->group_fd, "pids.max", value) < 0) goto fail;
        uint64_t readback; bool available;
        if (stat_value(resources->group_fd, "pids.max", &readback, &available) < 0 ||
            !available || readback != limits->pids_max) { errno = EIO; goto fail; }
    }
    if (limits->cpu_percent) {
        snprintf(value, sizeof(value), "%" PRIu64 " 100000\n", (uint64_t)limits->cpu_percent * 1000);
        if (write_control(resources->group_fd, "cpu.max", value) < 0) goto fail;
        char readback[96];
        if (read_control(resources->group_fd, "cpu.max", readback, sizeof(readback)) != 1 ||
            strcmp(readback, value)) { errno = EIO; goto fail; }
    }
    return 0;
fail: {
        int saved = errno;
        char discarded[256];
        (void)enclio_resources_cleanup(resources, discarded, sizeof(discarded));
        errno = saved;
        return resource_error(error, error_size, "prepare cgroup (controllers and delegation must already be enabled)");
    }
}

int enclio_resources_enter(const struct enclio_resources *resources,
    char *error, size_t error_size)
{
    if (!resources || !resources->active) return 0;
    if (write_control(resources->group_fd, "cgroup.procs", "0\n") < 0)
        return resource_error(error, error_size, "join job cgroup");
    return 0;
}

int enclio_resources_stats(const struct enclio_resources *resources,
    struct enclio_resource_stats *stats, char *error, size_t error_size)
{
    if (!stats) { errno = EINVAL; return resource_error(error, error_size, "resource stats arguments"); }
    memset(stats, 0, sizeof(*stats));
    if (!resources || !resources->active) return 0;
    int fd = resources->group_fd;
    if (stat_key(fd, "cpu.stat", "usage_usec", &stats->cpu_usage_usec) < 0 ||
        stat_key(fd, "cpu.stat", "throttled_usec", &stats->cpu_throttled_usec) < 0 ||
        stat_value(fd, "memory.current", &stats->memory_current, NULL) < 0 ||
        stat_value(fd, "memory.peak", &stats->memory_peak, &stats->memory_peak_available) < 0 ||
        stat_key(fd, "memory.events", "max", &stats->memory_max_events) < 0 ||
        stat_key(fd, "memory.events", "oom_kill", &stats->oom_kills) < 0 ||
        stat_value(fd, "pids.current", &stats->pids_current, NULL) < 0 ||
        stat_value(fd, "pids.peak", &stats->pids_peak, &stats->pids_peak_available) < 0 ||
        stat_key(fd, "pids.events", "max", &stats->pids_max_events) < 0)
        return resource_error(error, error_size, "read job resource counters");
    return 0;
}

int enclio_resources_cleanup(struct enclio_resources *resources,
    char *error, size_t error_size)
{
    if (!resources) { errno = EINVAL; return resource_error(error, error_size, "resource cleanup arguments"); }
    int saved = 0;
    if (resources->active && resources->group_fd >= 0) {
        if (write_control(resources->group_fd, "cgroup.kill", "1\n") < 0) saved = errno;
        uint64_t populated = 0;
        bool empty = false;
        for (unsigned i = 0; i < 300; i++) {
            populated = 0;
            if (stat_key(resources->group_fd, "cgroup.events", "populated", &populated) < 0) {
                if (!saved) saved = errno;
                break;
            }
            if (!populated) { empty = true; break; }
            struct timespec delay = {.tv_nsec = 10000000};
            while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
        }
        if (!empty && !saved) saved = EBUSY;
    }
    if (resources->group_fd >= 0) close(resources->group_fd);
    resources->group_fd = -1;
    if (resources->active && resources->parent_fd >= 0 &&
        unlinkat(resources->parent_fd, resources->name, AT_REMOVEDIR) < 0 && !saved) saved = errno;
    if (resources->parent_fd >= 0) close(resources->parent_fd);
    resources->parent_fd = -1;
    resources->active = false;
    if (saved) { errno = saved; return resource_error(error, error_size, "kill and remove job cgroup"); }
    return 0;
}

static int set_limit(int resource, uint64_t value, char *error, size_t size)
{
    if (!value) return 0;
    if ((uint64_t)(rlim_t)value != value || (rlim_t)value == RLIM_INFINITY) {
        errno = ERANGE; return resource_error(error, size, "rlimit value out of range");
    }
    struct rlimit limit = {.rlim_cur = (rlim_t)value, .rlim_max = (rlim_t)value};
    if (setrlimit(resource, &limit) < 0) return resource_error(error, size, "set requested hard rlimit");
    return 0;
}

static int set_cpu_limit(unsigned seconds, char *error, size_t size)
{
    if (!seconds) return 0;
    uint64_t hard = (uint64_t)seconds + 1;
    if ((uint64_t)(rlim_t)hard != hard || (rlim_t)hard == RLIM_INFINITY) {
        errno = ERANGE; return resource_error(error, size, "CPU rlimit out of range");
    }
    struct rlimit limit = {.rlim_cur = (rlim_t)seconds, .rlim_max = (rlim_t)hard};
    if (setrlimit(RLIMIT_CPU, &limit) < 0)
        return resource_error(error, size, "set CPU soft/hard rlimit");
    return 0;
}

int enclio_resources_apply_rlimits(const struct enclio_resource_limits *limits,
    char *error, size_t error_size)
{
    if (!limits) { errno = EINVAL; return resource_error(error, error_size, "rlimit arguments"); }
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core) < 0) return resource_error(error, error_size, "disable core dumps");
    if (set_cpu_limit(limits->cpu_seconds, error, error_size) < 0 ||
        set_limit(RLIMIT_AS, limits->address_space_bytes, error, error_size) < 0 ||
        set_limit(RLIMIT_FSIZE, limits->file_bytes, error, error_size) < 0 ||
        set_limit(RLIMIT_NOFILE, limits->open_files, error, error_size) < 0) return -1;
    return 0;
}

#define ENCLIO_COPY_DEPTH_MAX 128
#define ENCLIO_COPY_ENTRY_MAX 65536
struct copy_budget { uint64_t bytes; unsigned entries; };

static int copy_directory(int source, int destination, unsigned depth, struct copy_budget *budget)
{
    if (depth > ENCLIO_COPY_DEPTH_MAX) { errno = ELOOP; return -1; }
    int duplicate = fcntl(source, F_DUPFD_CLOEXEC, 3);
    if (duplicate < 0) return -1;
    DIR *directory = fdopendir(duplicate);
    if (!directory) { int saved = errno; close(duplicate); errno = saved; return -1; }
    struct dirent *entry;
    int result = 0, saved = 0;
    for (;;) {
        errno = 0;
        entry = readdir(directory);
        if (!entry) { if (errno) { result = -1; saved = errno; } break; }
        const char *name = entry->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
        if (!budget->entries) { errno = E2BIG; goto entry_fail; }
        budget->entries--;
        struct stat st;
        if (fstatat(source, name, &st, AT_SYMLINK_NOFOLLOW) < 0) goto entry_fail;
        if (S_ISDIR(st.st_mode)) {
            int child = openat(source, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0) goto entry_fail;
            if (mkdirat(destination, name, 0700) < 0) { saved = errno; close(child); goto saved_fail; }
            int output = openat(destination, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (output < 0) { saved = errno; close(child); goto saved_fail; }
            result = copy_directory(child, output, depth + 1, budget);
            saved = errno;
            if (!result && fchmod(output, st.st_mode & 0777) < 0) { result = -1; saved = errno; }
            close(output); close(child);
            if (result < 0) goto saved_fail;
        } else if (S_ISREG(st.st_mode)) {
            int input = openat(source, name, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
            if (input < 0) goto entry_fail;
            struct stat actual;
            if (fstat(input, &actual) < 0) { saved = errno; close(input); goto saved_fail; }
            if (!S_ISREG(actual.st_mode)) { saved = EINVAL; close(input); goto saved_fail; }
            if (actual.st_size < 0 || (uint64_t)actual.st_size > budget->bytes) {
                saved = EFBIG; close(input); goto saved_fail;
            }
            int output = openat(destination, name,
                                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
            if (output < 0) { saved = errno; close(input); goto saved_fail; }
            char buffer[32768];
            for (;;) {
                ssize_t n = read(input, buffer, sizeof(buffer));
                if (n < 0 && errno == EINTR) continue;
                if (n < 0) { saved = errno; result = -1; break; }
                if (!n) break;
                if ((uint64_t)n > budget->bytes) { saved = EFBIG; result = -1; break; }
                budget->bytes -= (uint64_t)n;
                size_t offset = 0;
                while (offset < (size_t)n) {
                    ssize_t written = write(output, buffer + offset, (size_t)n - offset);
                    if (written < 0 && errno == EINTR) continue;
                    if (written <= 0) { saved = written < 0 ? errno : EIO; result = -1; break; }
                    offset += (size_t)written;
                }
                if (result < 0) break;
            }
            if (!result && fchmod(output, actual.st_mode & 0777) < 0) { saved = errno; result = -1; }
            if (close(output) < 0 && !result) { saved = errno; result = -1; }
            close(input);
            if (result < 0) { unlinkat(destination, name, 0); goto saved_fail; }
        } else if (S_ISLNK(st.st_mode)) {
            char target[PATH_MAX + 1];
            ssize_t length = readlinkat(source, name, target, sizeof(target) - 1);
            if (length < 0) goto entry_fail;
            if ((size_t)length == sizeof(target) - 1) { errno = ENAMETOOLONG; goto entry_fail; }
            if ((uint64_t)length > budget->bytes) { errno = EFBIG; goto entry_fail; }
            budget->bytes -= (uint64_t)length;
            target[length] = 0;
            if (symlinkat(target, destination, name) < 0) goto entry_fail;
        } else { errno = EINVAL; goto entry_fail; }
        continue;
entry_fail:
        saved = errno;
saved_fail:
        result = -1;
        break;
    }
    closedir(directory);
    if (result < 0) errno = saved;
    return result;
}

static int copy_into_fd(const char *source, int destination, bool exporting, char *error, size_t size)
{
    struct stat st;
    if (fstat(destination, &st) < 0)
        return resource_error(error, size, "stat workspace destination");
    if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        return resource_error(error, size, "workspace destination must be an open directory");
    }
    int input = open(source, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) return resource_error(error, size, "open workspace copy source");
    struct statvfs filesystem;
    if (fstatvfs(exporting ? input : destination, &filesystem) < 0) {
        int saved = errno; close(input); errno = saved;
        return resource_error(error, size, "read copy filesystem capacity");
    }
    uint64_t unit = filesystem.f_frsize ? filesystem.f_frsize : filesystem.f_bsize;
    if (!unit || !filesystem.f_blocks || (uint64_t)filesystem.f_blocks > UINT64_MAX / unit) {
        close(input); errno = EOVERFLOW;
        return resource_error(error, size, "invalid copy filesystem capacity");
    }
    struct copy_budget budget = {.bytes = (uint64_t)filesystem.f_blocks * unit,
                                 .entries = ENCLIO_COPY_ENTRY_MAX};
    int result = copy_directory(input, destination, 0, &budget);
    int saved = errno;
    close(input);
    if (result < 0) { errno = saved; return resource_error(error, size, "copy workspace (special files, collisions, depth and logical-byte/entry excess are rejected)"); }
    return 0;
}

int enclio_workspace_copy(const char *source, const char *destination, char *error, size_t error_size)
{
    int output = open(destination, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (output < 0) return resource_error(error, error_size, "open workspace copy destination");
    int result = copy_into_fd(source, output, false, error, error_size);
    int saved = errno;
    close(output); errno = saved;
    return result;
}

int enclio_workspace_export(const char *source, int destination_dirfd, char *error, size_t error_size)
{
    return copy_into_fd(source, destination_dirfd, true, error, error_size);
}
