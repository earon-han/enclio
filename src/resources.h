#ifndef ENCLIO_RESOURCES_H
#define ENCLIO_RESOURCES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Zero leaves a limit unset. Aggregate limits never fall back to rlimits. */
struct enclio_resource_limits {
    uint64_t memory_bytes;
    unsigned pids_max;
    unsigned cpu_percent;
    unsigned cpu_seconds;
    uint64_t address_space_bytes;
    uint64_t file_bytes;
    unsigned open_files;
};

struct enclio_resources {
    int parent_fd;
    int group_fd;
    char name[96];
    bool active;
};

struct enclio_resource_stats {
    uint64_t cpu_usage_usec;
    uint64_t cpu_throttled_usec;
    uint64_t memory_current;
    uint64_t memory_peak;
    uint64_t memory_max_events;
    uint64_t oom_kills;
    uint64_t pids_current;
    uint64_t pids_peak;
    uint64_t pids_max_events;
    bool memory_peak_available;
    bool pids_peak_available;
};

int enclio_resources_prepare(const char *parent,
    const struct enclio_resource_limits *limits, struct enclio_resources *resources,
    char *error, size_t error_size);
int enclio_resources_enter(const struct enclio_resources *resources,
    char *error, size_t error_size);
int enclio_resources_stats(const struct enclio_resources *resources,
    struct enclio_resource_stats *stats, char *error, size_t error_size);
int enclio_resources_cleanup(struct enclio_resources *resources,
    char *error, size_t error_size);
int enclio_resources_apply_rlimits(const struct enclio_resource_limits *limits,
    char *error, size_t error_size);

/* Destinations must already exist. New entries are exclusively created: existing
 * entries are never overwritten or followed. No special files are accepted.
 * Total logical bytes are bounded by destination FS capacity (copy) or source
 * FS capacity (export), with 65536 entries and depth 128 maximum. */
int enclio_workspace_copy(const char *source, const char *destination,
    char *error, size_t error_size);
int enclio_workspace_export(const char *source, int destination_dirfd,
    char *error, size_t error_size);

#endif
