#ifndef ENCLIO_GUARDIAN_H
#define ENCLIO_GUARDIAN_H
#include <sys/types.h>
#include "resources.h"
struct enclio_guardian {
    pid_t pid;
    int fd;
};
int enclio_guardian_start(struct enclio_guardian *guard, char *temporary, size_t temporary_size,
                          const char *cgroup_parent, const struct enclio_resource_limits *limits,
                          struct enclio_resources *resources, char *error, size_t error_size,
                          unsigned startup_timeout_ms, int caller_fd);
int enclio_guardian_track(struct enclio_guardian *guard, pid_t process);
int enclio_guardian_stop(struct enclio_guardian *guard, bool disarm);
#endif
