#define _GNU_SOURCE
#include "output.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
int enclio_output_open(struct enclio_output *out, int input, int destination)
{
    memset(out, 0, sizeof(*out));
    out->input = input;
    out->destination = -1;
    struct stat st;
    if (fstat(destination, &st))
        return -1;
    /* Reopening pipes/ttys gives a distinct open-file description: changing
     * O_NONBLOCK must never mutate the caller's original descriptor flags. */
    if (S_ISFIFO(st.st_mode) || S_ISCHR(st.st_mode)) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", destination);
        out->destination = open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    } else
        out->destination = fcntl(destination, F_DUPFD_CLOEXEC, 10);
    return out->destination < 0 ? -1 : 0;
}
int enclio_output_read(struct enclio_output *out, uint64_t *total, uint64_t maximum)
{
    if (out->eof || out->begin != out->end)
        return 0;
    out->begin = out->end = 0;
    ssize_t n = read(out->input, out->bytes, sizeof(out->bytes));
    if (!n) {
        out->eof = true;
        close(out->input);
        out->input = -1;
        return 0;
    }
    if (n < 0)
        return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
    uint64_t available = maximum - *total;
    out->end = (size_t)n;
    if ((uint64_t)n > available) {
        out->end = (size_t)available;
        *total = maximum;
        return 1;
    }
    *total += (uint64_t)n;
    return 0;
}
int enclio_output_write(struct enclio_output *out)
{
    if (out->begin == out->end)
        return 0;
    ssize_t n = write(out->destination, out->bytes + out->begin, out->end - out->begin);
    if (n > 0) {
        out->begin += (size_t)n;
        return 0;
    }
    if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
        return 0;
    return -1;
}
void enclio_output_close(struct enclio_output *out)
{
    if (out->input >= 0)
        close(out->input);
    if (out->destination >= 0)
        close(out->destination);
    out->input = out->destination = -1;
}
int enclio_input_open(struct enclio_output *input, int pipe_destination)
{
    memset(input, 0, sizeof(*input));
    input->input = -1;
    input->destination = pipe_destination;
    struct stat st;
    if (fstat(0, &st))
        return -1;
    if (S_ISFIFO(st.st_mode) || S_ISCHR(st.st_mode))
        input->input = open("/proc/self/fd/0", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    else
        input->input = fcntl(0, F_DUPFD_CLOEXEC, 10);
    int f = fcntl(pipe_destination, F_GETFL);
    if (input->input < 0 || f < 0 || fcntl(pipe_destination, F_SETFL, f | O_NONBLOCK) < 0)
        return -1;
    return 0;
}
