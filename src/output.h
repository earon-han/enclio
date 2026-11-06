#ifndef ENCLIO_OUTPUT_H
#define ENCLIO_OUTPUT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define ENCLIO_OUTPUT_BUFFER 32768
struct enclio_output {
    int input, destination;
    unsigned char bytes[ENCLIO_OUTPUT_BUFFER];
    size_t begin, end;
    bool eof;
};
int enclio_output_open(struct enclio_output *out, int input, int destination);
/* Returns 1 when the aggregate budget is exceeded, -1 for output I/O errors. */
int enclio_output_read(struct enclio_output *out, uint64_t *total, uint64_t maximum);
int enclio_output_write(struct enclio_output *out);
void enclio_output_close(struct enclio_output *out);
/* The caller's stdin is relayed into a new pipe, never inherited as a writable
 * host file/terminal capability by the workload. */
int enclio_input_open(struct enclio_output *input, int pipe_destination);
#endif
