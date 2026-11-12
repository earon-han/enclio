/* Compile only with ENCLIO_PROXY_TESTING. Production has no fuzz entry point. */
#include "../src/proxy.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const corpus[] = {
    "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "HEAD http://example.com:8080/?q=x HTTP/1.1\r\nHost: example.com:8080\r\n\r\n",
    "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 12\r\n\r\n",
    "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
    "CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com:8443\r\n\r\n",
    "OPTIONS http://example.com HTTP/1.0\r\n\r\n",
    "GET http://example.com?x=y HTTP/1.1\r\nHost: example.com\r\nConnection: close, x-hide\r\nX-Hide: secret\r\n\r\n"
};
static uint32_t random_state = 0x5a17c3e9U;
static uint32_t next_random(void) {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)enclio_proxy_fuzz_request(data, size);
    return 0;
}
#ifndef ENCLIO_LIBFUZZER
int main(int argc, char **argv) {
    unsigned long iterations = 250000;
    if (argc == 2) {
        char *end;
        iterations = strtoul(argv[1], &end, 10);
        if (!*argv[1] || *end || iterations > 100000000UL) return 2;
    }
    size_t corpus_count = sizeof(corpus)/sizeof(corpus[0]);
    for (size_t i = 0; i < corpus_count; ++i)
        assert(enclio_proxy_fuzz_request((const unsigned char *)corpus[i], strlen(corpus[i])) == 0);
    const char *invalid[] = {
        "GET http://127.1/ HTTP/1.1\r\nHost: 127.1\r\n\r\n",
        "GET http://example.com/ HTTP/1.1\r\nHost: other.example\r\n\r\n",
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
        "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 67108865\r\n\r\n",
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: x,\r\n\r\n",
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\n\r\n"
    };
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i)
        assert(enclio_proxy_fuzz_request((const unsigned char *)invalid[i], strlen(invalid[i])) < 0);
    unsigned long accepted = 0;
    for (unsigned long i = 0; i < iterations; ++i) {
        unsigned char bytes[8192]; size_t size;
        if (i % 3) {
            const char *seed = corpus[next_random() % corpus_count];
            size = strlen(seed); memcpy(bytes, seed, size);
            unsigned mutations = 1 + next_random()%16;
            for (unsigned j = 0; j < mutations; ++j) {
                unsigned change = next_random()%4;
                if (change == 0 && size) --size;
                else if (change == 1 && size < sizeof(bytes)) bytes[size++] = (unsigned char)next_random();
                else if (size) bytes[next_random()%size] = (unsigned char)next_random();
            }
        } else {
            size = next_random()%sizeof(bytes);
            for (size_t j = 0; j < size; ++j) bytes[j] = (unsigned char)next_random();
        }
        if (enclio_proxy_fuzz_request(bytes, size) == 0) ++accepted;
    }
    printf("{\"iterations\":%lu,\"accepted\":%lu,\"rejected\":%lu,\"seed\":1511506921,\"status\":\"PASS\"}\n",
           iterations, accepted, iterations-accepted);
    return 0;
}
#endif
