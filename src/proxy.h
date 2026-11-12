#ifndef ENCLIO_PROXY_H
#define ENCLIO_PROXY_H

#include <stddef.h>
#include <sys/socket.h>

#define ENCLIO_NETWORK_HOST_MAX 253
#define ENCLIO_NETWORK_RULE_MAX 64
#define ENCLIO_HTTP_BODY_MAX (64ULL * 1024 * 1024)
struct enclio_network_rule {
    char host[ENCLIO_NETWORK_HOST_MAX + 1];
    unsigned short port;
};

/* default_port == 0 requires an explicit host:port. Exact DNS names only. */
int enclio_proxy_rule_parse(const char *text, struct enclio_network_rule *rule,
                           unsigned short default_port);
int enclio_proxy_serve_rules(const char *unix_path,
                            const struct enclio_network_rule *rules,
                            size_t rule_count);
/* Legacy API: each exact hostname grants TCP 443 only. */
int enclio_proxy_serve(const char *unix_path, const char *const *allowed_hosts,
                       size_t host_count);
/* Private SOCK_SEQPACKET bootstrap. Receiver owns/closes control on every path;
 * sender leaves control ownership with its caller and closes its listener copy
 * on every path. The workload must inherit neither descriptor. */
int enclio_proxy_serve_control(int control, const struct enclio_network_rule *rules,
                              size_t rule_count, unsigned timeout_ms);
int enclio_proxy_send_listener(int control, unsigned short port, unsigned timeout_ms);

int enclio_proxy_host_valid(const char *host);
int enclio_proxy_address_public(const struct sockaddr *address);
#ifdef ENCLIO_PROXY_TESTING
/* Parser-only fuzz entry point; no test policy bypass is present in production. */
int enclio_proxy_fuzz_request(const unsigned char *data, size_t size);
#endif
#endif
