#ifndef TEGUM_PROXY_H
#define TEGUM_PROXY_H

#include <stddef.h>
#include <sys/socket.h>

/* Both servers run in their own supervised process; neither function returns
 * during normal service. CONNECT destinations are restricted to port 443. */
int tg_proxy_serve(const char *unix_path, const char *const *allowed_hosts,
                   size_t host_count);
int tg_relay_serve(const char *unix_path, unsigned short port);

/* Pure validation helpers, shared with the independent policy tests. */
int tg_proxy_host_valid(const char *host);
int tg_proxy_address_public(const struct sockaddr *address);

#endif
