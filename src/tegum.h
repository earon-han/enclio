#ifndef TEGUM_H
#define TEGUM_H
#define TG_VERSION "0.1.0-preview.1"
#define TG_PROXY_PORT 18080
#define TG_MAX_HOSTS 64
#define TG_MAX_ENV 64
int tg_install_seccomp(void);
int tg_internal_main(int argc, char **argv);
#endif
