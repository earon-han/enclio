#ifndef ENCLIO_H
#define ENCLIO_H
#include <stddef.h>
#define ENCLIO_VERSION "0.2.0-preview.1"
#define ENCLIO_PROXY_PORT 18080
#define ENCLIO_MAX_HOSTS 64
#define ENCLIO_MAX_ENV 64
#define ENCLIO_SECCOMP_RULE_MAX 64
struct enclio_seccomp_rule {
    int syscall_nr;
    unsigned action;
};
/* NAME=allow|deny|kill|errno:N; native syscalls only. Returns 0 or -1. */
int enclio_seccomp_rule_parse(const char *text, struct enclio_seccomp_rule *rule);
/* Rules affect the target only; last duplicate wins, overriding all default
 * syscall/argument rules for that syscall. Existing outer filters still apply. */
int enclio_install_seccomp_rules(int strict, const struct enclio_seccomp_rule *rules, size_t count);
int enclio_install_seccomp(int strict);
int enclio_internal_main(int argc, char **argv);
#endif
