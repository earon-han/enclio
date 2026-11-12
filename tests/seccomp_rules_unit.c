#define _GNU_SOURCE
#include "enclio.h"
#include <assert.h>
#include <errno.h>
#include <seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static int test_child(int which, int strict)
{
    struct enclio_seccomp_rule rules[3];
    size_t count = 0;
#define RULE(text) do { assert(!enclio_seccomp_rule_parse(text, &rules[count])); count++; } while (0)
    if (which == 1) { RULE("process_vm_readv=allow"); }
    if (which == 2) { RULE("getppid=errno:42"); }
    if (which == 3) { RULE("getcpu=allow"); }
    if (which == 4) { RULE("socket=allow"); }
    if (which == 5) { RULE("getppid=kill"); }
    if (which == 6) { RULE("getppid=deny"); RULE("getppid=allow"); }
    if (which == 7) { RULE("getppid=allow"); RULE("getppid=errno:43"); }
    if (which == 8) { RULE("seccomp=deny"); RULE("prctl=deny"); }
    if (enclio_install_seccomp_rules(strict, rules, count)) return 10;
    if (which == 0 || which == 1) {
        char a = 'x', b = 0;
        struct iovec local = {.iov_base=&b,.iov_len=1}, remote = {.iov_base=&a,.iov_len=1};
        errno = 0;
        long n = syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1, 0);
        return which ? !(n == 1 && b == 'x') : !(n == -1 && errno == EPERM);
    }
    if (which == 2 || which == 7) {
        errno=0;long n=syscall(SYS_getppid);
        return !(n == -1 && errno == (which == 2 ? 42 : 43));
    }
    if (which == 3) {
        unsigned cpu, node;
        return syscall(SYS_getcpu, &cpu, &node, NULL) != 0;
    }
    if (which == 4) {
        errno=0;int fd=socket(AF_UNIX,SOCK_RAW,0);
        int e=errno;if(fd >= 0)close(fd);
        return fd < 0 && e == EPERM;
    }
    if (which == 5) { (void)syscall(SYS_getppid); return 11; }
    if (which == 6) return syscall(SYS_getppid) <= 0;
    if (which == 8) {
        errno=0;long a=syscall(SYS_seccomp,0,0,NULL);int first=errno;
        errno=0;long b=prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0);
        return !(a == -1 && first == EPERM && b == -1 && errno == EPERM);
    }
    return 12;
}
int main(void)
{
    struct enclio_seccomp_rule rule;
    const char *bad[] = {"", "read", "=allow", "read=", "read=ALLOW", "read=errno:0",
        "read=errno:4096", "read=errno:-1", "read=errno:1x", "read=errno:", "read=errno:9999999999999",
        "no_such_enclio_syscall=allow", "read=allow=deny", "1=allow", " read=allow", NULL};
    for (int i=0;bad[i];i++)assert(enclio_seccomp_rule_parse(bad[i],&rule)<0);
    assert(enclio_seccomp_rule_parse(NULL,&rule)<0);
    assert(enclio_seccomp_rule_parse("read=allow",NULL)<0);
    assert(!enclio_seccomp_rule_parse("read=errno:4095",&rule));
    assert(rule.action == SCMP_ACT_ERRNO(4095));
    rule.syscall_nr=-1;rule.action=SCMP_ACT_ALLOW;
    assert(enclio_install_seccomp_rules(1,&rule,1)<0);
    assert(enclio_install_seccomp_rules(1,NULL,1)<0);
    assert(enclio_install_seccomp_rules(1,&rule,ENCLIO_SECCOMP_RULE_MAX+1)<0);
    for(int strict=0;strict<=1;strict++)for(int which=0;which<=8;which++) {
        pid_t pid=fork();assert(pid>=0);
        if(!pid)_exit(test_child(which,strict));
        int status;assert(waitpid(pid,&status,0)==pid);
        if(which==5)assert(WIFSIGNALED(status)&&WTERMSIG(status)==SIGSYS);
        else {
            if(!WIFEXITED(status)||WEXITSTATUS(status))fprintf(stderr,"seccomp case strict=%d which=%d status=%d\n",strict,which,status);
            assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);
        }
    }
    puts("seccomp custom rules: PASS (native parse, deny/allow/errno/kill, strict admission, argument override, last wins, final-layer install)");
    return 0;
}
