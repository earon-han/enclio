#define _GNU_SOURCE
/* Exercise the private receiver in-process so FD leaks are observable. */
#include "../src/proxy.c"
#include <assert.h>
#include <dirent.h>

static int descriptor_count(void)
{
    DIR *d = opendir("/proc/self/fd");
    assert(d);
    int count = 0;
    while (readdir(d)) count++;
    closedir(d);
    return count;
}
static int listener(unsigned ip)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {.sin_family=AF_INET, .sin_port=htons(ENCLIO_PROXY_PORT),
                           .sin_addr.s_addr=htonl(ip)};
    assert(fd >= 0 && bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0 && listen(fd, 1) == 0);
    return fd;
}
static void transfer(int channel, const char *tag, size_t size, int fd, unsigned count)
{
    int descriptors[32];
    assert(count <= 32);
    for (unsigned i=0; i<count; i++) descriptors[i] = fd;
    char ancillary[CMSG_SPACE(sizeof(descriptors))];
    memset(ancillary, 0, sizeof(ancillary));
    struct iovec iov = {.iov_base=(void *)tag, .iov_len=size};
    struct msghdr msg = {.msg_iov=&iov, .msg_iovlen=1};
    if (count) {
        msg.msg_control=ancillary; msg.msg_controllen=CMSG_SPACE(count*sizeof(int));
        struct cmsghdr *c=CMSG_FIRSTHDR(&msg);
        c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS;
        c->cmsg_len=CMSG_LEN(count*sizeof(int));
        memcpy(CMSG_DATA(c), descriptors, count*sizeof(int));
    }
    assert(sendmsg(channel,&msg,MSG_NOSIGNAL)==(ssize_t)size);
}
static void rejected(const char *tag,size_t length,int fd,unsigned count)
{
    int channel[2];
    assert(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,channel)==0);
    int before=descriptor_count();
    transfer(channel[0],tag,length,fd,count);
    assert(receive_listener(channel[1],100) < 0);
    assert(descriptor_count()==before);
    close(channel[0]); close(channel[1]);
}
int main(void)
{
    signal(SIGPIPE,SIG_IGN);
    int channel[2];
    assert(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,channel)==0);
    int fd=listener(INADDR_LOOPBACK), before=descriptor_count();
    transfer(channel[0],"EL01",4,fd,1);
    int received=receive_listener(channel[1],100);
    assert(received>=0 && (fcntl(received,F_GETFD)&FD_CLOEXEC));
    close(received);
    assert(descriptor_count()==before);
    rejected("EL01",4,fd,0);
    rejected("BAD!",4,fd,1);
    rejected("EL01extra",9,fd,1);
    rejected("EL01",4,fd,2);
    rejected("EL01",4,fd,32); /* ancillary truncation must close delivered FDs */
    close(fd);
    int wrong = socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,IPPROTO_TCP);
    struct sockaddr_in ephemeral = {.sin_family=AF_INET, .sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(wrong >= 0 && bind(wrong,(struct sockaddr *)&ephemeral,sizeof(ephemeral))==0 && listen(wrong,1)==0);
    rejected("EL01",4,wrong,1); close(wrong); /* correct IP, wrong port */
    fd=listener(INADDR_ANY);
    rejected("EL01",4,fd,1); close(fd);
    fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    assert(fd>=0); rejected("EL01",4,fd,1); close(fd);
    fd=open("/dev/null",O_RDONLY|O_CLOEXEC);
    assert(fd>=0); rejected("EL01",4,fd,1); close(fd);
    fd=open("/dev/null",O_RDONLY|O_CLOEXEC);
    assert(fd>=0); before=descriptor_count();
    transfer(channel[0],"EA01",4,fd,1);
    assert(receive_control(channel[1],"EA01",0,monotonic_ms()+100)<0);
    assert(descriptor_count()==before); close(fd);
    assert(receive_listener(channel[1],20)<0); /* deadline with open idle peer */
    close(channel[0]);
    assert(receive_listener(channel[1],100)<0); /* EOF */
    close(channel[1]);
    for(int positive=0;positive<2;positive++) {
        assert(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,channel)==0);
        pid_t child=fork(); assert(child>=0);
        if(!child) {
            close(channel[0]);
            int accepted=receive_listener(channel[1],1000);
            if(accepted<0) _exit(2);
            const char *ack=positive ? "EA01" : "BAD!";
            int ok=send(channel[1],ack,4,MSG_NOSIGNAL)==4;
            close(accepted); close(channel[1]); _exit(ok?0:3);
        }
        close(channel[1]);
        before=descriptor_count();
        int rc=enclio_proxy_send_listener(channel[0],ENCLIO_PROXY_PORT,1000);
        assert(positive ? rc==0 : rc<0);
        assert(descriptor_count()==before);
        close(channel[0]); int status; assert(waitpid(child,&status,0)==child);
        assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);
    }
    assert(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,channel)==0);
    before=descriptor_count();
    assert(enclio_proxy_send_listener(channel[0],ENCLIO_PROXY_PORT,20)<0);
    /* Receiver queue owns a duplicate until the channel closes. */
    close(channel[0]); close(channel[1]);
    assert(descriptor_count()==before-2);
    for(int type=SOCK_STREAM;type<=SOCK_DGRAM;type++) {
        assert(socketpair(AF_UNIX,type|SOCK_CLOEXEC,0,channel)==0);
        before=descriptor_count();
        assert(receive_listener(channel[1],20)<0);
        assert(enclio_proxy_send_listener(channel[0],ENCLIO_PROXY_PORT,20)<0);
        assert(descriptor_count()==before);
        close(channel[0]); close(channel[1]);
    }
    puts("listener handoff: PASS (valid FD/CLOEXEC, malformed/truncated messages, wrong endpoint/type, timeout/EOF, ACK, FD cleanup)");
    return 0;
}
