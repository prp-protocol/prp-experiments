#define _GNU_SOURCE
#include "packet_filter.h"
#include <linux/filter.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
static const struct sock_filter program[] = {
    BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x88fb, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, 0xffffffffu),
    BPF_STMT(BPF_RET | BPF_K, 0),
};
int pf_attach(int fd)
{
    struct sock_fprog p = {4, (struct sock_filter *)program};
    return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &p, sizeof(p)) ? -errno : 0;
}
int pf_lock(int fd)
{
    int one = 1;
    return setsockopt(fd, SOL_SOCKET, SO_LOCK_FILTER, &one, sizeof(one)) ? -errno : 0;
}
int pf_verify(int fd)
{
    struct sock_filter actual[4] = {0};
    socklen_t n = 4;
    if (getsockopt(fd, SOL_SOCKET, SO_GET_FILTER, actual, &n))
        return -errno;
    if (n != 4 || memcmp(actual, program, sizeof(program)))
        return -EPROTO;
    int locked = 0;
    n = sizeof(locked);
    if (getsockopt(fd, SOL_SOCKET, SO_LOCK_FILTER, &locked, &n))
        return -errno;
    return n == sizeof(locked) && locked == 1 ? 0 : -EPROTO;
}
