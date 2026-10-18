#define _GNU_SOURCE
#include "socket_identity.h"
#ifdef EXP002_PRP_CAPTURE
#include "packet_filter.h"
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/netlink.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
static int failure(struct si_set *s, struct si_observed *o, int e)
{
    if (o && !o->error)
        o->error = e;
    if (!s->primary)
        s->primary = e;
    s->complete = 0;
    return s->primary;
}
static int option(struct si_observed *o, int fd, int name, int *value, unsigned bit)
{
    socklen_t n = sizeof(*value);
    int rc = getsockopt(fd, SOL_SOCKET, name, value, &n);
    if (rc)
        return -errno;
    o->options_seen |= bit;
    return n == sizeof(*value) ? 0 : -EPROTO;
}
static int selected(enum si_domain domain, unsigned i)
{
    return domain == SI_LEGACY_LOCAL || (domain == SI_ENDPOINT_VM && i != 3) ||
           (domain == SI_DUT_VM && i == 3);
}
int si_inspect_domain(struct si_set *s, const struct si_expect e[5], enum si_domain domain)
{
    if (!s)
        return -EINVAL;
    if (s->attempted)
        return failure(s, NULL, -EALREADY);
    s->attempted = 1;
    if (!e || (domain != SI_LEGACY_LOCAL && domain != SI_ENDPOINT_VM && domain != SI_DUT_VM))
        return failure(s, NULL, -EINVAL);
    s->domain = (unsigned)domain;
    /* Reject incomplete/duplicate capabilities before any metadata call. Numeric
  * identity is independently supplied expectation, not acquired ownership. */
    for (unsigned i = 0; i < 5; i++) {
        if (!selected(domain, i))
            continue;
        if (e[i].fd < 0 || !e[i].ino || !e[i].binding || (i < 2 && e[i].binding > 2147483647u))
            return failure(s, NULL, -EINVAL);
        for (unsigned j = 0; j < i; j++)
            if (selected(domain, j) &&
                (e[i].fd == e[j].fd || (e[i].dev == e[j].dev && e[i].ino == e[j].ino)))
                return failure(s, NULL, -EINVAL);
    }
    for (unsigned i = 0; i < 5; i++) {
        if (!selected(domain, i))
            continue;
        struct si_observed *o = &s->sockets[i];
        struct stat before, after;
        s->inspected++;
        s->mask |= 1u << i;
        o->fd = e[i].fd;
        if (fstat(e[i].fd, &before))
            return failure(s, o, -errno);
        o->dev = before.st_dev;
        o->ino = before.st_ino;
        if (!S_ISSOCK(before.st_mode) || o->dev != e[i].dev || o->ino != e[i].ino)
            return failure(s, o, -ESTALE);
        o->flags = fcntl(e[i].fd, F_GETFL);
        if (o->flags < 0)
            return failure(s, o, -errno);
        if (!(o->flags & O_NONBLOCK))
            return failure(s, o, -EINVAL);
        const int names[5] = {SO_DOMAIN, SO_TYPE, SO_PROTOCOL, SO_RCVBUF, SO_SNDBUF};
        int *values[5] = {&o->domain, &o->type, &o->protocol, &o->receive_bytes, &o->send_bytes};
        for (unsigned k = 0; k < 5; k++) {
            int rc = option(o, e[i].fd, names[k], values[k], 1u << k);
            if (rc)
                return failure(s, o, rc);
        }
        /* AF_PACKET stores its effective EtherType in packet_sock.num, exposed by
   * sockaddr_ll below. Generic SO_PROTOCOL is sk_protocol (zero), not EtherType. */
        if (o->domain != (i < 2 ? AF_PACKET : AF_NETLINK) || o->type != SOCK_RAW ||
            o->protocol != (i < 2 ? 0 : NETLINK_GENERIC))
            return failure(s, o, -EPROTO);
        int ceiling = i < 2 ? 524288 : 174762;
        /* Selected effective values, no silent halving or rounding. A valid target
   * with different attainable values requires disposition, not assumed fit. */
        if (o->receive_bytes != ceiling || o->send_bytes != ceiling)
            return failure(s, o, -ENOBUFS);
        s->effective_sum += (uint64_t)o->receive_bytes + (uint64_t)o->send_bytes;
        union {
            struct sockaddr_ll packet;
            struct sockaddr_nl netlink;
        } address;
        memset(&address, 0, sizeof(address));
        socklen_t n = sizeof(address);
        if (getsockname(e[i].fd, (struct sockaddr *)&address, &n))
            return failure(s, o, -errno);
        o->address_length = n;
        memcpy(o->address, &address, sizeof(address));
        if (i < 2) {
            o->binding = (unsigned)address.packet.sll_ifindex;
            if (n != offsetof(struct sockaddr_ll, sll_addr) + ETH_ALEN ||
                address.packet.sll_halen != ETH_ALEN || address.packet.sll_family != AF_PACKET ||
                address.packet.sll_protocol != htons(ETH_P_ALL) || o->binding != e[i].binding)
                return failure(s, o, -EPROTO);
        } else {
            o->binding = address.netlink.nl_pid;
            o->groups = address.netlink.nl_groups;
            if (n != sizeof(struct sockaddr_nl) || address.netlink.nl_family != AF_NETLINK ||
                o->groups || o->binding != e[i].binding)
                return failure(s, o, -EPROTO);
        }
#ifdef EXP002_PRP_CAPTURE
        if (i < 2) {
            int rc = pf_verify(e[i].fd);
            if (rc)
                return failure(s, o, rc);
        }
#endif
        if (fstat(e[i].fd, &after))
            return failure(s, o, -errno);
        o->final_dev = after.st_dev;
        o->final_ino = after.st_ino;
        if (!S_ISSOCK(after.st_mode) || o->final_dev != o->dev || o->final_ino != o->ino)
            return failure(s, o, -ESTALE);
    }
    if (s->primary)
        return s->primary;
    uint64_t expected = domain == SI_ENDPOINT_VM ? 2796200u
                        : domain == SI_DUT_VM    ? 349524u
                                                 : 3145724u;
    if (s->effective_sum != expected || s->effective_sum > 3145728)
        return failure(s, NULL, -ENOBUFS);
    s->complete = 1;
    return 0;
}
int si_inspect(struct si_set *s, const struct si_expect e[5])
{
    return si_inspect_domain(s, e, SI_LEGACY_LOCAL);
}
int si_budget_join(const struct si_set *a, const struct si_set *b, uint64_t *sum)
{
    if (!a || !b || a == b || !sum || !a->attempted || !b->attempted || !a->complete ||
        !b->complete || a->primary || b->primary || a->domain != SI_ENDPOINT_VM || a->mask != 23 ||
        a->inspected != 4 || a->effective_sum != 2796200 || b->domain != SI_DUT_VM ||
        b->mask != 8 || b->inspected != 1 || b->effective_sum != 349524)
        return -EINVAL;
    *sum = a->effective_sum + b->effective_sum;
    return 0;
}
