#define _GNU_SOURCE
#include "control_capture.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
static uint64_t nc_clock(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) || t.tv_sec < 0 || t.tv_nsec < 0 ||
        t.tv_nsec >= 1000000000)
        return UINT64_MAX;
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}
static int valid(const struct so_owner *o)
{
    struct stat s;
    return o->ready && !o->closed && !o->primary && o->fd == o->expected.fd &&
           o->plan.binding == o->expected.binding && !fstat(o->fd, &s) && S_ISSOCK(s.st_mode) &&
           (uint64_t)s.st_dev == o->expected.dev && (uint64_t)s.st_ino == o->expected.ino;
}
static int receive_m1(struct rp_pool *p, struct so_owner owners[2], struct nq_store *store,
                      const struct cm_path *path, const struct cm_direct_path *direct,
                      struct sb_backend *hash, struct cm_m1 *out, int quiet)
{
    struct cm_direct_path direct_selected = {0};
    if (direct)
        direct_selected = *direct;
    struct cm_path selected = {0};
    struct cm_m1 admitted = {0};
    if (path)
        selected = *path;
    if (out)
        memset(out, 0, sizeof(*out));
    struct rp_handle direct_parent = {0};
    uint64_t parent_revision =
        direct && direct_selected.parent ? direct_selected.parent->revision : 0;
    int primary = 0;
    unsigned count = 0, prp = 0;
    size_t retained = 0;
    uint64_t last = nc_clock(), silent_since = last;
    int silent = 0;
    if (!!path != !!out || !p || !store || !p->initialized || p->primary || last >= p->normal_end ||
        !valid(&owners[0]) || !valid(&owners[1]))
        primary = -EINVAL;
    if (direct && sf_active_ticket(direct_selected.parent, &direct_parent))
        primary = SA_IDENTITY;
    printf("{\"schema\":\"EXP002-CONTROL-CAPTURE-1\",\"records\":[");
    /* At most32 observations and8192 retained bytes in this smaller qualification.
  * These are refusals inside pool3, not new budgets or packet filters. */
    while (!primary && count < 32 && retained <= 8192 - 1984) {
        uint64_t before = nc_clock();
        if (before < last || before >= p->normal_end) {
            primary = -ETIMEDOUT;
            break;
        }
        last = before;
        struct pollfd f[2] = {{owners[0].fd, POLLIN, 0}, {owners[1].fd, POLLIN, 0}};
        uint64_t left = p->normal_end - before;
        int ms = (int)(left / 1000000);
        if (ms > (quiet ? 150 : 200))
            ms = quiet ? 150 : 200;
        if (ms < 1)
            ms = 1;
        int ready = poll(f, 2, ms), poll_errno = errno;
        uint64_t after = nc_clock();
        if (after < last || after >= p->normal_end) {
            primary = prp ? 0 : -ETIMEDOUT;
            break;
        }
        last = after;
        if (ready < 0) {
            primary = -poll_errno;
            break;
        }
        if (!ready) {
            if (quiet && after >= silent_since + 150000000ULL) {
                silent = 1;
                break;
            }
            continue;
        }
        silent_since = after;
        for (unsigned k = 0; k < 2 && !primary; k++) {
            if (!f[k].revents)
                continue;
            if (f[k].revents != POLLIN || count >= 32 || retained > 8192 - 1984 ||
                !valid(&owners[k])) {
                primary = -ENOBUFS;
                break;
            }
            struct rp_handle h = {0};
            if (!rp_reserve_capture(p, 0, &h)) {
                primary = -ENOBUFS;
                break;
            }
            struct rp_ticket *t = rp_get(h);
            t->ran = t->busy = 1;
            t->capture_not_before = last;
            t->capture_end = p->normal_end;
            t->transaction.before = nc_clock();
            if (t->transaction.before < last || t->transaction.before >= p->normal_end) {
                t->primary = primary = -ETIMEDOUT;
                t->busy = 0;
                nq_archive(store, h);
                break;
            }
            struct rp_capture_raw *r = &t->capture_raw;
            r->before = t->transaction.before;
            r->context.netns = owners[k].plan.netns_ino;
            r->context.epoch = owners[k].plan.epoch;
            struct sockaddr_ll a = {0};
            struct iovec v = {r->bytes, sizeof(r->bytes)};
            struct msghdr m = {
                .msg_name = &a, .msg_namelen = sizeof(a), .msg_iov = &v, .msg_iovlen = 1};
            t->capture_attempted = 1;
            ssize_t n = recvmsg(owners[k].fd, &m, MSG_DONTWAIT | MSG_TRUNC);
            int e = errno;
            r->after = t->transaction.after = nc_clock();
            r->length = n > 0 ? (size_t)n : 0;
            r->rc = n < 0 ? -e : 0;
            r->truncated = !!(m.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
            r->context.ifindex = a.sll_ifindex;
            r->context.direction = a.sll_pkttype == PACKET_OUTGOING ? 1 : 2;
            if (n >= 14) {
                memcpy(r->context.destination, r->bytes, 6);
                memcpy(r->context.source, r->bytes + 6, 6);
            }
            if (r->rc)
                primary = r->rc;
            else if (r->after < r->before || r->after >= p->normal_end)
                primary = -ETIMEDOUT;
            else if (!valid(&owners[k]) || m.msg_namelen != sizeof(a) ||
                     a.sll_family != AF_PACKET || a.sll_ifindex != (int)owners[k].plan.binding ||
                     n < 14 || n > 1984 || r->truncated)
                primary = -EPROTO;
            /* No capture accepted flag: this is raw observation custody, not an oracle. */
            t->primary = primary;
            t->busy = 0;
            last = r->after;
            unsigned candidate = !primary && a.sll_pkttype != PACKET_OUTGOING &&
                                 n == (direct ? 198 : 148) && r->bytes[12] == 0x88 &&
                                 r->bytes[13] == 0xfb && r->bytes[14] == (direct ? 0 : 2);
            if (candidate && path) {
                primary = prp      ? SA_REPEAT
                          : direct ? cm_admit_direct(h, &direct_selected, last, hash, &admitted)
                                   : cm_admit(h, &selected, last, &admitted);
                if (primary)
                    t->primary = primary;
            }
            if (count++)
                putchar(',');
            int enc = rp_encode(h, NULL);
            printf(
                "{\"slot\":%u,\"fd\":%d,\"dev\":%llu,\"ino\":%llu,\"packet_type\":%u,\"protocol\":%u,\"ifindex\":%d,\"before\":%llu,\"after\":%llu,\"length\":%zu,\"rc\":%d,\"flags\":%d,\"frame\":\"",
                k, owners[k].fd, (unsigned long long)owners[k].expected.dev,
                (unsigned long long)owners[k].expected.ino, a.sll_pkttype, (unsigned)a.sll_protocol,
                a.sll_ifindex, (unsigned long long)r->before, (unsigned long long)r->after,
                r->length, primary, m.msg_flags);
            size_t kept = r->length > 1984 ? 1984 : r->length;
            for (size_t j = 0; j < kept; j++)
                printf("%02x", r->bytes[j]);
            printf("\",\"receipt\":\"");
            for (size_t j = 0; j < t->length; j++)
                printf("%02x", t->receipt[j]);
            printf("\"}");
            retained += kept;
            if (!primary && candidate)
                prp++;
            if ((!enc || !nq_archive(store, h)) && !primary)
                primary = -EIO;
        }
        if (quiet)
            silent_since = last;
        if (prp && !quiet)
            break; /* Qualification ends after one candidate; oracle is independent. */
    }
    if (!primary && !(quiet ? (silent != 0) : (prp != 0)))
        primary = -ENODATA;
    if (!primary && out) {
        uint64_t completed = nc_clock();
        struct rp_handle current = {0};
        if (direct &&
            (direct_selected.parent->revision != parent_revision ||
             sf_active_ticket(direct_selected.parent, &current) ||
             current.pool != direct_parent.pool || current.id != direct_parent.id ||
             current.slot != direct_parent.slot || current.generation != direct_parent.generation))
            primary = SA_IDENTITY;
        if (p->primary)
            primary = p->primary;
        else if (completed < last || completed >= selected.end)
            primary = -ETIMEDOUT;
        else if (!primary) {
            admitted.remote.not_before = completed;
            *out = admitted;
        }
    }
    printf(
        "],\"count\":%u,\"retained\":%zu,\"candidate_frames\":%u,\"primary\":%d,\"remote_acceptance_proven\":false}",
        count, retained, prp, primary);
    return primary;
}

int nc_receive_m1(struct rp_pool *p, struct so_owner o[2], struct nq_store *s,
                  const struct cm_path *path, struct cm_m1 *out)
{
    return receive_m1(p, o, s, path, NULL, NULL, out, 0);
}
int nc_receive_direct_m1(struct rp_pool *p, struct so_owner o[2], struct nq_store *s,
                         const struct cm_direct_path *path, struct sb_backend *hash,
                         struct cm_m1 *out)
{
    if (!path || !hash || !out)
        return SA_REFUSED;
    return receive_m1(p, o, s, &path->path, path, hash, out, 0);
}
int nc_run(struct rp_pool *p, struct so_owner o[2], struct nq_store *s)
{
    return nc_receive_m1(p, o, s, NULL, NULL);
}

int nc_quiet(struct rp_pool *p, struct so_owner o[2], struct nq_store *s)
{
    return receive_m1(p, o, s, NULL, NULL, NULL, NULL, 1);
}
