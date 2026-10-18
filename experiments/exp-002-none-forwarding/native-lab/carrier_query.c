#define _POSIX_C_SOURCE 200809L
#include "carrier_query.h"
#ifdef M1_QUERY
#include "m1_query.h"
#include "control_capture.h"
#include "peer_path.h"
#include "paired_query.h"
#include "route_query.h"
#endif
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <time.h>
static uint64_t clock_now(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) || t.tv_sec < 0 || t.tv_nsec < 0 ||
        t.tv_nsec >= 1000000000)
        return UINT64_MAX;
    return (uint64_t)t.tv_sec * 1000000000 + (uint64_t)t.tv_nsec;
}
int cq_run(struct rp_pool *pool, struct so_owner *owner, uint16_t family, uint32_t *seq,
           unsigned first, unsigned second, struct nq_store *store
#ifdef M1_QUERY
           ,
           uint16_t session_family, struct mq_identity *identity,
           struct mq_identity *second_identity, struct so_owner *packet_owners,
           const struct pair_plan *pair
#endif
)
{
    struct rp_handle tickets[13] = {{0}};
    struct rn_port ports[13] = {0};
    struct nt_context contexts[13];
    const unsigned commands[13] = {1, 60, 60, 62, 62, 75, 76, 76, 76, 76, 61, 61, 2},
                   indices[13] = {0, first, second, first, second, 0, 0, 0, 0, 0, second, first, 0};
    struct nt_budget budget = {1024, sizeof(struct nt_ledger), 4, 1000000};
    int primary = 0, secondary = 0;
    unsigned emitted = 0, possible[3] = {0};
    uint64_t wait_before = 0, wait_after = 0;
    int wait_rc = 0;
    uint64_t hold_before = 0, hold_after = 0;
    int hold_rc = 0;
    if (!pool || !owner || !owner->ready || owner->closed || owner->primary || !seq ||
        *seq > UINT32_MAX - 13 || family < 16 || !first || !second || first == second)
        primary = -EINVAL;
    for (unsigned i = 0; i < 13 && !primary; i++) {
        contexts[i] = (struct nt_context){owner->expected.ino,
                                          owner->plan.epoch,
                                          owner->plan.netns_ino,
                                          i < 10 ? pool->normal_end : pool->close_end,
                                          ++*seq,
                                          owner->plan.binding,
                                          family};
        if (!rp_reserve(pool, i >= 10, &budget, &tickets[i]) ||
            !rn_init(&ports[i], pool, &tickets[i], owner->fd, owner->expected.dev,
                     owner->expected.ino, &contexts[i], &budget))
            primary = -ENOBUFS;
    }
    printf("{\"operations\":[");
    for (unsigned i = 0; i < 13; i++) {
        if (i == 10 && !primary) {
            /* Successful local observation does not finish the peer's normal phase.
    * Keep owned links until our ORIGINAL normal boundary, not a new timer.
    * This is bounded retention, not a cross-VM barrier or completion promise. */
            hold_before = clock_now();
            if (hold_before < pool->normal_end) {
                uint64_t left = pool->normal_end - hold_before;
                hold_rc = poll(NULL, 0, (int)(left / 1000000 + (left % 1000000 != 0)));
            }
            hold_after = clock_now();
            if (hold_rc || hold_after < hold_before || hold_after >= pool->close_end)
                primary = -ETIMEDOUT;
        }
        if (i < 10 && primary)
            continue;
        if (i >= 10 && !possible[i == 10 ? 2 : i == 11 ? 1 : 0])
            continue;
        if (!tickets[i].pool) {
            if (!secondary)
                secondary = -ENOBUFS;
            continue;
        }
        if (i == 3) {
            /* One bounded observation window, not a causal barrier or retry loop.
    * Source default PED interval is10s; absence afterwards remains INCOMPLETE. */
            wait_before = clock_now();
            if (wait_before >= pool->normal_end ||
                pool->normal_end - wait_before <= 11000000000ULL) {
                primary = -ETIMEDOUT;
                continue;
            }
            wait_rc = poll(NULL, 0, 11000);
            wait_after = clock_now();
            if (wait_rc || wait_after < wait_before || wait_after >= pool->normal_end) {
                primary = -ETIMEDOUT;
                continue;
            }
        }
        struct nt_carrier plan = {commands[i], indices[i], 2};
        struct nt_stream io = rn_stream(&ports[i]);
        int rc = (i >= 6 && i < 10) ? rp_member_context(tickets[i], tickets[5], &contexts[i],
                                                        (i - 6) / 2, 1 + ((i - 6) % 2), &io)
                                    : rp_carrier(tickets[i], &contexts[i], &plan, &io);
        struct rp_ticket *t = rp_get(tickets[i]);
        if (i < 3)
            possible[i] = t->socket_fact.possible;
        if (!rp_encode(tickets[i], NULL) && !rc)
            rc = -EBADMSG;
        if (emitted++)
            putchar(',');
        printf(
            "{\"ordinal\":%u,\"command\":%u,\"ifindex\":%u,\"rc\":%d,\"records\":%u,\"receipt\":\"",
            i, commands[i], indices[i], rc, t->transaction.carrier_records);
        for (size_t j = 0; j < t->length; j++)
            printf("%02x", t->receipt[j]);
        printf("\"");
#ifdef M1_QUERY
        if (i == 9 && !rc) {
            struct pp_path paths[2] = {0};
            int mr = pp_select(&paths[0], tickets[5], &tickets[6], first);
            if (!mr && pair && pair->links == 2)
                mr = pp_select(&paths[1], tickets[5], &tickets[6], second);
            if (!mr)
                mr = pair && pair->links == 2 ? pp_retire_list(paths, store)
                                              : pp_retire(&paths[0], store);
            printf(
                ",\"path_ifindex\":%u,\"path_index\":%u,\"retired_context_records\":%u,\"path_rc\":%d",
                first, paths[0].index, paths[0].retired, mr);
            if (!mr) {
                if (pair && pair->links == 2) {
                    printf(",\"paired_route\":[");
                    mr = rq_run(pool, owner, session_family, seq, paths, store, identity,
                                second_identity, packet_owners, pair);
                    putchar(']');
                } else {
                    printf(pair ? ",\"paired_handshake\":" : ",\"m1\":");
                    mr = pair ? pq_run(pool, owner, session_family, seq, &paths[0], store, identity,
                                       packet_owners, pair)
                              : mq_run(pool, owner, session_family, seq, paths[0].tx, store,
                                       identity);
                }
            }
            if (mr && !primary)
                primary = mr;
            if (packet_owners && !primary && !pair) {
                printf(",\"control_capture\":");
                int cr = nc_run(pool, packet_owners, store);
                if (cr)
                    primary = cr;
            }
        }
#endif
        printf("}");
        if (rc) {
            if (!primary)
                primary = rc;
            else if (!secondary)
                secondary = rc;
        }
        if (i == 5 && !rc && t->transaction.carrier_records != 2) {
            primary = -ENODATA;
        }
        /* LIST is a live source for all four CTX queries. Retire only afterwards.
   * Current CTX source tickets stay live through this qualification phase;
   * a future expectation consumer must run before their retirement. */
        if (store && i != 5 && !(i >= 6 && i < 10) && !nq_archive(store, tickets[i])) {
            if (!primary)
                primary = -EIO;
            else if (!secondary)
                secondary = -EIO;
        }
        if (store && i == 9) {
            for (unsigned j = 5; j <= 9; j++)
                if (rp_get(tickets[j]) && !nq_archive(store, tickets[j])) {
                    if (!primary)
                        primary = -EIO;
                    else if (!secondary)
                        secondary = -EIO;
                }
        }
    }
    if (store)
        for (unsigned j = 0; j < 13; j++) {
            struct rp_ticket *left = rp_get(tickets[j]);
            if (left && left->ran && !left->persist_attempted && !nq_archive(store, tickets[j])) {
                if (!primary)
                    primary = -EIO;
                else if (!secondary)
                    secondary = -EIO;
            }
        }
    printf(
        "],\"wait_before\":%llu,\"wait_after\":%llu,\"wait_rc\":%d,\"hold_before\":%llu,\"hold_after\":%llu,\"hold_rc\":%d,\"primary\":%d,\"secondary\":%d}",
        (unsigned long long)wait_before, (unsigned long long)wait_after, wait_rc,
        (unsigned long long)hold_before, (unsigned long long)hold_after, hold_rc, primary,
        secondary);
    return primary ? primary : secondary;
}
