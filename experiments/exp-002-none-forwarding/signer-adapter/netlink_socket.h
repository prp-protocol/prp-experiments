#ifndef EXP_NETLINK_SOCKET_H
#define EXP_NETLINK_SOCKET_H
#include "transaction.h"
/* Borrowed, exclusively owned nonblocking descriptor. Namespace and lifetime
 * provenance belong to the caller; metadata equality does not prove them. */
struct ns_port {
    /* Optional local reservation admission; never an ownership proof. */
    int (*admission)(void *);
    void *admission_arg;
    struct nt_context context;
    uint64_t operation_end; /* May only be clamped by bound transaction expiry. */
    uint64_t dev, ino, last, send_before, send_after, receive_after;
    int fd, initialized, busy, primary, secondary, possible, sent;
    unsigned calls, max_calls;
    size_t remaining, request_length;
    unsigned char request[264];
    long send_result;
    int send_errno;
};
int ns_init(struct ns_port *, int, uint64_t, uint64_t, const struct nt_context *,
            const struct nt_budget *);
struct nt_stream ns_stream(struct ns_port *);
#endif
