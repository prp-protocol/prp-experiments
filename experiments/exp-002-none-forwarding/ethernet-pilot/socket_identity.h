#ifndef EXP002_SOCKET_IDENTITY_H
#define EXP002_SOCKET_IDENTITY_H
#include <stdint.h>
#include <sys/types.h>
/* Borrowed exclusive descriptors. Does not create, configure or close sockets.
 * This local metadata check cannot prove namespace origin, exclusive writers,
 * future FD continuity, native health or physical memory usage. */
struct si_expect {
    int fd;
    uint64_t dev, ino;
    unsigned binding;
};
struct si_observed {
    int fd;
    uint64_t dev, ino, final_dev, final_ino;
    int flags, domain, type, protocol, receive_bytes, send_bytes, error;
    unsigned binding, groups, address_length, options_seen;
    unsigned char address[32];
};
enum si_domain { SI_LEGACY_LOCAL = 0, SI_ENDPOINT_VM = 1, SI_DUT_VM = 2 };
struct si_set {
    int attempted, complete, primary;
    unsigned inspected, domain, mask;
    uint64_t effective_sum;
    struct si_observed sockets[5];
};
/* Exact order: capture U, capture E, control U, control D, control E.
 * Caller must reserve evidence and check original deadlines around this finite
 * inspection. Calls can block/finish late; this function supplies no timeout. */
int si_inspect(struct si_set *, const struct si_expect[5]);
/* Global slots stay U capture,E capture,U control,D control,E control.
 * Endpoint inspects slots0/1/2/4 locally; DUT inspects only slot3 locally.
 * Unselected expectations are not inspected or interpreted as local FDs. */
int si_inspect_domain(struct si_set *, const struct si_expect[5], enum si_domain);
/* Arithmetic join of separately authenticated observations, not authentication
 * of their origin. Never compares dev/inode/FD across VM namespaces. */
int si_budget_join(const struct si_set *, const struct si_set *, uint64_t *);
#endif
