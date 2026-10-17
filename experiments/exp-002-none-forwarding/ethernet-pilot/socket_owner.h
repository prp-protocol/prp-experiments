#ifndef EXP002_SOCKET_OWNER_H
#define EXP002_SOCKET_OWNER_H
#include "socket_identity.h"
/* Guest-local creation in the already selected current namespace. No setns,
 * namespace creation, inherited FD adoption, traffic send, retry or module work.
 * Zeroed exclusive caller storage; caller alone may close/replace the returned
 * descriptor. Quota/phase admission and evidence reservations belong to caller.
 */
struct so_plan {
 unsigned slot,binding; /* 0/1 packet ifindex; 2/3/4 exact Netlink port id */
 uint64_t netns_dev,netns_ino,epoch,normal_end,close_end;
};
struct so_owner {
 struct so_plan plan;
 struct si_expect expected;
 uint64_t last,raw_clock,revision;
 unsigned attempted,created,identified,ready,close_started,close_attempted,closed,close_unknown,time_failed;
 unsigned configured,bound;
 int primary,secondary,fd,close_rc,close_errno;
};
/* Linux requests 262144 packet / 87381 Netlink, verified effective doubled values
 * 524288 / 174762. No FORCE options, policy modification or buffer fallback. */
int so_open(struct so_owner *,const struct so_plan *);
/* One close, original returned descriptor; a close error never permits retry.
 * Closing a socket is not remote/session cleanup or global writer settlement. */
int so_close(struct so_owner *);
#endif
