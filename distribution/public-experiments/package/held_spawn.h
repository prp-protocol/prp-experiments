#ifndef EXP002_HELD_SPAWN_H
#define EXP002_HELD_SPAWN_H
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/* Exclusive, single-threaded parent/reaper; no callback or target discovery. */
struct hs_plan {
    int executable;             /* already pinned open ELF descriptor, >=4 */
    int streams[4];              /* stdin/stdout/stderr/private QMP sources */
    char *const *argv;
    char *const *envp;
    int64_t launch_end_ns;       /* original HOST phase end */
    unsigned network_count;     /* 0 (legacy) or exactly 4: two TAP/vhost pairs */
    int network[4];             /* sources map to child4..7; caller-owned */
};
struct hs_child {
    pid_t pid;                  /* original fork return; never reconstructed */
    int pidfd, gate, exec_error;
    int started, owned, retired, release_attempted, release_possible;
    int primary, secondary;
    ssize_t release_count;
    int64_t last_ns, launch_end_ns;
};
void hs_init(struct hs_child *child);
/* On error, child may still own a held process. Caller MUST retain this object. */
int hs_create(struct hs_child *child, const struct hs_plan *plan);
int hs_release(struct hs_child *child, int64_t original_launch_end_ns);
/* One close only. EOF suppresses exec only before complete token acceptance. */
int hs_cancel_gate(struct hs_child *child);
void hs_retire(struct hs_child *child);
/* Exact structure association for consumer FFI; SIZE_MAX means unsupported. */
size_t hs_layout(unsigned structure, unsigned field);
#endif
