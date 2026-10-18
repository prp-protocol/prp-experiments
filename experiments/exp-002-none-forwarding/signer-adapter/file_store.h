#ifndef EXP_FILE_STORE_H
#define EXP_FILE_STORE_H
#include "reservations.h"
#include <sys/types.h>
/* HOST-owned directory only. Inventory is bounded independently in pool13.
 * No crash/power-loss or hostile-writer isolation guarantee. */
struct rf_entry {
    uint64_t id, generation;
    dev_t dev;
    ino_t ino;
    size_t written, read;
    int primary, secondary, settled, inventory_opened, inventory_settled;
    char name[64];
};
struct rf_store {
    int initialized, dirfd, busy, primary;
    unsigned count;
    uint64_t end, last, revision, seen, ticket_revision;
    struct rp_handle current;
    struct rp_pool *pool;
    uint64_t (*clock)(void *);
    void *arg;
    struct rf_entry entries[256];
};
int rf_open(struct rf_store *, struct rp_pool *, const char *, uint64_t, uint64_t (*)(void *),
            void *);
struct rp_store rf_operations(struct rf_store *);
int rf_close(struct rf_store *);
#endif
