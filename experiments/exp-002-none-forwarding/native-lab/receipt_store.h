#ifndef EXP_NATIVE_RECEIPT_STORE_H
#define EXP_NATIVE_RECEIPT_STORE_H
#include "file_store.h"
/* Borrowed dependency handles remain live. This is not a transport retry. */
struct nq_store {
    struct rf_store files;
    unsigned archived, failed;
};
int nq_open(struct nq_store *, struct rp_pool *, const char *, uint64_t, uint64_t (*)(void *),
            void *);
int nq_archive_before(struct nq_store *, struct rp_handle, uint64_t);
int nq_archive(struct nq_store *, struct rp_handle);
int nq_close(struct nq_store *);
#endif
