#ifndef EXP_NATIVE_PREPARE_H
#define EXP_NATIVE_PREPARE_H
#include "reserved_netlink.h"
/* Pre-input intent, held by the consumer. This is not remote identity evidence.
 * M2 requires independent remote-M1 admission before PREPARE, then the existing
 * verifier/binding path. Neither API supplies capture or peer provenance. */
struct np_intent {
 unsigned started,attempted;
 struct rn_port *port;
 struct nt_context context;
 struct nt_prepare setup;
 struct sa_policy policy;
 struct nt_remote_m1 remote;
 unsigned remote_bound;
 int primary;
};
int np_bind(struct np_intent *,struct rn_port *,const struct nt_prepare *,
            const struct sa_policy *);
int np_sign(struct np_intent *,struct sc_client *,const struct sa_ops *);
int np_bind_m2(struct np_intent *,struct rn_port *,const struct nt_prepare *,
               const struct sa_policy *,const struct nt_remote_m1 *);
int np_sign_m2(struct np_intent *,struct sc_client *,const unsigned char *,size_t,
               struct sb_backend *,const struct sa_ops *);
#endif
