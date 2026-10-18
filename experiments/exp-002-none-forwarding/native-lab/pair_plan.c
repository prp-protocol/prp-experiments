#include "pair_plan.h"
#include <string.h>
static int mac(const unsigned char *b)
{
    unsigned any = 0;
    for (unsigned i = 0; i < 6; i++)
        any |= b[i];
    return any && !(b[0] & 1);
}
int pair_decode(struct pair_plan *p, const unsigned char b[60], unsigned expected)
{
    if (!p || !b)
        return 0;
    memset(p, 0, sizeof(*p));
    if (memcmp(b, "EXP2HS01", 8) || b[8] != expected || (expected != 1 && expected != 2) || b[9] ||
        b[10] || b[11] || b[12] || b[13] || b[14] || b[15] != 1 || !mac(b + 16) || !mac(b + 22) ||
        !memcmp(b + 16, b + 22, 6))
        return 0;
    unsigned any = 0;
    for (unsigned i = 28; i < 60; i++)
        any |= b[i];
    if (!any)
        return 0;
    p->role = expected;
    p->links = 1;
    p->generation = 1;
    memcpy(p->local, b + 16, 6);
    memcpy(p->remote, b + 22, 6);
    memcpy(p->public_key, b + 28, 32);
    return 1;
}

int pair_decode_route(struct pair_plan *p, const unsigned char *b, size_t n, unsigned expected)
{
    if (!p)
        return 0;
    memset(p, 0, sizeof(*p));
    if (!b || n != 104 || memcmp(b, "EXP2HS02", 8))
        return 0;
    unsigned char legacy[60];
    memcpy(legacy, b, 28);
    memcpy(legacy, "EXP2HS01", 8);
    memcpy(legacy + 28, b + 40, 32);
    struct pair_plan value;
    if (!pair_decode(&value, legacy, expected))
        return 0;
    const unsigned char *addresses[4] = {b + 16, b + 22, b + 28, b + 34};
    for (unsigned i = 0; i < 4; i++) {
        if (!mac(addresses[i]))
            return 0;
        for (unsigned j = 0; j < i; j++)
            if (!memcmp(addresses[i], addresses[j], 6))
                return 0;
    }
    unsigned any = 0;
    for (unsigned i = 72; i < 104; i++)
        any |= b[i];
    if (!any)
        return 0;
    memcpy(value.public_key_second, b + 72, 32);
    value.links = 2;
    memcpy(value.local_second, b + 28, 6);
    memcpy(value.remote_second, b + 34, 6);
    *p = value;
    return 1;
}
