/* Counts actual entries into the instrumented C example and library; never changes its state. */
#include <stdint.h>
#define CAPACITY 32768
struct entry { uintptr_t address; uint64_t count; };
static struct entry entries[CAPACITY];
static unsigned used, overflow, enabled;
/* The application-session API requires a serialized owner. The harness is
 * single-threaded, as is this observer. Neither callback allocates memory. */
void __cyg_profile_func_enter(void *function, void *caller)
{
    (void)caller;
    if (!enabled) return;
    uintptr_t address=(uintptr_t)function;
    unsigned slot=(unsigned)((address >> 4) % CAPACITY);
    for (unsigned n=0;n<CAPACITY;n++,slot=(slot+1)%CAPACITY) {
        if (!entries[slot].address) { entries[slot].address=address; used++; }
        if (entries[slot].address==address) { entries[slot].count++; return; }
    }
    overflow=1;
}
void __cyg_profile_func_exit(void *function, void *caller)
{ (void)function; (void)caller; }
void exp_observer_begin(void)
{
    enabled=0;
    for (unsigned n=0;n<CAPACITY;n++) { entries[n].address=0; entries[n].count=0; }
    used=overflow=0; enabled=1;
}
void exp_observer_end(void) { enabled=0; }
unsigned exp_observer_overflow(void) { return overflow; }
unsigned exp_observer_capacity(void) { return CAPACITY; }
uintptr_t exp_observer_address(unsigned index) { return entries[index].address; }
uint64_t exp_observer_count(unsigned index) { return entries[index].count; }
