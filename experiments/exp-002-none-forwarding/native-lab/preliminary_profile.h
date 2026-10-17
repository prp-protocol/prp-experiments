#ifndef EXP002_PRELIMINARY_PROFILE_H
#define EXP002_PRELIMINARY_PROFILE_H
/* Phase/record/barrier identity never changes with treatment order. */
#ifndef PD_REVERSE
#define PD_REVERSE 0
#endif
#if PD_REVERSE != 0 && PD_REVERSE != 1
#error Invalid preliminary treatment order
#endif
#ifdef PD_WARMED
#define PD_WARMUP 32u
#define PD_MEASURED 32u
#else
#define PD_WARMUP 0u
#define PD_MEASURED 2u
#endif
#ifndef PD_VERIFY_ANNEX
#define PD_VERIFY_ANNEX 1
#endif
#if PD_VERIFY_ANNEX != 0 && PD_VERIFY_ANNEX != 1
#error Invalid annex policy
#endif
#define PD_PER_MODE (PD_WARMUP + PD_MEASURED)
static inline unsigned pd_mode(unsigned phase)
{
 return phase == 1 || phase == 2 ? (PD_REVERSE ? 3 - phase : phase) : 0;
}
#endif
