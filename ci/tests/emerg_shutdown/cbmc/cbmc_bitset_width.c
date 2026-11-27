/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 */

/*
 * CBMC proof that bitset_set / bitset_get in emerg-shutdown-panic-state.h are
 * correct for every key index the evdev bitmap can hold, on BOTH a 64-bit and a
 * 32-bit target. cbmc-run.sh runs it with and without --32; the 32-bit run is
 * the point.
 *
 * With the old 'unsigned long' (1UL) shift constant on an ILP32 target:
 *  - bitset_set(bm, i, true) for (i % 64) >= 32 shifts a 32-bit 1 (undefined;
 *    on x86-32 the count is masked to 5 bits, so the WRONG bit is set), so
 *    bitset_get(bm, i) reads back false - the key is never seen as held;
 *  - any release '&= ~(1UL << ...)' zero-extends a 32-bit mask to 64 bits,
 *    wiping bits 32..63 of that word - every other high key in the word is lost.
 * Key codes reach KEY_F24 = 194, so this is reachable. The shipped UINT64_C(1)
 * is width-correct, so both runs must verify SUCCESSFUL.
 *
 * Properties, over a nondeterministic bit index i, a second index j, and
 * arbitrary starting bitmap contents:
 *  - set-then-get round-trips (bitset_get(bm, i) == the value just written);
 *  - setting or clearing bit i changes no other bit j (no same-word or
 *    cross-word clobber).
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "emerg-shutdown-panic-state.h"

uint32_t nondet_u32(void);
uint64_t nondet_u64(void);
bool nondet_bool(void);

#define bits_total (key_flags_len * 64)

int main(void) {
  uint64_t bm[key_flags_len];
  size_t w = 0;
  uint32_t i = nondet_u32();
  uint32_t j = nondet_u32();
  bool set_val = nondet_bool();
  bool j_before = false;

  __CPROVER_assume(i < bits_total);
  __CPROVER_assume(j < bits_total);

  /* Arbitrary starting contents, so the proof covers any prior held keys. */
  for (w = 0; w < key_flags_len; w++) {
    bm[w] = nondet_u64();
  }

  j_before = bitset_get(bm, j);

  bitset_set(bm, i, set_val);

  __CPROVER_assert(bitset_get(bm, i) == set_val,
    "bitset_set then bitset_get round-trips for every key index");

  if (j != i) {
    __CPROVER_assert(bitset_get(bm, j) == j_before,
      "bitset_set changes only bit i, never another bit (no word clobber)");
  }
  return 0;
}
