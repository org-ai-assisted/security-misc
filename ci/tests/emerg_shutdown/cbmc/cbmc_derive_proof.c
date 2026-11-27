/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 */

/*
 * AI-Assisted
 *
 * CBMC proof for emerg-shutdown's panic-state derivation (the SHIPPED
 * derive_panic_state in emerg-shutdown-panic-state.h).
 *
 * Proves, over all inputs, the single-snapshot spec that the per-device
 * key-state design guarantees and that the previous EVIOCGKEY resync could
 * not:
 *
 *   a panic group is active IFF some SURVIVING device (fd >= 0) holds one of
 *   its keys, read from ONE in-memory snapshot.
 *
 * The "fd >= 0" half is exactly the c1bV fix: a dropped (tombstoned, fd -1)
 * device must contribute nothing, so its held keys cannot complete a combo.
 * The single-snapshot half is the c1bR property: the result reflects one
 * consistent instant, never state OR'd across devices read at different times.
 * See cbmc_derive_canary_stale.c and cbmc_crosstime_canary.c for the matching
 * canaries (CBMC must FIND a counterexample on the pre-fix behaviors).
 */

#include "emerg-shutdown-panic-state.h"

#define proof_max_dev 3
#define proof_num_group 2

int nondet_int(void);
uint64_t nondet_u64(void);
uint32_t nondet_u32(void);

int main(void) {
  size_t num_dev = (size_t) nondet_int();
  __CPROVER_assume(num_dev <= proof_max_dev);

  int fds[proof_max_dev];
  uint64_t bitmaps[proof_max_dev][key_flags_len];
  uint64_t *bitmap_ptrs[proof_max_dev];

  for (size_t d = 0; d < num_dev; d++) {
    fds[d] = nondet_int();
    for (size_t w = 0; w < key_flags_len; w++) {
      bitmaps[d][w] = nondet_u64();
    }
    bitmap_ptrs[d] = bitmaps[d];
  }

  /*
   * Two panic groups, one key each. Keys are nondeterministic but valid: in
   * range of the bitmap and nonzero (0 terminates a key group).
   */
  uint32_t key_a = nondet_u32();
  uint32_t key_b = nondet_u32();
  __CPROVER_assume(key_a > 0 && key_a < key_flags_len * 64);
  __CPROVER_assume(key_b > 0 && key_b < key_flags_len * 64);

  uint32_t group0[2] = { key_a, 0 };
  uint32_t group1[2] = { key_b, 0 };
  uint32_t *panic_key_list[proof_num_group] = { group0, group1 };
  bool active[proof_num_group] = { false, false };

  derive_panic_state(num_dev, fds, bitmap_ptrs, proof_num_group,
    panic_key_list, active);

  uint32_t group_key[proof_num_group] = { key_a, key_b };
  for (size_t g = 0; g < proof_num_group; g++) {
    bool expect = false;
    for (size_t d = 0; d < num_dev; d++) {
      if (fds[d] >= 0 && bitset_get(bitmap_ptrs[d], group_key[g])) {
        expect = true;
      }
    }
    __CPROVER_assert(active[g] == expect,
      "group active IFF a surviving device holds its key (single snapshot)");
  }
  return 0;
}
