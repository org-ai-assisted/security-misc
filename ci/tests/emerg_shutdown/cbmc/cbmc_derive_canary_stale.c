/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 */

/*
 * AI-Assisted
 *
 * Canary for cbmc_derive_proof.c (canary-test-your-tests): the proof's
 * assertion must be able to CATCH the c1bV bug. This harness runs the SAME
 * single-snapshot spec against a model of the pre-fix behavior -- a derivation
 * that does NOT exclude dropped (fd -1) devices, so a tombstoned keyboard's
 * stale held keys still count toward a combo.
 *
 * CBMC MUST report VERIFICATION FAILED here (a counterexample: a dropped
 * device holding a group's key makes the group active although the spec says a
 * dropped device contributes nothing). cbmc-run.sh treats FAILED as the
 * expected, passing result for this file. If it ever verified SUCCESSFUL, the
 * proof's assertion would be vacuous.
 */

#include "emerg-shutdown-panic-state.h"

#define canary_max_dev 3
#define canary_num_group 2

int nondet_int(void);
uint64_t nondet_u64(void);
uint32_t nondet_u32(void);

/* Pre-fix model: no fd < 0 exclusion -> a tombstoned device still contributes. */
static void derive_panic_state_stale(size_t event_fd_list_len,
  const int *event_fd_list, uint64_t *const *event_key_state_list,
  size_t panic_key_list_len, uint32_t **panic_key_list,
  bool *panic_key_active_list) {
  (void) event_fd_list;
  for (size_t pkl_idx = 0; pkl_idx < panic_key_list_len; pkl_idx++) {
    panic_key_active_list[pkl_idx] = false;
  }
  for (size_t efl_idx = 0; efl_idx < event_fd_list_len; efl_idx++) {
    for (size_t pkl_idx = 0; pkl_idx < panic_key_list_len; pkl_idx++) {
      for (size_t kg_idx = 0; panic_key_list[pkl_idx][kg_idx] != 0; kg_idx++) {
        if (bitset_get(event_key_state_list[efl_idx],
          panic_key_list[pkl_idx][kg_idx])) {
          panic_key_active_list[pkl_idx] = true;
        }
      }
    }
  }
}

int main(void) {
  size_t num_dev = (size_t) nondet_int();
  __CPROVER_assume(num_dev <= canary_max_dev);

  int fds[canary_max_dev];
  uint64_t bitmaps[canary_max_dev][key_flags_len];
  uint64_t *bitmap_ptrs[canary_max_dev];

  for (size_t d = 0; d < num_dev; d++) {
    fds[d] = nondet_int();
    for (size_t w = 0; w < key_flags_len; w++) {
      bitmaps[d][w] = nondet_u64();
    }
    bitmap_ptrs[d] = bitmaps[d];
  }

  uint32_t key_a = nondet_u32();
  uint32_t key_b = nondet_u32();
  __CPROVER_assume(key_a > 0 && key_a < key_flags_len * 64);
  __CPROVER_assume(key_b > 0 && key_b < key_flags_len * 64);

  uint32_t group0[2] = { key_a, 0 };
  uint32_t group1[2] = { key_b, 0 };
  uint32_t *panic_key_list[canary_num_group] = { group0, group1 };
  bool active[canary_num_group] = { false, false };

  derive_panic_state_stale(num_dev, fds, bitmap_ptrs, canary_num_group,
    panic_key_list, active);

  uint32_t group_key[canary_num_group] = { key_a, key_b };
  for (size_t g = 0; g < canary_num_group; g++) {
    bool expect = false;
    for (size_t d = 0; d < num_dev; d++) {
      if (fds[d] >= 0 && bitset_get(bitmap_ptrs[d], group_key[g])) {
        expect = true;
      }
    }
    __CPROVER_assert(active[g] == expect,
      "CANARY: stale model must violate the surviving-device spec");
  }
  return 0;
}
