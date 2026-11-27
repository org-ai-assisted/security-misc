/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 */

/*
 * AI-Assisted
 *
 * Deterministic unit test for emerg-shutdown's shipped panic-state primitives
 * (emerg-shutdown-panic-state.h). Pins the invariants the per-device key-state
 * design guarantees:
 *   - a group is active IFF some SURVIVING (fd >= 0) device holds its key;
 *   - a dropped (fd -1) device contributes nothing (c1bV);
 *   - any alias in a key group keeps the group active (alias correctness).
 * The adversarial RED-on-pre-fix proof lives in the CBMC canaries; this is the
 * fast forward guard.
 */

#include "emerg-shutdown-panic-state.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, msg)                                                    \
  do {                                                                      \
    if (!(cond)) {                                                          \
      fprintf(stderr, "FAIL: %s\n", (msg));                                 \
      failures++;                                                           \
    }                                                                       \
  } while (0)

/* Arbitrary valid, nonzero key codes (0 terminates a key group). */
enum { K_CTRL = 29, K_RCTRL = 97, K_ALT = 56 };

static void clear_bitmap(uint64_t *bm) {
  memset(bm, 0, key_flags_len * sizeof(uint64_t));
}

int main(void) {
  /* Two groups, one key each: group0 = Ctrl, group1 = Alt. */
  uint32_t group0[2] = { K_CTRL, 0 };
  uint32_t group1[2] = { K_ALT, 0 };
  uint32_t *panic_key_list[2] = { group0, group1 };

  uint64_t bm0[key_flags_len];
  uint64_t bm1[key_flags_len];
  uint64_t *bitmaps[2] = { bm0, bm1 };
  bool active[2];

  /* Test A: OR across surviving devices. dev0 holds Ctrl, dev1 holds Alt. */
  {
    int fds[2] = { 3, 4 };
    clear_bitmap(bm0);
    clear_bitmap(bm1);
    bitset_set(bm0, K_CTRL, true);
    bitset_set(bm1, K_ALT, true);
    derive_panic_state(2, fds, bitmaps, 2, panic_key_list, active);
    CHECK(active[0] && active[1],
      "A: both groups active when each held on a surviving device");
  }

  /* Test B: a dropped (fd -1) device holding both keys contributes nothing. */
  {
    int fds[2] = { -1, 4 };
    clear_bitmap(bm0);
    clear_bitmap(bm1);
    bitset_set(bm0, K_CTRL, true);
    bitset_set(bm0, K_ALT, true);
    /* bm1 empty, dev1 surviving but holds nothing. */
    derive_panic_state(2, fds, bitmaps, 2, panic_key_list, active);
    CHECK(!active[0] && !active[1],
      "B: dropped device's held keys do not count");
  }

  /* Test C (c1bV): Ctrl held on a surviving device, Alt held on a dropped one.
   * The combo must NOT be complete (only group0 active). */
  {
    int fds[2] = { 3, -1 };
    clear_bitmap(bm0);
    clear_bitmap(bm1);
    bitset_set(bm0, K_CTRL, true);
    bitset_set(bm1, K_ALT, true);
    derive_panic_state(2, fds, bitmaps, 2, panic_key_list, active);
    CHECK(active[0] && !active[1],
      "C: stale key on a dropped device cannot complete the combo");
  }

  /* Test D: alias group {Ctrl|RCtrl}. Holding only the RCtrl alias keeps the
   * group active (the old global-bool path cleared the group on any release). */
  {
    uint32_t alias_group[3] = { K_CTRL, K_RCTRL, 0 };
    uint32_t *alias_list[1] = { alias_group };
    bool alias_active[1];
    int fds[1] = { 3 };
    uint64_t *one[1] = { bm0 };
    clear_bitmap(bm0);
    bitset_set(bm0, K_RCTRL, true);
    derive_panic_state(1, fds, one, 1, alias_list, alias_active);
    CHECK(alias_active[0], "D: a held alias keeps its key group active");
  }

  /* Test E: bitset_set / bitset_get roundtrip across a word boundary. */
  {
    clear_bitmap(bm0);
    bitset_set(bm0, 0, true);
    bitset_set(bm0, 63, true);
    bitset_set(bm0, 64, true);
    bitset_set(bm0, 130, true);
    CHECK(bitset_get(bm0, 0) && bitset_get(bm0, 63) && bitset_get(bm0, 64)
      && bitset_get(bm0, 130), "E: set bits read back as set");
    CHECK(!bitset_get(bm0, 1) && !bitset_get(bm0, 65),
      "E: unset bits read back as unset");
    bitset_set(bm0, 64, false);
    CHECK(!bitset_get(bm0, 64), "E: cleared bit reads back as unset");
    CHECK(bitset_get(bm0, 0) && bitset_get(bm0, 130),
      "E: clearing one bit leaves others intact");
  }

  if (failures == 0) {
    printf("PASS: test_panic_state (%d checks ok).\n", 11);
    return 0;
  }
  fprintf(stderr, "FAIL: test_panic_state had %d failing checks.\n", failures);
  return 1;
}
