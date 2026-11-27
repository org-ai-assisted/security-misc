/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 */

/*
 * AI-Assisted
 *
 * Canary for the c1bR bug class: the pre-fix design resynced panic state by
 * calling EVIOCGKEY on each surviving device in turn, ORing snapshots that were
 * read at DIFFERENT instants. This models that -- each device read at an
 * independently chosen time -- and asserts the property the panic logic must
 * satisfy: a reported all-groups-held combo must correspond to SOME single
 * instant at which both groups were held across the devices.
 *
 * CBMC MUST report VERIFICATION FAILED (a counterexample where cross-time OR
 * reports a combo that held at no common instant). cbmc-run.sh treats FAILED as
 * the expected, passing result here. The shipped derive_panic_state avoids this
 * entirely by reading ONE in-memory snapshot (proven in cbmc_derive_proof.c),
 * so the same property holds for the new design by construction.
 */

#include <stdbool.h>
#include <stddef.h>

#define canary_dev 2
#define canary_time 2

int nondet_int(void);
bool nondet_bool(void);

int main(void) {
  /* hold_ctrl[d][t] / hold_alt[d][t]: device d holds the group's key at time t. */
  bool hold_ctrl[canary_dev][canary_time];
  bool hold_alt[canary_dev][canary_time];
  for (size_t d = 0; d < canary_dev; d++) {
    for (size_t t = 0; t < canary_time; t++) {
      hold_ctrl[d][t] = nondet_bool();
      hold_alt[d][t] = nondet_bool();
    }
  }

  /* Old resync: read each device once, at an independently chosen instant. */
  size_t read_time[canary_dev];
  for (size_t d = 0; d < canary_dev; d++) {
    read_time[d] = (size_t) nondet_int();
    __CPROVER_assume(read_time[d] < canary_time);
  }

  bool active_ctrl = false;
  bool active_alt = false;
  for (size_t d = 0; d < canary_dev; d++) {
    if (hold_ctrl[d][read_time[d]]) {
      active_ctrl = true;
    }
    if (hold_alt[d][read_time[d]]) {
      active_alt = true;
    }
  }

  /* Was there any single instant with both groups held across the devices? */
  bool exists_common = false;
  for (size_t t = 0; t < canary_time; t++) {
    bool c = false;
    bool a = false;
    for (size_t d = 0; d < canary_dev; d++) {
      if (hold_ctrl[d][t]) {
        c = true;
      }
      if (hold_alt[d][t]) {
        a = true;
      }
    }
    if (c && a) {
      exists_common = true;
    }
  }

  if (active_ctrl && active_alt) {
    __CPROVER_assert(exists_common,
      "CANARY: cross-time OR must be able to fire with no common instant");
  }
  return 0;
}
