#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Run the emerg-shutdown CBMC proofs and their canaries.
##
## - cbmc_derive_proof.c       : the shipped derive_panic_state satisfies the
##                               single-snapshot / surviving-device spec. Must
##                               verify SUCCESSFUL.
## - cbmc_derive_canary_stale.c: a model of the pre-fix stale-dropped-device
##                               behavior (c1bV). Must verify FAILED, on its
##                               named assertion.
## - cbmc_crosstime_canary.c   : a model of the pre-fix cross-time EVIOCGKEY OR
##                               (c1bR). Must verify FAILED, on its named
##                               assertion.
## - cbmc_bitset_width.c       : bitset_set/get are width-correct for every key
##                               index on a 64-bit AND a 32-bit target (the old
##                               1UL shift was broken on ILP32). Must verify
##                               SUCCESSFUL under both.
##
## The canaries fail ON PURPOSE (canary-test-your-tests): if they ever verified
## SUCCESSFUL the proof's assertion would be vacuous. A canary is accepted only
## when CBMC fails on its INTENDED assertion and on NOTHING else - an unwinding,
## bounds, or pointer failure would make the canary pass for the wrong reason
## while its real property still holds.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

export LC_ALL=C

here="$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")"
## ci/tests/emerg_shutdown/cbmc -> repo root (no git dependency: the sandbox
## syncs a worktree copy without the submodule .git).
repo_root="$(cd -- "${here}/../../../.." && pwd)"
src_dir="${repo_root}/usr/src/security-misc"

## Clean-named symlink so a harness can #include the '#tag'-suffixed header.
inc_dir="$(mktemp -d)"
## invoked indirectly via 'trap ... EXIT'
# shellcheck disable=SC2317
cleanup() {
  safe-rm --recursive --force -- "${inc_dir}"
}
trap cleanup EXIT

ln -snf -- "${src_dir}/emerg-shutdown-panic-state.h#security-misc-shared" \
  "${inc_dir}/emerg-shutdown-panic-state.h"

## --unwind exceeds the longest harness loop (key_flags_len seeding = 12).
cbmc_flags=(
  --unwind 13
  --unwinding-assertions
  --bounds-check
  --pointer-check
  -I "${inc_dir}"
)

## Per-run extras (e.g. --32) and a label for the output line.
extra_flags=()
extra_label=""

run_one() {
  local harness="$1"
  local expect="$2"
  local assert_desc="${3:-}"
  local out=""
  local got=""
  local fails=""
  local other=""

  printf '%s\n' "=== cbmc $(basename -- "${harness}") ${extra_label}(expect ${expect}) ==="
  if out="$(cbmc "${cbmc_flags[@]}" "${extra_flags[@]}" "${harness}" 2>&1)"; then
    : ## exit 0: verification successful
  else
    : ## non-zero (e.g. 10 on property violation): verdict parsed from text
  fi

  case "${out}" in
    *'VERIFICATION SUCCESSFUL'*)
      got=success
      ;;
    *'VERIFICATION FAILED'*)
      got=failed
      ;;
    *)
      printf '%s\n' "FAIL: cbmc gave no clear verdict for ${harness}" >&2
      printf '%s\n' "${out}" >&2
      return 1
      ;;
  esac

  if [ "${got}" != "${expect}" ]; then
    printf '%s\n' \
      "FAIL: $(basename -- "${harness}") ${extra_label}expected ${expect}, got ${got}" >&2
    printf '%s\n' "${out}" >&2
    return 1
  fi

  ## A canary must fail for its INTENDED reason only.
  if [ "${expect}" = failed ] && [ -n "${assert_desc}" ]; then
    fails="$(printf '%s\n' "${out}" | grep -- ': FAILURE' || true)"
    case "${fails}" in
      *"${assert_desc}: FAILURE"*)
        : ## intended assertion is among the failures
        ;;
      *)
        printf '%s\n' \
          "FAIL: $(basename -- "${harness}") did not fail on its intended assertion" >&2
        printf '%s\n' "  expected FAILURE of: ${assert_desc}" >&2
        printf '%s\n' "${fails}" >&2
        return 1
        ;;
    esac
    other="$(printf '%s\n' "${fails}" | grep -vF -- "${assert_desc}" || true)"
    case "${other}" in
      *': FAILURE'*)
        printf '%s\n' \
          "FAIL: $(basename -- "${harness}") also failed an unintended property (vacuous canary)" >&2
        printf '%s\n' "${other}" >&2
        return 1
        ;;
    esac
  fi

  printf '%s\n' "OK: $(basename -- "${harness}") ${extra_label}-> ${got}"
}

overall=0

extra_flags=()
extra_label=""
run_one "${here}/cbmc_derive_proof.c" success || overall=1
run_one "${here}/cbmc_derive_canary_stale.c" failed \
  "CANARY: stale model must violate the surviving-device spec" || overall=1
run_one "${here}/cbmc_crosstime_canary.c" failed \
  "CANARY: cross-time OR must be able to fire with no common instant" || overall=1
run_one "${here}/cbmc_bitset_width.c" success || overall=1

## The 32-bit run is what catches the 1UL regression (undefined/short shift).
extra_flags=(--32)
extra_label="--32 "
run_one "${here}/cbmc_bitset_width.c" success || overall=1

if [ "${overall}" -eq 0 ]; then
  printf '%s\n' "PASS: all CBMC proof + canary checks met expectations."
else
  printf '%s\n' "FAIL: a CBMC check did not meet its expectation." >&2
fi
exit "${overall}"
