#!/bin/bash
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for 'remount-secure' option parsing / level resolution.
##
## Asserts (via '--check', which audits without root and never mounts):
##   - each explicit level maps to the right mount-option set
##   - level 0 opts out (exit 0, warning)
##   - an unrecognized argument fails closed (the parser must never silently
##     fall back to a level for a typo)
##
## The no-argument service default (level 3 when no remountsecure= token is on
## the kernel command line) enforces real mounts as root and is covered by the
## image boot test, not here.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
rs_bin="${REMOUNT_SECURE_BIN:-${repo_root}/usr/bin/remount-secure#security-misc-shared}"

if [ ! -f "${rs_bin}" ]; then
  printf '%s\n' "FAIL: remount-secure not found at '${rs_bin}'." >&2
  exit 1
fi

fail() {
  printf '%s\n' "FAIL: ${1}" >&2
  exit 1
}

assert_contains() {
  local desc="$1" haystack="$2" needle="$3"
  if [[ "${haystack}" != *"${needle}"* ]]; then
    fail "${desc}: expected output to contain '${needle}'"
  fi
}

assert_absent() {
  local desc="$1" haystack="$2" needle="$3"
  if [[ "${haystack}" == *"${needle}"* ]]; then
    fail "${desc}: expected output to NOT contain '${needle}'"
  fi
}

## --check exits non-zero when the live system deviates from the audited level,
## which is the normal state on a build/dev host, so the level INFO lines (not
## the exit status) are the machine-independent signal for levels 1-3.

## Level 3: noexec everywhere, including /home.
out="$(bash -- "${rs_bin}" --check 3 2>&1 || true)"
assert_contains 'level 3' "${out}" 'INFO: level 3/3'
assert_contains 'level 3' "${out}" 'using noexec for all: yes'

## Level 2: noexec for most, excluding /home.
out="$(bash -- "${rs_bin}" --check 2 2>&1 || true)"
assert_contains 'level 2' "${out}" 'INFO: level 2/3'
assert_contains 'level 2' "${out}" 'using noexec for most (not all): yes'
assert_absent   'level 2' "${out}" 'using noexec for all: yes'

## Level 1: nosuid,nodev only, no noexec.
out="$(bash -- "${rs_bin}" --check 1 2>&1 || true)"
assert_contains 'level 1' "${out}" 'INFO: level 1/3'
assert_absent   'level 1' "${out}" 'using noexec for all: yes'

## Level 0: opt out entirely (exit 0, explicit warning).
rc=0
out="$(bash -- "${rs_bin}" --check 0 2>&1)" || rc=$?
[ "${rc}" -eq 0 ] || fail "--check 0 should exit 0, got ${rc}."
assert_contains 'level 0' "${out}" 'Not using remount-secure'

## An unrecognized argument (a typo, or an out-of-range level) must fail closed,
## never silently fall back to the default level.
for bad in 'bogus' '9'; do
  rc=0
  out="$(bash -- "${rs_bin}" --check "${bad}" 2>&1)" || rc=$?
  [ "${rc}" -ne 0 ] || fail "unrecognized argument '${bad}' should fail but exited 0."
  assert_contains "bad arg '${bad}'" "${out}" 'unexpected argument'
done

printf '%s\n' "PASS: remount-secure option parsing / level resolution"
