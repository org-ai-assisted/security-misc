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
## The 'noremountsecure' debug off-switch and the hardcoded no-config default
## (level 3) are checked here via '--check'. The real mount enforcement as root
## is covered by the image boot test.

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

## Multiple explicit levels on argv: the last one wins cleanly.
## 'level_to_mount_options' resets its noexec flags on each call; without that,
## '3 2' bleeds the level-3 /home noexec into the level-2 result and the summary
## wrongly reports 'noexec for all'.
out="$(bash -- "${rs_bin}" --check 3 2 2>&1 || true)"
assert_contains 'multi-level 3 2' "${out}" 'using noexec for most (not all): yes'
assert_absent   'multi-level 3 2' "${out}" 'using noexec for all: yes'

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

## No explicit level: resolve from the drop-in config / cmdline. A fake cmdline
## file is injected so the test does not depend on the host's real /proc/cmdline.
tmp_cmdline="$(mktemp -t rs-parse-cmdline.XXXXXX)"
stub_helpers=''
cleanup() {
  safe-rm --force -- "${tmp_cmdline}"
  [ -z "${stub_helpers}" ] || safe-rm --recursive --force -- "${stub_helpers}"
}
trap cleanup EXIT

## No drop-in config readable (HELPER_SCRIPTS_PATH points nowhere) and no
## 'noremountsecure' token -> the hardcoded default level 3.
printf '%s\n' 'BOOT_IMAGE=/vmlinuz ro quiet' > "${tmp_cmdline}"
out="$(HELPER_SCRIPTS_PATH=/nonexistent remount_secure_cmdline_file="${tmp_cmdline}" \
  bash -- "${rs_bin}" --check 2>&1 || true)"
assert_contains 'no-config default' "${out}" 'INFO: level 3/3'

## 'noremountsecure' on the kernel command line is a debug off-switch (level 0,
## exit 0), overriding the drop-in level.
printf '%s\n' 'BOOT_IMAGE=/vmlinuz noremountsecure ro quiet' > "${tmp_cmdline}"
rc=0
out="$(HELPER_SCRIPTS_PATH=/nonexistent remount_secure_cmdline_file="${tmp_cmdline}" \
  bash -- "${rs_bin}" --check 2>&1)" || rc=$?
[ "${rc}" -eq 0 ] || fail "noremountsecure --check should exit 0, got ${rc}."
assert_contains 'noremountsecure' "${out}" 'Not using remount-secure'

## A drop-in read that FAILS after a fragment already set the level must fall
## back to the ANNOUNCED default (3), never retain the stale partial value. Stub
## a source_folder.bsh whose 'source_config' sets a level and then returns
## non-zero -- exactly the 'an earlier fragment set remount_secure_level, a later
## fragment failed bash -n' case. Without the failure-branch reset, the stale
## level 0 wins and the audit wrongly reports an opt-out (fail-open + a warning
## that lies about the level in effect).
stub_helpers="$(mktemp --directory -t rs-stub-helpers.XXXXXX)"
mkdir --parents -- "${stub_helpers}/usr/libexec/helper-scripts"
{
  printf '%s\n' 'source_config() {'
  printf '%s\n' '  remount_secure_level=0'
  printf '%s\n' '  return 1'
  printf '%s\n' '}'
} > "${stub_helpers}/usr/libexec/helper-scripts/source_folder.bsh"
printf '%s\n' 'BOOT_IMAGE=/vmlinuz ro quiet' > "${tmp_cmdline}"
out="$(HELPER_SCRIPTS_PATH="${stub_helpers}" remount_secure_cmdline_file="${tmp_cmdline}" \
  bash -- "${rs_bin}" --check 2>&1 || true)"
assert_contains 'stale-level fallback' "${out}" 'reading remount-secure drop-in configuration failed'
assert_contains 'stale-level fallback' "${out}" 'INFO: level 3/3'
assert_absent   'stale-level fallback' "${out}" 'Not using remount-secure'

printf '%s\n' "PASS: remount-secure option parsing / level resolution"
