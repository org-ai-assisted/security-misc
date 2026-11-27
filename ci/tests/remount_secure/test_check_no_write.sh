#!/bin/bash
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test: 'remount-secure --check' (audit) must not write.
##
## The audit path is read-only by contract (systemcheck runs it, possibly as
## root). A regression that creates the '/run/remount-secure' status directory
## during --check aborts the audit under 'errexit' if '/run' is read-only.
##
## Run under 'unshare --map-root-user' so 'id -u' is 0 inside (exercising the
## root branch) while filesystem writes outside the temp dir remain unprivileged.
## That also makes the test RED on the pre-fix code: its 'init' mkdir targets the
## real '/run/remount-secure', which the mapped-root user cannot create, so the
## script aborts before the audit markers are ever printed.

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

## Simulating root requires unprivileged user namespaces. This is a required
## capability (present on the CI runner); its absence is an environment bug, not
## a reason to skip and read green.
if ! unshare --map-root-user -- true >/dev/null 2>&1; then
  fail "unprivileged user namespaces unavailable: cannot simulate root for this test."
fi

tmp_base="$(mktemp --directory -t rs-check-no-write.XXXXXX)"
## The status dir path is INSIDE tmp_base and does NOT exist yet. A write to it
## is the regression this test catches.
run_dir="${tmp_base}/run-remount-secure"
cleanup() {
  safe-rm --recursive --force -- "${tmp_base}"
}
trap cleanup EXIT

assert_no_run_dir() {
  local desc="$1"
  if [ -e "${run_dir}" ]; then
    fail "${desc}: --check created the status dir '${run_dir}' -- audit must not write."
  fi
}

assert_contains() {
  local desc="$1" haystack="$2" needle="$3"
  if [[ "${haystack}" != *"${needle}"* ]]; then
    fail "${desc}: expected audit to run and emit '${needle}' (pre-fix code aborts in init before this)."
  fi
}

## --check with an explicit level 3, as (mapped) root. The audit must run to
## completion (markers present) and create nothing under run_dir.
out="$(unshare --map-root-user -- \
  env remount_secure_runtime_dir="${run_dir}" \
  bash -- "${rs_bin}" --check 3 2>&1 || true)"
assert_contains 'explicit --check 3' "${out}" 'INFO: --check (audit only)'
assert_contains 'explicit --check 3' "${out}" 'INFO: level 3/3'
assert_no_run_dir 'explicit --check 3'

## --check with no explicit level resolves the configured default (level 3 with
## no drop-in). HELPER_SCRIPTS_PATH points nowhere so the drop-in read is
## hermetic. Still no write on the audit path.
out="$(unshare --map-root-user -- \
  env remount_secure_runtime_dir="${run_dir}" \
      HELPER_SCRIPTS_PATH=/nonexistent \
      remount_secure_cmdline_file=/dev/null \
  bash -- "${rs_bin}" --check 2>&1 || true)"
assert_contains 'bare --check' "${out}" 'INFO: --check (audit only)'
assert_contains 'bare --check' "${out}" 'INFO: level 3/3'
assert_no_run_dir 'bare --check'

printf '%s\n' "PASS: remount-secure --check performs no status-directory write"
