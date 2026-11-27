#!/bin/bash
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for 'remount-secure --runtime-dir <uid>' -- the per-login
## /run/user/<uid> noexec hardening invoked from the user-runtime-dir@.service
## ExecStartPost drop-in (logind mounts that tmpfs nosuid,nodev but never noexec).
##
## Asserts (with 'id'/'findmnt'/'mount' stubbed, so the logic runs without root or
## real mounts):
##   - a non-numeric or empty uid fails closed (never reaches a mount path)
##   - level gating: noexec is added only at effective level >= 2 (matching /run);
##     the 'noremountsecure' off-switch (-> level 0) makes it a no-op
##   - the exact remount invocation (remount,nosuid,nodev,noexec /run/user/<uid>)
##   - a not-mounted dir is a no-op, not an error
##   - non-root fails closed
## The real kernel remount + exec-block is covered by the image boot test.

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

stub_dir="$(mktemp --directory -t rs-runtime-stub.XXXXXX)"
mount_log="$(mktemp -t rs-runtime-mount.XXXXXX)"
tmp_cmdline="$(mktemp -t rs-runtime-cmdline.XXXXXX)"
cleanup() {
  safe-rm --recursive --force -- "${stub_dir}"
  safe-rm --force -- "${mount_log}" "${tmp_cmdline}"
}
trap cleanup EXIT

## id: report RS_TEST_UID (default 0 = root) for 'id -u'.
cat > "${stub_dir}/id" <<'STUB'
#!/bin/bash
[ "${1:-}" = "-u" ] && { printf '%s\n' "${RS_TEST_UID:-0}"; exit 0; }
exit 0
STUB
## findmnt: mounted unless RS_TEST_MOUNTED=0.
cat > "${stub_dir}/findmnt" <<'STUB'
#!/bin/bash
[ "${RS_TEST_MOUNTED:-1}" = "1" ] && exit 0
exit 1
STUB
## mount: record the invocation, never touch the real mount table.
cat > "${stub_dir}/mount" <<STUB
#!/bin/bash
printf '%s\n' "\$*" >> "${mount_log}"
exit 0
STUB
chmod 0755 -- "${stub_dir}/id" "${stub_dir}/findmnt" "${stub_dir}/mount"

## No drop-in config (HELPER_SCRIPTS_PATH points nowhere) -> the hardcoded default
## level 3, i.e. the noexec-applying path, unless the cmdline opts out.
printf '%s\n' 'BOOT_IMAGE=/vmlinuz ro quiet' > "${tmp_cmdline}"

run_rtd() {
  ## $1 uid; honors RS_TEST_UID / RS_TEST_MOUNTED / the cmdline file from the env.
  PATH="${stub_dir}:${PATH}" HELPER_SCRIPTS_PATH=/nonexistent \
    remount_secure_cmdline_file="${tmp_cmdline}" \
    bash -- "${rs_bin}" --runtime-dir "$@" 2>&1
}

## A non-numeric or empty uid must fail closed before any mount path is built.
for bad in 'abc' '' '10; rm -rf /' '../0'; do
  printf '%s' '' > "${mount_log}"
  rc=0
  out="$(run_rtd "${bad}")" || rc=$?
  [ "${rc}" -ne 0 ] || fail "non-numeric uid '${bad}' should fail but exited 0."
  assert_contains "bad uid '${bad}'" "${out}" 'numeric uid'
  [ ! -s "${mount_log}" ] || fail "bad uid '${bad}' must not invoke mount."
done

## Default level 3 + mounted + root: noexec IS applied with the exact options.
printf '%s' '' > "${mount_log}"
out="$(run_rtd 1000)"
log="$(cat -- "${mount_log}")"
assert_contains 'level 3 remount opts' "${log}" 'remount,nosuid,nodev,noexec'
assert_contains 'level 3 remount target' "${log}" '/run/user/1000'
assert_contains 'level 3 make-private' "${log}" '--make-private'

## 'noremountsecure' kernel-cmdline off-switch (-> effective level 0): no-op, no
## mount, exit 0.
printf '%s\n' 'BOOT_IMAGE=/vmlinuz noremountsecure ro quiet' > "${tmp_cmdline}"
printf '%s' '' > "${mount_log}"
rc=0
out="$(run_rtd 1000)" || rc=$?
[ "${rc}" -eq 0 ] || fail "noremountsecure --runtime-dir should exit 0, got ${rc}."
[ ! -s "${mount_log}" ] || fail "level 0 must not invoke mount."
assert_contains 'level 0 no-op' "${out}" 'noexec starts at level 2'
printf '%s\n' 'BOOT_IMAGE=/vmlinuz ro quiet' > "${tmp_cmdline}"

## A /run/user/<uid> that is not mounted is a no-op (fail open), not an error.
printf '%s' '' > "${mount_log}"
rc=0
out="$(RS_TEST_MOUNTED=0 run_rtd 1000)" || rc=$?
[ "${rc}" -eq 0 ] || fail "not-mounted --runtime-dir should exit 0, got ${rc}."
[ ! -s "${mount_log}" ] || fail "not-mounted dir must not invoke mount."
assert_contains 'not mounted' "${out}" 'not mounted'

## Non-root must fail closed (the remount needs CAP_SYS_ADMIN).
printf '%s' '' > "${mount_log}"
rc=0
out="$(RS_TEST_UID=1000 run_rtd 1000)" || rc=$?
[ "${rc}" -ne 0 ] || fail "non-root --runtime-dir should fail but exited 0."
assert_contains 'non-root' "${out}" 'must run as root'
[ ! -s "${mount_log}" ] || fail "non-root must not invoke mount."

printf '%s\n' "PASS: remount-secure --runtime-dir /run/user hardening"
