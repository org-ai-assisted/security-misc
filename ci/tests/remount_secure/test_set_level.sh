#!/bin/bash
## Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for 'remount-secure --get-level' / '--set-level'.
##
## These subcommands back the System Maintenance Panel "Exec / Noexec Settings"
## dialog. --set-level records the chosen level (0-3) on the kernel command
## line via a managed GRUB drop-in and regenerates grub.cfg; --get-level reads
## it back so the GUI can preselect.
##
## Asserts:
##   - absent config -> --get-level reports the assumed default (3)
##   - --set-level N writes 'remountsecure=N' and round-trips via --get-level
##   - the written GRUB line keeps the literal, unexpanded $GRUB_CMDLINE_LINUX
##     (grub-mkconfig expands it, not us)
##   - level 0 is recorded explicitly
##   - an invalid level fails closed (non-zero exit)
##
## Root-free and grub-free: the managed drop-in path is redirected to a temp
## file via the environment, and a stub 'update-grub' is placed on PATH.

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

test_dir="$(mktemp -d -t rs-set-level-test.XXXXXX)"

cleanup() {
  safe-rm --recursive --force -- "${test_dir}"
}
trap cleanup EXIT

## Redirect the managed GRUB drop-in to the temp dir.
export remount_secure_managed_grub_drop_in="${test_dir}/40_remount_secure_managed.cfg"

## Stub 'update-grub' so the test needs neither root nor an installed GRUB.
stub_dir="${test_dir}/bin"
mkdir --parents -- "${stub_dir}"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${stub_dir}/update-grub"
chmod +x -- "${stub_dir}/update-grub"
export PATH="${stub_dir}:${PATH}"

fail() {
  printf '%s\n' "FAIL: ${1}" >&2
  exit 1
}

## Absent config must report the assumed default level.
level="$(bash -- "${rs_bin}" --get-level)"
[ "${level}" = '3' ] \
  || fail "absent config: expected default '3', got '${level}'."

## A chosen level must survive a write/read round-trip.
bash -- "${rs_bin}" --set-level 2 >/dev/null \
  || fail "--set-level 2 exited non-zero."
grep --quiet --fixed-strings 'remountsecure=2' -- "${remount_secure_managed_grub_drop_in}" \
  || fail "drop-in does not contain 'remountsecure=2'."
level="$(bash -- "${rs_bin}" --get-level)"
[ "${level}" = '2' ] \
  || fail "after set-level 2: expected '2', got '${level}'."

## grub-mkconfig expands the variable, not us, so the match string stays
## literal; single quotes are intentional here.
# shellcheck disable=SC2016
grep --quiet --fixed-strings 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX remountsecure=2"' \
  -- "${remount_secure_managed_grub_drop_in}" \
  || fail "GRUB line not written verbatim (escaping regression)."

## Off must be recorded explicitly, not left to the default.
bash -- "${rs_bin}" --set-level 0 >/dev/null \
  || fail "--set-level 0 exited non-zero."
level="$(bash -- "${rs_bin}" --get-level)"
[ "${level}" = '0' ] \
  || fail "after set-level 0: expected '0', got '${level}'."

## An out-of-range level must fail closed.
rc=0
bash -- "${rs_bin}" --set-level 9 >/dev/null 2>&1 || rc="$?"
[ "${rc}" -ne 0 ] \
  || fail "--set-level 9 should fail but exited 0."

printf '%s\n' "PASS: remount-secure --get-level / --set-level"
