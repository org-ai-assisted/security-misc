#!/bin/bash
## Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for 'remount-secure --get-level' / '--set-level'.
##
## These subcommands back the System Maintenance Panel "Mount Security Options"
## dialog. --set-level records the chosen level (0-3) in a managed drop-in
## (/etc/remount-secure.d/40_managed.conf); --get-level reads the effective
## drop-in level back so the GUI can preselect.
##
## Asserts:
##   - absent config -> --get-level reports the hardcoded default (3)
##   - --set-level N writes 'remount_secure_level=N' (mode 644) and round-trips
##   - a /usr/local/etc drop-in overrides /etc (last sourced wins)
##   - a drop-in that sets no level falls back to the default
##   - level 0 is recorded explicitly
##   - an invalid level fails closed (non-zero exit)
##
## Root-free and helper-scripts-free: the drop-in dirs are redirected into a
## temp dir via the environment, and 'source_config' is stubbed on
## HELPER_SCRIPTS_PATH. The real, hardened source_config (ownership/mode/symlink
## checks) is helper-scripts' own concern; here we exercise remount-secure's
## level logic against the sourcing contract (every *.conf, later files win).

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

## Redirect the drop-in config dirs into the temp dir.
etc_dir="${test_dir}/etc"
local_dir="${test_dir}/local"
mkdir --parents -- "${etc_dir}" "${local_dir}"
export remount_secure_etc_dropin_dir="${etc_dir}"
export remount_secure_local_dropin_dir="${local_dir}"
export remount_secure_managed_conf="${etc_dir}/40_managed.conf"

## Stub 'source_config' via HELPER_SCRIPTS_PATH so the test needs no
## helper-scripts checkout and no root-owned config dirs. Mirrors the real
## contract: source every *.conf in directory order, later files win.
helper_lib_dir="${test_dir}/helper/usr/libexec/helper-scripts"
mkdir --parents -- "${helper_lib_dir}"
cat > "${helper_lib_dir}/source_folder.bsh" <<'STUB'
source_config() {
  local dir_item file_item
  shopt -s nullglob
  for dir_item in "$@"; do
    for file_item in "${dir_item}"/*.conf; do
      # shellcheck disable=SC1090
      source "${file_item}"
    done
  done
}
STUB
export HELPER_SCRIPTS_PATH="${test_dir}/helper"

fail() {
  printf '%s\n' "FAIL: ${1}" >&2
  exit 1
}

get_level() {
  bash -- "${rs_bin}" --get-level
}

## Absent config must report the hardcoded default level.
level="$(get_level)"
[ "${level}" = '3' ] \
  || fail "absent config: expected default '3', got '${level}'."

## A chosen level must survive a write/read round-trip.
bash -- "${rs_bin}" --set-level 2 >/dev/null \
  || fail "--set-level 2 exited non-zero."
grep --quiet --fixed-strings 'remount_secure_level=2' -- "${remount_secure_managed_conf}" \
  || fail "managed drop-in does not contain 'remount_secure_level=2'."

## The drop-in must be world-readable: set_level runs as root, but --get-level
## is read unprivileged (the GUI), and mktemp creates it 0600.
mode="$(stat --format='%a' -- "${remount_secure_managed_conf}")"
[ "${mode}" = '644' ] \
  || fail "drop-in mode is '${mode}', expected 644 (unprivileged --get-level must read it)."

level="$(get_level)"
[ "${level}" = '2' ] \
  || fail "after set-level 2: expected '2', got '${level}'."

## A /usr/local/etc drop-in must override /etc (last sourced wins).
printf '%s\n' 'remount_secure_level=1' > "${local_dir}/50_local.conf"
level="$(get_level)"
[ "${level}" = '1' ] \
  || fail "local drop-in should override etc: expected '1', got '${level}'."
safe-rm --force -- "${local_dir}/50_local.conf"

## A drop-in that sets no level must fall back to the default.
printf '%s\n' '## comment only, no level' > "${etc_dir}/40_managed.conf"
level="$(get_level)"
[ "${level}" = '3' ] \
  || fail "drop-in without remount_secure_level: expected default '3', got '${level}'."

## Off must be recorded explicitly, not left to the default.
bash -- "${rs_bin}" --set-level 0 >/dev/null \
  || fail "--set-level 0 exited non-zero."
level="$(get_level)"
[ "${level}" = '0' ] \
  || fail "after set-level 0: expected '0', got '${level}'."

## An out-of-range level must fail closed.
rc=0
bash -- "${rs_bin}" --set-level 9 >/dev/null 2>&1 || rc="$?"
[ "${rc}" -ne 0 ] \
  || fail "--set-level 9 should fail but exited 0."

printf '%s\n' "PASS: remount-secure --get-level / --set-level"
