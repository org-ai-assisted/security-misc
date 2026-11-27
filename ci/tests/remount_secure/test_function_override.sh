#!/bin/bash
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for drop-in FUNCTION OVERRIDE: a '*.conf' fragment sourced from
## /etc/remount-secure.d (or /usr/local/etc/remount-secure.d) may redefine a
## mount-helper function (e.g. '_opt', '_home') to customize that mountpoint's
## options. This works only because the config is sourced in the MAIN shell during
## level resolution (not a '$()' subshell, which would discard the redefinition).
##
## Guards the exact regression this feature fixed: on the old subshell code the
## override was silently dropped and '/opt' kept its default options. Asserts (with
## 'id'/'findmnt'/'mount' and 'source_config' stubbed, so no root, real mounts, or
## root-owned config files are needed -- the real hardened source_config is covered
## in the helper-scripts suite):
##   - an overridden function ('_opt') changes that mountpoint's mount options
##   - a non-overridden mountpoint ('/etc') is unaffected
##   - a drop-in that RELAXES options (removes an option) also takes effect

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
    fail "${desc}: expected '${needle}' in: ${haystack}"
  fi
}

assert_absent() {
  local desc="$1" haystack="$2" needle="$3"
  if [[ "${haystack}" == *"${needle}"* ]]; then
    fail "${desc}: did not expect '${needle}' in: ${haystack}"
  fi
}

stub_dir="$(mktemp --directory -t rs-override-stub.XXXXXX)"
helper_dir="$(mktemp --directory -t rs-override-helper.XXXXXX)"
dropin_dir="$(mktemp --directory -t rs-override-dropin.XXXXXX)"
run_dir="$(mktemp --directory -t rs-override-run.XXXXXX)"
mount_log="$(mktemp -t rs-override-mount.XXXXXX)"
cleanup() {
  safe-rm --recursive --force -- \
    "${stub_dir}" "${helper_dir}" "${dropin_dir}" "${run_dir}"
  safe-rm --force -- "${mount_log}"
}
trap cleanup EXIT

## id -> root; findmnt -> mounted; mount -> record the invocation.
printf '%s\n' '#!/bin/bash' 'exit 0' > "${stub_dir}/findmnt"
cat > "${stub_dir}/id" <<'STUB'
#!/bin/bash
[ "${1:-}" = "-u" ] && { printf '%s\n' 0; exit 0; }
exit 0
STUB
cat > "${stub_dir}/mount" <<STUB
#!/bin/bash
printf '%s\n' "\$*" >> "${mount_log}"
exit 0
STUB
chmod 0755 -- "${stub_dir}/id" "${stub_dir}/findmnt" "${stub_dir}/mount"

## Stub source_config: source every '*.conf' in the given dirs into the current
## shell. The REAL source_config adds ownership/mode/symlink + 'bash -n' hardening
## (tested in the helper-scripts suite); here we only exercise that a sourced
## redefinition reaches the dispatch.
mkdir --parents -- "${helper_dir}/usr/libexec/helper-scripts"
cat > "${helper_dir}/usr/libexec/helper-scripts/source_folder.bsh" <<'STUB'
source_config() {
  local d f
  for d in "$@"; do
    [ -d "${d}" ] || continue
    for f in "${d}"/*.conf; do
      [ -e "${f}" ] || continue
      # shellcheck disable=SC1090
      source "${f}"
    done
  done
  return 0
}
STUB

## Drop-in: redefine '_opt' to HARDEN (add noexec,ro) and '_srv' to RELAX
## (drop nodev). '/etc' is left alone as the untouched baseline.
cat > "${dropin_dir}/50_override.conf" <<'CONF'
remount_secure_level=3
_opt() {
  mount_folder="/opt"
  intended_mount_options="nosuid,nodev,noexec,ro"
  remount_secure
}
_srv() {
  mount_folder="/srv"
  intended_mount_options="nosuid"
  remount_secure
}
CONF

PATH="${stub_dir}:${PATH}" \
  HELPER_SCRIPTS_PATH="${helper_dir}" \
  remount_secure_etc_dropin_dir="${dropin_dir}" \
  remount_secure_local_dropin_dir="/nonexistent" \
  remount_secure_runtime_dir="${run_dir}" \
  remount_secure_cmdline_file=/dev/null \
  bash -- "${rs_bin}" >/dev/null 2>&1 || fail "remount-secure exited non-zero with a drop-in override."

log="$(cat -- "${mount_log}")"
[ -n "${log}" ] || fail "no mount invocations recorded (dispatch did not run)."

opt_line="$(printf '%s\n' "${log}" | grep -- ' /opt$')" || fail "no /opt mount recorded."
assert_contains 'opt override hardens' "${opt_line}" 'nosuid,nodev,noexec,ro'

srv_line="$(printf '%s\n' "${log}" | grep -- ' /srv$')" || fail "no /srv mount recorded."
assert_contains 'srv override relaxes' "${srv_line}" 'remount,nosuid /srv'
assert_absent 'srv override dropped nodev' "${srv_line}" 'nodev'

etc_line="$(printf '%s\n' "${log}" | grep -- ' /etc$')" || fail "no /etc mount recorded."
assert_contains 'etc baseline untouched' "${etc_line}" 'nosuid,nodev'
assert_absent 'etc not overridden' "${etc_line}" 'noexec'

printf '%s\n' "PASS: remount-secure drop-in function override"
