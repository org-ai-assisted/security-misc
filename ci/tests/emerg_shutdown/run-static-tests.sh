#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Build and run emerg-shutdown's host-only static tests: the panic-state unit
## test and the CBMC proof + canaries. No root, no uinput, no kernel module -
## safe to run anywhere a C toolchain and cbmc exist. The uinput integration
## test (test_keyboard_hotplug.py) is separate and needs root + /dev/uinput.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

export LC_ALL=C

here="$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")"
## ci/tests/emerg_shutdown -> repo root (no git dependency; see cbmc-run.sh).
repo_root="$(cd -- "${here}/../../.." && pwd)"
src_dir="${repo_root}/usr/src/security-misc"

build_dir="$(mktemp -d)"
## invoked indirectly via 'trap ... EXIT'
# shellcheck disable=SC2317
cleanup() {
  safe-rm --recursive --force -- "${build_dir}"
}
trap cleanup EXIT

ln -snf -- "${src_dir}/emerg-shutdown-panic-state.h#security-misc-shared" \
  "${build_dir}/emerg-shutdown-panic-state.h"

printf '%s\n' "=== unit: test_panic_state ==="
gcc -O2 -Wall -Wextra -Wconversion -Wshadow -std=gnu11 \
  -I "${build_dir}" "${here}/test_panic_state.c" \
  -o "${build_dir}/test_panic_state"
"${build_dir}/test_panic_state"

printf '%s\n' "=== cbmc proof + canaries ==="
bash "${here}/cbmc/cbmc-run.sh"

printf '%s\n' "PASS: emerg-shutdown static tests passed."
