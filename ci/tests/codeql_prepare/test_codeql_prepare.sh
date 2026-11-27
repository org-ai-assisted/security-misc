#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for ci/codeql-prepare.sh. Builds a throwaway git repo
## of tagged source files, runs the script, and asserts:
##
## - a header '.h#<tag>' becomes a REAL '.h' copy (CodeQL flags a
##   symlinked #include target as a non-header);
## - a '.c#<tag>' / '.py#<tag>' becomes a symlink;
## - a '.c' whose path merely CONTAINS '.h#' stays a symlink (the arm
##   keys on the clean name's '.h' suffix, not a substring);
## - a symlinked SOURCE header is NOT dereferenced into the tree (no
##   secret exfiltration / device-node hang);
## - a genuinely tracked untagged file at the clean path is preserved;
## - a re-run on a dirty tree refreshes a changed header (idempotent).
##
## Pass an alternate script path as $1 to canary the test against an
## older codeql-prepare.sh (it must FAIL there).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

here="$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")"
prepare="${1:-${here}/../../codeql-prepare.sh}"
prepare="$(readlink -f -- "${prepare}")"

work="$(mktemp -d)"
## invoked indirectly via 'trap ... EXIT'
# shellcheck disable=SC2317
cleanup() {
  safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

fail=0
check() {
  local desc="$1"
  shift
  if "$@"; then
    printf '%s\n' "ok   ${desc}"
  else
    printf '%s\n' "FAIL ${desc}" >&2
    fail=1
  fi
}

cd -- "${work}"
git init -q .
git config user.email 'test@example.invalid'
git config user.name 'test'

mkdir -p 'usr' 'usr/d.h#x'
printf '%s\n' 'HDR_V1' > 'usr/foo.h#pkg'
printf '%s\n' 'SRC'    > 'usr/bar.c#pkg'
printf '%s\n' 'LOOSE'  > 'usr/d.h#x/baz.c#pkg'   ## '.h#' mid-path, clean name is a .c
printf '%s\n' 'SECRET' > 'usr/secret_target'     ## stands in for a sensitive file
ln -s 'secret_target' 'usr/evil.h#pkg'           ## symlinked SOURCE header
printf '%s\n' 'REAL'        > 'usr/real.h'       ## tracked untagged clean file
printf '%s\n' 'REAL_TAGGED' > 'usr/real.h#pkg'   ## collides with the tracked clean name

git add -A
git -c commit.gpgsign=false commit -qm 'fixture'

bash "${prepare}" >/dev/null

check 'header is a regular file'           test -f 'usr/foo.h'
check 'header is NOT a symlink'            test ! -L 'usr/foo.h'
check 'header content copied'              test "$(cat -- 'usr/foo.h')" = HDR_V1
check '.c is a symlink'                    test -L 'usr/bar.c'
check 'loose-glob .c stays a symlink'      test -L 'usr/d.h#x/baz.c'
check 'symlinked source not dereferenced'  test -L 'usr/evil.h'
check 'tracked clean file preserved'       test "$(cat -- 'usr/real.h')" = REAL
check 'tracked clean file still regular'   test ! -L 'usr/real.h'

## Idempotency: change the tagged header, re-run on the dirty tree, expect refresh.
printf '%s\n' 'HDR_V2' > 'usr/foo.h#pkg'
bash "${prepare}" >/dev/null
check 'header refreshed on re-run'         test "$(cat -- 'usr/foo.h')" = HDR_V2

if [ "${fail}" -ne 0 ]; then
  printf '%s\n' 'FAIL: codeql-prepare regression test' >&2
  exit 1
fi
printf '%s\n' 'PASS: codeql-prepare regression test'
