#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## CodeQL pre-init source-tree prep.
##
## This repo names installable files with a '#<package-tag>' suffix
## (Kicksecure/genmkfile convention - the suffix routes the file to
## the correct Debian binary package at build time). The suffix
## breaks two CodeQL paths:
##
##   * Python extractor discovers source files by the '.py'
##     extension; 'foo.py#security-misc-shared' is invisible.
##   * gcc selects driver behavior by extension; 'foo.c#tag' is
##     treated by ld as a linker script ("file format not
##     recognized"). The compile helpers used by ci/codeql-build.sh
##     receive their .c source by path argument, so a clean
##     '.c'-extension symlink is required here too.
##
## Walk the tracked file list and create same-directory symlinks
## without the '#tag' suffix so both extractors and gcc see the
## source under its conventional name. Symlinks point at the
## original tagged file via basename so the link resolves regardless
## of how the tree is later moved.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

repo_root="$(git rev-parse --show-toplevel)"
cd -- "${repo_root}"

linked=0
copied=0
skipped=0
while IFS= read -r tagged; do
  ## Only files where the suffix immediately follows a known
  ## source-language extension. Other tagged files (config files,
  ## scripts without an extension, etc.) need no rename.
  case "${tagged}" in
    *'.py#'*|*'.c#'*|*'.h#'*)
      ;;
    *)
      continue
      ;;
  esac

  clean="${tagged%#*}"

  ## Do not clobber a real (untagged) file. CI runs on a fresh
  ## checkout, so 'clean' is only ever absent or a prior prepare
  ## artifact (a symlink, handled below).
  if [ -e "${clean}" ] && [ ! -L "${clean}" ]; then
    skipped=$((skipped + 1))
    continue
  fi

  case "${tagged}" in
    *'.h#'*)
      ## A HEADER becomes a real '.h' copy, never a symlink. CodeQL
      ## canonicalizes a symlinked #include target to the tagged
      ## realpath, whose extension is '.h#<tag>' (not a header), and
      ## 'Include header files only' (cpp/include-non-header) then
      ## flags every repo-local header include. A real '.h' copy has a
      ## genuine header extension. --remove-destination drops a stale
      ## symlink from a prior run first, so cp writes a file instead of
      ## writing THROUGH the link into the tagged source.
      cp --remove-destination -- "${tagged}" "${clean}"
      copied=$((copied + 1))
      ;;
    *)
      ## '.c'/'.py' are compiled/extracted by path (not an #include
      ## target), so a symlink is enough. Target is relative to the
      ## link's directory.
      target="$(basename -- "${tagged}")"
      ln -snf -- "${target}" "${clean}"
      linked=$((linked + 1))
      ;;
  esac
done < <(git ls-files -- '*.py#*' '*.c#*' '*.h#*')

printf '%s\n' \
  "codeql-prepare: linked=${linked} copied=${copied} skipped=${skipped}"
