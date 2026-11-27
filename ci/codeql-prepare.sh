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

## Create the clean-named artifact for one tagged source. Idempotent:
## safe to re-run on a dirty tree (ln -snf / cp --remove-destination both
## replace a prior-run artifact), so a changed tagged source is always
## re-propagated.
make_clean() {
  local tagged="$1"
  local clean="$2"
  local target

  ## Symlink target is relative to the link's directory.
  target="$(basename -- "${tagged}")"

  ## A HEADER needs a real '.h' copy, never a symlink: CodeQL
  ## canonicalizes a symlinked #include target to the tagged realpath,
  ## whose extension is '.h#<tag>' (not a header), so
  ## cpp/include-non-header flags every repo-local header include. A
  ## real '.h' copy has a genuine header extension. '.c'/'.py' are
  ## compiled/extracted by path (never an #include target), so a symlink
  ## is enough. Decide by the CLEAN name's real extension - a '.h#' can
  ## appear mid-path, so match the suffix, not a substring.
  case "${clean}" in
    *.h)
      ## Never dereference a symlinked SOURCE: cp would copy the
      ## referent's bytes into the tree (secret exfiltration) or hang on
      ## a device node. A tracked '.h#tag' symlink is pathological;
      ## degrade it to a symlink (--remove-destination clears a stale
      ## artifact so cp writes a file, not through a link).
      if [ -L "${tagged}" ]; then
        ln -snf -- "${target}" "${clean}"
        linked=$((linked + 1))
      else
        cp --remove-destination -- "${tagged}" "${clean}"
        copied=$((copied + 1))
      fi
      ;;
    *)
      ln -snf -- "${target}" "${clean}"
      linked=$((linked + 1))
      ;;
  esac
}

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

  ## Protect a genuinely TRACKED file at the clean path (a real
  ## untagged source we must not clobber). A prior-run artifact is
  ## untracked and gets refreshed, keeping the script idempotent.
  if git ls-files --error-unmatch -- "${clean}" >/dev/null 2>&1; then
    skipped=$((skipped + 1))
    continue
  fi

  make_clean "${tagged}" "${clean}"
done < <(git ls-files -- '*.py#*' '*.c#*' '*.h#*')

printf '%s\n' \
  "codeql-prepare: linked=${linked} copied=${copied} skipped=${skipped}"
