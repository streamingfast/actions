#!/usr/bin/env bash
# Decide whether the scan runs, writes `scan=true|false` to $GITHUB_OUTPUT.
#
# Always scans, except on a pull_request with SCAN_PATHS set: then it scans only when the files changed by the
# pull request match one of the SCAN_PATHS lines (one extended regex per line, anchor with ^).
# On a pull_request the checkout is the merge commit, `HEAD^1` is the base branch: the caller needs fetch-depth: 2.
set -euo pipefail

scan=true
paths="${SCAN_PATHS:-}"

if [[ "${GITHUB_EVENT_NAME:-}" == "pull_request" && -n "${paths//[[:space:]]/}" ]]; then
  patterns="$(mktemp)"
  # Blank lines would match every file
  grep -v '^[[:space:]]*$' <<<"${paths}" >"${patterns}"

  # grep exits 2 on an invalid pattern, which `if grep` would read as "no match": fail closed instead
  rc=0
  grep -Eq -f "${patterns}" /dev/null || rc=$?
  if [[ "${rc}" -gt 1 ]]; then
    echo "::error::scan-paths holds an invalid regular expression"
    exit 1
  fi

  if ! changed="$(git diff --name-only HEAD^1 HEAD)"; then
    echo "::error::Cannot diff HEAD^1 HEAD, check that the checkout uses fetch-depth: 2"
    exit 1
  fi

  if grep -Eq -f "${patterns}" <<<"${changed}"; then
    echo "Image-affecting files changed, scanning"
  else
    echo "No image-affecting file changed, skipping scan"
    scan=false
  fi
  rm -f "${patterns}"
fi

echo "scan=${scan}" >>"${GITHUB_OUTPUT:?}"
