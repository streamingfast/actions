#!/usr/bin/env bash
# Publish the scan report of an image: job summary, and on a pull_request a comment created or updated in place.
#
# Usage: comment.sh <image> <report.md>
# Env: GH_TOKEN, GITHUB_REPOSITORY, GITHUB_EVENT_NAME, GITHUB_STEP_SUMMARY, PR_NUMBER (pull_request only)
set -euo pipefail

image="${1:?image required}"
report="${2:?report required}"

# No report when the scanner could not run (infra failure)
[[ -s "${report}" ]] || exit 0

{
  echo "## Image scan (${image})"
  echo
  cat "${report}"
} >>"${GITHUB_STEP_SUMMARY:?}"

[[ "${GITHUB_EVENT_NAME:-}" == "pull_request" ]] || exit 0

# The image is in the marker so a matrix (one image per architecture) does not overwrite itself.
# `--` would end the HTML comment early, so runs of dashes collapse.
marker="<!-- image-scan:$(sed -E 's/-+/-/g' <<<"${image}") -->"
# PR comments cap at 65536 chars, iconv drops a multibyte character cut in half by the truncation
body="$(
  printf '%s\n## Image scan (%s)\n\n' "${marker}" "${image}"
  # iconv still exits 1 on the partial character it drops
  head -c 60000 "${report}" | { iconv -c -f UTF-8 -t UTF-8 2>/dev/null || true; }
)"
pr="${PR_NUMBER:?}"
repo="${GITHUB_REPOSITORY:?}"

comment_id="$(gh api --paginate "repos/${repo}/issues/${pr}/comments" |
  jq -r --arg marker "${marker}" '.[] | select(.body | startswith($marker)) | .id' | head -n1)"
if [[ -n "${comment_id}" ]]; then
  gh api -X PATCH "repos/${repo}/issues/comments/${comment_id}" -f body="${body}" >/dev/null
else
  gh api -X POST "repos/${repo}/issues/${pr}/comments" -f body="${body}" >/dev/null
fi
