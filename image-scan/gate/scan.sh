#!/usr/bin/env bash
# Scan the image, name the CVEs, apply the VEX exceptions and enforce (or not) the result.
#
# Usage: scan.sh <image> <report.md> [comment.md]
#
# <report.md> is what comment.sh publishes in the job summary, always in full: the CVE table, the CVEs suppressed by
# the VEX documents with their justification, then the scanner's own markdown report.
#
# [comment.md] is what comment.sh publishes in the pull request comment, quieter: on findings the same without the scanner
# report in the open (a collapsed <details> block), on a clean scan one line (with the CVEs accepted via VEX collapsed), which
# comment.sh only posts to update the comment of an earlier failing run.
#
# Runs the scanner up to 3 times: 1. markdown report, exit code (with the VEX documents), 2. on findings, the SARIF report with
# the same documents to name the CVEs, 3. with vex-location, the SARIF report WITHOUT the documents: what disappeared from the
# second is what the documents suppress. Only the first decides the outcome, the others are best effort (the scanner failing
# there only drops the tables, with a warning).
#
# Exit codes: those of lib/scanner.sh (0 clean, 2 findings, 10 infra failure). With enforce=false findings exit 0, they are
# warnings, and the infra failures still fail: nothing is known about the image.
#
# Env: IMAGE_SCAN_ENFORCE (default true), IMAGE_SCAN_VEX_LOCATION, and those of lib/scanner.sh.
# Writes `findings=true|false` to $GITHUB_OUTPUT (before exiting, also on exit 2).
set -uo pipefail

image="${1:?image required}"
report="${2:?report required}"
comment="${3:-}"

here="$(dirname "${BASH_SOURCE[0]}")"
scanner="${here}/../lib/scanner.sh"
# shellcheck source=../lib/report.sh
source "${here}/../lib/report.sh"

enforce="${IMAGE_SCAN_ENFORCE:-true}"
enforce="$(tr '[:upper:]' '[:lower:]' <<<"${enforce}")"
if [[ "${enforce}" != true && "${enforce}" != false ]]; then
  echo "::error::enforce must be true or false, got '${IMAGE_SCAN_ENFORCE}'"
  exit 1
fi
vex_location="${IMAGE_SCAN_VEX_LOCATION:-}"

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/image-scan-XXXXXX")"
trap 'rm -rf "${work}"' EXIT

# 1. The decision
level=error
if [[ "${enforce}" == false ]]; then level=warning; fi
IMAGE_SCAN_FINDINGS_LEVEL="${level}" "${scanner}" "${image}" "${work}/scout.md"
rc=$?
if [[ "${rc}" -ne 0 && "${rc}" -ne 2 ]]; then
  exit "${rc}"
fi

# 2. and 3. The CVEs, best effort
sarif_pass() { # sarif_pass <output> [no-vex]: findings rows on stdout, [] when the scanner could not tell
  local out="$1" code=0
  if [[ "${2:-}" == no-vex ]]; then
    IMAGE_SCAN_VEX_LOCATION="" IMAGE_SCAN_FINDINGS_LEVEL=debug "${scanner}" "${image}" "${out}" sarif >&2 || code=$?
  else
    IMAGE_SCAN_FINDINGS_LEVEL=debug "${scanner}" "${image}" "${out}" sarif >&2 || code=$?
  fi
  if [[ "${code}" -ne 0 && "${code}" -ne 2 ]]; then
    echo "::warning::Cannot list the CVEs of ${image}: the scanner failed (exit ${code}), the report has no CVE table" >&2
    return 1
  fi
  sarif_findings "${out}"
}

active='[]'
if [[ "${rc}" -eq 2 ]]; then
  active="$(sarif_pass "${work}/active.sarif")" || active='[]'
  if [[ "$(jq length <<<"${active}")" -eq 0 ]]; then
    echo "::warning::The scanner reported vulnerabilities in ${image} but none could be read from its SARIF report, see the scanner report"
  fi
fi

suppressed='[]'
if [[ -n "${vex_location}" ]]; then
  statements="$(vex_statements "${vex_location}")"
  if all="$(sarif_pass "${work}/all.sarif" no-vex)"; then
    suppressed="$(suppressed_findings "${all}" "${active}" "${statements}" "${image}")"
    # A statement that cannot work must be seen, not trusted
    while IFS= read -r line; do
      [[ -n "${line}" ]] && echo "::warning::${line}"
    done < <(jq -r '.[] | "VEX statement for \(if .id == "" then "?" else .id end) in \(.file) has status \(.status | if . == "" then "none" else . end): only not_affected suppresses a CVE, this one is ignored"' <<<"$(ineffective_statements "${statements}")")
    stale="$(stale_statements "${all}" "${statements}")"
    while IFS= read -r line; do
      [[ -n "${line}" ]] && echo "::notice::${line}"
    done < <(jq -r --arg image "${image}" '.[] | "VEX statement for \(.id) in \(.file) matches no critical/high finding of \($image), remove it if the fix shipped"' <<<"${stale}")
  fi
fi

# The log: findings and exceptions by name
findings=false
if [[ "${rc}" -eq 2 ]]; then findings=true; fi
if [[ "$(jq length <<<"${active}")" -gt 0 ]]; then
  echo "Vulnerabilities of ${image}:"
  findings_text "${active}"
fi
if [[ "$(jq length <<<"${suppressed}")" -gt 0 ]]; then
  echo "Suppressed by the VEX documents of ${vex_location} ($(jq length <<<"${suppressed}")), not counted above:"
  suppressed_text "${suppressed}"
  echo "::notice::$(jq length <<<"${suppressed}") vulnerabilities of ${image} are suppressed by the VEX documents of ${vex_location}: $(jq -r 'map(.id) | join(", ")' <<<"${suppressed}")"
fi

# The report: what a reader needs first, then the scanner's own
{
  if [[ "${rc}" -eq 2 && "${enforce}" == false ]]; then
    echo "> [!WARNING]"
    echo "> Advisory mode (\`enforce: false\`): the vulnerabilities below do not fail the build."
    echo
  fi
  if [[ "$(jq length <<<"${active}")" -gt 0 ]]; then
    echo "### Vulnerabilities ($(jq length <<<"${active}"))"
    echo
    findings_markdown "${active}"
    echo
  fi
  if [[ "$(jq length <<<"${suppressed}")" -gt 0 ]]; then
    echo "### Suppressed by VEX ($(jq length <<<"${suppressed}"))"
    echo
    echo "Not counted as findings: the statements of \`${vex_location}\` mark them not affected. Each one must link its \`risk-accepted\` issue and go away when the fix ships."
    echo
    suppressed_markdown "${suppressed}"
    echo
  fi
  # Nothing more to tell when only the scanner's report is left
  if [[ "$(jq length <<<"${active}")" -gt 0 || "$(jq length <<<"${suppressed}")" -gt 0 || ( "${rc}" -eq 2 && "${enforce}" == false ) ]]; then
    echo "### Scanner report"
    echo
  fi
  cat "${work}/scout.md"
} >"${report}"

if [[ -n "${comment}" ]]; then
  suppressed_count="$(jq length <<<"${suppressed}")"
  {
    if [[ "${rc}" -eq 0 ]]; then
      severities="$(tr -d ' ' <<<"${IMAGE_SCAN_SEVERITIES:-critical,high}" | tr '[:upper:]' '[:lower:]' | tr ',' '/')"
      # The scanner's report names the digest, no extra call for it
      digest="$(grep -m1 -oE 'sha256:[0-9a-f]{64}' "${work}/scout.md" || true)"
      line="✅ Image scan: no ${severities} vulnerabilities in ${image}"
      if [[ -n "${digest}" ]]; then line+=" (${digest:7:12})"; fi
      if [[ "${suppressed_count}" -gt 0 ]]; then line+=", ${suppressed_count} accepted via VEX"; fi
      echo "${line}"
      if [[ "${suppressed_count}" -gt 0 ]]; then
        echo
        echo "<details><summary>Accepted via VEX (${suppressed_count})</summary>"
        echo
        echo "The statements of \`${vex_location}\` mark them not affected. Each one must link its \`risk-accepted\` issue and go away when the fix ships."
        echo
        suppressed_markdown "${suppressed}"
        echo
        echo "</details>"
      fi
    else
      if [[ "${enforce}" == false ]]; then
        echo "> [!WARNING]"
        echo "> Advisory mode (\`enforce: false\`): the vulnerabilities below do not fail the build."
        echo
      fi
      if [[ "$(jq length <<<"${active}")" -gt 0 ]]; then
        echo "### Vulnerabilities ($(jq length <<<"${active}"))"
        echo
        findings_markdown "${active}"
        echo
      fi
      if [[ "${suppressed_count}" -gt 0 ]]; then
        echo "### Accepted via VEX (${suppressed_count})"
        echo
        suppressed_markdown "${suppressed}"
        echo
      fi
      echo "<details><summary>Scanner report</summary>"
      echo
      cat "${work}/scout.md"
      echo
      echo "</details>"
    fi
  } >"${comment}"
fi

echo "findings=${findings}" >>"${GITHUB_OUTPUT:?}"

if [[ "${rc}" -eq 2 && "${enforce}" == false ]]; then
  echo "::warning::Advisory mode (enforce: false): ${image} has vulnerabilities, the build is not failed"
  exit 0
fi
exit "${rc}"
