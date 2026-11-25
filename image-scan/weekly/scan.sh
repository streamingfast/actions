#!/usr/bin/env bash
# Scan <repository>:<tag>-<arch> for every architecture and write the findings, one entry per CVE, to <findings.json>:
#   [{"id": "CVE-2025-0001", "severity": "critical|high", "images": ["ghcr.io/..."]}, ...]
#
# Usage: scan.sh <image-repository> <release-tag> <architectures (space separated)> <findings.json>
#
# Exits with the scanner's code on an infra failure (10), or 11 when findings cannot be read from the report,
# so no findings file is written for a partial scan.
# With IMAGE_SCAN_VEX_LOCATION the documents apply (see ../lib/scanner.sh): a suppressed CVE is not a finding, so it opens no issue.
# Env: same as ../lib/scanner.sh, plus RUNNER_TEMP (reports) and GITHUB_STEP_SUMMARY.
set -euo pipefail

repository="${1:?image repository required}"
tag="${2:?release tag required}"
architectures="${3:?architectures required}"
output="${4:?findings file required}"

here="$(dirname "${BASH_SOURCE[0]}")"
scanner="${here}/../lib/scanner.sh"
# shellcheck source=../lib/report.sh
source "${here}/../lib/report.sh"
vex_location="${IMAGE_SCAN_VEX_LOCATION:-}"
tmp="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
# The weekly scan always tracks critical and high only: severity labels and due dates do not exist below
export IMAGE_SCAN_SEVERITIES="critical,high"

findings='[]'
suppressed='[]'
# shellcheck disable=SC2086 # word splitting of the architecture list is intended
for arch in ${architectures}; do
  image="${repository}:${tag}-${arch}"
  report="${tmp}/image-scan-${arch}.sarif"
  rm -f "${report}"

  rc=0
  "${scanner}" "${image}" "${report}" sarif || rc=$?
  if [[ "${rc}" -ne 0 && "${rc}" -ne 2 ]]; then
    exit "${rc}"
  fi

  # What the VEX documents suppress on this image (best effort, it only completes the summary): the findings without the
  # documents that the scan above, with them, does not report. The scan above alone decides which issues are open.
  if [[ -n "${vex_location}" ]]; then
    all_report="${tmp}/image-scan-${arch}-all.sarif"
    rm -f "${all_report}"
    all_rc=0
    IMAGE_SCAN_VEX_LOCATION="" IMAGE_SCAN_FINDINGS_LEVEL=debug "${scanner}" "${image}" "${all_report}" sarif >/dev/null || all_rc=$?
    if [[ "${all_rc}" -eq 0 || "${all_rc}" -eq 2 ]]; then
      active='[]'
      if [[ "${rc}" -eq 2 ]]; then active="$(sarif_findings "${report}")"; fi
      arch_suppressed="$(suppressed_findings "$(sarif_findings "${all_report}")" "${active}" "$(vex_statements "${vex_location}")")"
      suppressed="$(jq -nc --argjson a "${suppressed}" --argjson b "${arch_suppressed}" --arg image "${image}" '$a + ($b | map(. + {image: $image}))')"
    else
      echo "::warning::Cannot list the CVEs suppressed by the VEX documents on ${image} (scanner exit ${all_rc})"
    fi
  fi

  if [[ "${rc}" -eq 2 ]]; then
    if [[ ! -s "${report}" ]]; then
      echo "::error::The scanner reported findings for ${image} but wrote no report"
      exit 11
    fi
    # SARIF: one rule per CVE, `id` is the CVE id. Severity comes from `properties.cvssV3_severity`, else the numeric
    # `properties.security-severity` (>= 9.0 is critical), else `high` (the scan is already limited to critical,high).
    # Rules missing from the driver fall back to the ruleId of the results.
    arch_findings="$(jq --arg image "${image}" '
      def severity:
        ((.properties.cvssV3_severity // "") | ascii_downcase) as $level
        | ((.properties["security-severity"] // "") | tonumber? // null) as $score
        | if $level == "critical" or ($level == "" and $score != null and $score >= 9) then "critical" else "high" end;
      (([.runs[].tool.driver.rules[]? | {id: .id, severity: severity}])) as $rules
      | ([.runs[].results[]?.ruleId] | unique | map({id: ., severity: "high"})) as $fromResults
      | ($rules + $fromResults | group_by(.id) | map(.[0]))
      | map(. + {images: [$image]})' "${report}")"
    # Findings that cannot be parsed must fail the job: an empty list would close every open issue
    if [[ "$(jq length <<<"${arch_findings}")" -eq 0 ]]; then
      echo "::error::The scanner reported findings for ${image} but none could be read from its SARIF report"
      exit 11
    fi
    findings="$(jq -n --argjson a "${findings}" --argjson b "${arch_findings}" '$a + $b')"
  fi
done

# One entry per CVE across architectures (most severe wins)
jq 'group_by(.id) | map({
      id: .[0].id,
      severity: (if any(.[]; .severity == "critical") then "critical" else "high" end),
      images: (map(.images[]) | unique)
    })' <<<"${findings}" >"${output}"

jq -r '"Findings: \(length)"' "${output}"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Image scan of ${repository}:${tag}"
    echo
    jq -r 'if length == 0 then "No critical/high vulnerability." else (.[] | "- \(.id) (\(.severity))") end' "${output}"
    if [[ "$(jq length <<<"${suppressed}")" -gt 0 ]]; then
      echo
      echo "Suppressed by the VEX documents of \`${vex_location}\`, no issue opened:"
      echo
      jq -r 'group_by(.id) | .[] | "- \(.[0].id) (\(.[0].severity)) \(.[0].package) \(.[0].installed)\(if .[0].status == "" then "" else ": " + (.[0].justification | if . == "" then "no justification" else . end) + (if .[0].impact == "" then "" else " - " + .[0].impact end) end) [\(map(.image) | join(", "))]"' <<<"${suppressed}"
    fi
  } >>"${GITHUB_STEP_SUMMARY}"
fi
