#!/usr/bin/env bash
# Sync GitHub issues with a findings list: one issue per CVE, deduped by the hidden marker `<!-- image-scan-cve:ID -->`.
#
# Usage: issues.sh <release-tag> <findings.json>
#   findings.json: [{"id": "CVE-2025-0001", "severity": "critical|high", "images": ["ghcr.io/..."]}, ...]
#   This must be the findings of a COMPLETE scan of the latest release (all architectures), otherwise
#   CVEs would be closed wrongly.
#
# Env: GH_TOKEN (issues: write), GITHUB_REPOSITORY, optional SLACK_MESSAGE_FILE (written when issues were opened)
#
# - new CVE            -> issue opened (labels security + severity:*), due date critical +7d, high +30d
# - known CVE          -> issue title/body refreshed, due date kept; skipped when labelled `risk-accepted`
#                         (open or closed: closing a risk-accepted issue does not open a new one)
# - CVE no longer seen -> open issue(s) closed with the release it was fixed in
#
# The Slack message file is appended as each issue is opened, so a later failure does not lose the announcement.
set -euo pipefail

tag="${1:?release tag required}"
findings="${2:?findings file required}"
repo="${GITHUB_REPOSITORY:?}"
slack_file="${SLACK_MESSAGE_FILE:-}"

# `date -d` is GNU only (ubuntu runners), fall back to BSD `date -v` so the script also runs on macOS.
due_date() {
  date -u -d "+$1 days" +%F 2>/dev/null || date -u -v "+$1d" +%F
}

for label in "security:B60205" "severity:critical:B60205" "severity:high:D93F0B" "risk-accepted:FBCA04"; do
  gh label create "${label%:*}" --color "${label##*:}" --repo "${repo}" >/dev/null 2>&1 || true
done

release_date="$(gh release view "${tag}" --repo "${repo}" --json publishedAt --jq '.publishedAt[:10]' 2>/dev/null || date -u +%F)"

# Issues of the scan (open and closed) with their CVE id from the hidden marker
all_issues="$(gh issue list --repo "${repo}" --label security --state all --limit 1000 \
  --json number,state,body,labels |
  jq 'map(. + {cve: (try (.body | capture("<!-- image-scan-cve:(?<id>[^ ]+) -->").id) catch null)})
      | map(select(.cve != null))')"
# Open ones as an array (all get closed when fixed), and keyed by CVE id (one gets refreshed)
open_list="$(jq -c 'map(select(.state == "OPEN"))' <<<"${all_issues}")"
# the one kept per CVE is the oldest, a risk-accepted one first (INDEX keeps the last of a sort)
open_issues="$(jq -c 'sort_by([any(.labels[]; .name == "risk-accepted"), -.number]) | INDEX(.cve)' <<<"${open_list}")"
# CVE ids whose issue, open or closed, is risk-accepted
accepted_ids="$(jq -c 'map(select(any(.labels[]; .name == "risk-accepted")) | .cve) | unique' <<<"${all_issues}")"

count=0
announce() { # announce <line>: header of the message is rewritten each time with the count
  count=$((count + 1))
  [[ -n "${slack_file}" ]] || return 0
  printf '%s\n' "$1" >>"${slack_file}.lines"
  {
    echo ":warning: *${repo}* image scan found ${count} new critical/high CVE(s) in \`${tag}\`:"
    cat "${slack_file}.lines"
  } >"${slack_file}"
}
if [[ -n "${slack_file}" ]]; then rm -f "${slack_file}" "${slack_file}.lines"; fi

while IFS= read -r finding; do
  id="$(jq -r .id <<<"${finding}")"
  severity="$(jq -r .severity <<<"${finding}")"
  images="$(jq -r '.images | map("`" + . + "`") | join(", ")' <<<"${finding}")"
  existing="$(jq -c --arg id "${id}" '.[$id] // empty' <<<"${open_issues}")"

  if [[ -n "${existing}" ]]; then
    number="$(jq -r .number <<<"${existing}")"
    # Extra open issues of the same CVE
    while IFS= read -r duplicate; do
      gh issue close "${duplicate}" --repo "${repo}" --comment "Duplicate of #${number}." >/dev/null
      echo "${id}: closed duplicate #${duplicate}"
    done < <(jq -r --arg id "${id}" --argjson keep "${number}" '.[] | select(.cve == $id and .number != $keep) | .number' <<<"${open_list}")
    if jq -e 'any(.labels[]; .name == "risk-accepted")' <<<"${existing}" >/dev/null; then
      echo "${id}: #${number} is risk-accepted, skipping"
      continue
    fi
    # Due date of the first detection, recomputed from the severity if the body lost it
    due="$(jq -r '.body | capture("\\*\\*Due date:\\*\\* (?<d>[0-9-]+)").d // empty' <<<"${existing}")"
    [[ -n "${due}" ]] || due="$(due_date "$([[ "${severity}" == critical ]] && echo 7 || echo 30)")"
    gh issue edit "${number}" --repo "${repo}" --add-label "severity:${severity}" \
      --title "Image scan: ${id} (${severity})" \
      --body "$(
        cat <<BODY
<!-- image-scan-cve:${id} -->
The image scan reports **${id}** (${severity}) in release \`${tag}\` (last seen $(date -u +%F)).

- **Due date:** ${due}
- **Affected images:** ${images}

Closed automatically once a release no longer reports it. Add the \`risk-accepted\` label to stop tracking.
This description is rewritten on every scan, discuss in comments.
BODY
      )" >/dev/null
    for other in critical high; do
      [[ "${other}" == "${severity}" ]] || gh issue edit "${number}" --repo "${repo}" --remove-label "severity:${other}" >/dev/null 2>&1 || true
    done
    echo "${id}: updated #${number}"
    continue
  fi

  if jq -e --arg id "${id}" 'index($id) != null' <<<"${accepted_ids}" >/dev/null; then
    echo "${id}: has a risk-accepted issue, skipping"
    continue
  fi

  days=30
  [[ "${severity}" == "critical" ]] && days=7
  due="$(due_date "${days}")"
  url="$(gh issue create --repo "${repo}" \
    --title "Image scan: ${id} (${severity})" \
    --label security --label "severity:${severity}" \
    --body "$(
      cat <<BODY
<!-- image-scan-cve:${id} -->
The image scan reports **${id}** (${severity}) in release \`${tag}\`.

- **Due date:** ${due}
- **Affected images:** ${images}

Closed automatically once a release no longer reports it. Add the \`risk-accepted\` label to stop tracking.
BODY
    )")"
  echo "${id}: opened ${url}"
  announce "• <${url}|${id}> (${severity}), due ${due}"
done < <(jq -c '.[]' "${findings}")

# Close issues whose CVE is not reported by the latest release anymore
while IFS= read -r issue; do
  id="$(jq -r .cve <<<"${issue}")"
  number="$(jq -r .number <<<"${issue}")"
  if jq -e --arg id "${id}" 'any(.[]; .id == $id)' "${findings}" >/dev/null; then
    continue
  fi
  gh issue close "${number}" --repo "${repo}" \
    --comment "${id} is not reported anymore by the image scan in latest release \`${tag}\` (published ${release_date}). Closing as remediated." >/dev/null
  # A fixed CVE that comes back later must be tracked again
  gh issue edit "${number}" --repo "${repo}" --remove-label risk-accepted >/dev/null 2>&1 || true
  echo "${id}: closed #${number}"
done < <(jq -c '.[]' <<<"${open_list}")

if [[ -n "${slack_file}" ]]; then rm -f "${slack_file}.lines"; fi
