#!/usr/bin/env bash
# Audited emergency bypass of the scan.
#
# Usage: skip.sh decide|record
#
#   decide   Writes `skip=true|false` to $GITHUB_OUTPUT. The scan is bypassed only when SKIP_REASON is not blank AND the
#            event is workflow_dispatch (a person triggered the run). On any other event the reason is ignored, with a
#            warning, and the scan runs normally: a misconfigured workflow must not bypass the gate.
#   record   Audit trail of a bypass: `::warning::`, a job summary section and a GitHub issue (opened, or commented when
#            one is already open for that image@digest). Never fails: the issue is best-effort (missing `issues: write`
#            permission, ...) since the warning and the job summary are always recorded.
#
# Env:
#   SKIP_REASON      the reason of the bypass
#   IMAGE, DIGEST    image and its digest (record only, DIGEST may be empty when it could not be resolved)
#   GH_TOKEN         token creating the issue (record only), needs issues: write
#   GITHUB_EVENT_NAME, GITHUB_ACTOR, GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_RUN_ID, GITHUB_OUTPUT, GITHUB_STEP_SUMMARY
set -uo pipefail

mode="${1:?decide or record required}"

# Trim, a blank reason is no reason
reason="${SKIP_REASON:-}"
reason="${reason#"${reason%%[![:space:]]*}"}"
reason="${reason%"${reason##*[![:space:]]}"}"

# One line, for workflow commands (a newline would end the ::warning:: message)
oneline() {
  local s="${1//%/%25}"
  s="${s//$'\r'/%0D}"
  echo "${s//$'\n'/ }"
}

case "${mode}" in
  decide)
    skip=false
    if [[ -n "${reason}" ]]; then
      if [[ "${GITHUB_EVENT_NAME:-}" == "workflow_dispatch" ]]; then
        skip=true
      else
        echo "::warning::skip-reason is ignored on a ${GITHUB_EVENT_NAME:-unknown} event, the scan runs: the scan can only be skipped on a manual workflow_dispatch run"
      fi
    fi
    echo "skip=${skip}" >>"${GITHUB_OUTPUT:?}"
    ;;

  record)
    image="${IMAGE:?image required}"
    digest="${DIGEST:-}"
    actor="${GITHUB_ACTOR:-unknown}"
    repo="${GITHUB_REPOSITORY:?}"
    run_url="${GITHUB_SERVER_URL:-https://github.com}/${repo}/actions/runs/${GITHUB_RUN_ID:-0}"
    when="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    digest_text="${digest:-unresolved}"

    # sha256:<64 hex> -> 12 hex
    short="${digest#sha256:}"
    short="${short::12}"
    title="Image scan skipped: ${image}@${short:-unresolved}"
    # Hidden marker, one issue per image@digest. `--` would end the HTML comment early, so runs of dashes collapse.
    marker="<!-- image-scan-skipped:$(sed -E 's/-+/-/g' <<<"${image}@${digest}") -->"

    echo "::warning::Image scan SKIPPED for ${image}@${digest_text} by ${actor}: $(oneline "${reason}") (${run_url})"

    details="$(
      printf -- '- **Image:** `%s`\n' "${image}"
      printf -- '- **Digest:** `%s`\n' "${digest_text}"
      printf -- '- **Skipped by:** @%s\n' "${actor}"
      printf -- '- **Time:** %s\n' "${when}"
      printf -- '- **Run:** %s\n' "${run_url}"
      printf -- '- **Reason:**\n\n'
      sed 's/^/  > /' <<<"${reason}"
    )"

    {
      echo "## Image scan skipped (${image})"
      echo
      echo "The vulnerability scan was bypassed with \`skip-reason\`, an audited exception."
      echo
      echo "${details}"
    } >>"${GITHUB_STEP_SUMMARY:?}"

    issue_body="$(
      printf '%s\n' "${marker}"
      echo "The vulnerability scan of this image was **skipped** with an audited emergency bypass (\`skip-reason\`)."
      echo
      echo "${details}"
      echo
      echo "**Follow up:** scan this image as soon as possible (re-run the scan, or the \`image-scan/gate\` workflow without \`skip-reason\`), fix or document the findings, then close this issue."
    )"

    issue_failed() { echo "::warning::Cannot record the skipped scan as a GitHub issue ($1), the warning and the job summary are the only record. Does the token have issues: write?"; exit 0; }

    # Best-effort, the labels may exist already
    for label in security image-scan-skipped; do
      gh label create "${label}" --repo "${repo}" >/dev/null 2>&1 || true
    done

    open_issues="$(gh issue list --repo "${repo}" --label image-scan-skipped --state open --limit 200 --json number,body)" || issue_failed "listing the issues"
    existing="$(jq -r --arg marker "${marker}" '[.[] | select(.body | contains($marker)) | .number] | first // empty' <<<"${open_issues}")" || issue_failed "reading the issues"

    if [[ -n "${existing}" ]]; then
      comment="$(
        echo "The scan of this image was skipped again."
        echo
        echo "${details}"
      )"
      gh issue comment "${existing}" --repo "${repo}" --body "${comment}" >/dev/null || issue_failed "commenting #${existing}"
      echo "Updated issue #${existing}"
    else
      url="$(gh issue create --repo "${repo}" --title "${title}" --label security --label image-scan-skipped --body "${issue_body}")" || issue_failed "creating the issue"
      echo "Opened ${url}"
    fi
    ;;

  *)
    echo "::error::unknown mode '${mode}'"
    exit 1
    ;;
esac
