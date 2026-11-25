#!/usr/bin/env bash
# Tests of the image-scan scripts with a fake docker and gh on PATH. Run: image-scan/tests/run.sh
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "${here}")"
failures=0
cases=0

ok() { cases=$((cases + 1)); }
check() { # check <description> <command...>
  local desc="$1"
  shift
  ok
  if "$@"; then echo "ok   - ${desc}"; else echo "FAIL - ${desc}"; failures=$((failures + 1)); fi
}
# shellcheck disable=SC2329 # the helpers are called through check
logged() { grep -q -- "$1" "${FAKE_DIR}/$2"; }
# shellcheck disable=SC2329
not_logged() { ! grep -q -- "$1" "${FAKE_DIR}/$2" 2>/dev/null; }
# shellcheck disable=SC2329
count() { [[ "$(grep -c -- "$1" "${FAKE_DIR}/$2" 2>/dev/null || true)" == "$3" ]]; }

setup() {
  FAKE_DIR="$(mktemp -d)"
  export FAKE_DIR PATH="${here}/bin:${PATH}"
  export RUNNER_TEMP="${FAKE_DIR}" GITHUB_OUTPUT="${FAKE_DIR}/output" GITHUB_STEP_SUMMARY="${FAKE_DIR}/summary"
  export GITHUB_REPOSITORY=o/r
  export IMAGE_SCAN_DOCKERHUB_USER=u IMAGE_SCAN_DOCKERHUB_PASSWORD=p IMAGE_SCAN_BACKOFF=0
  echo '[]' >"${FAKE_DIR}/issues.json"
  : >"${FAKE_DIR}/output"
}

# ---------------------------------------------------------------- scanner.sh
setup
"${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >/dev/null 2>&1
check "scanner: clean image exits 0" test $? -eq 0
check "scanner: passes severities" logged "--only-severity critical,high" docker.log
check "scanner: no --output nor bind mount of the report dir" not_logged -e "--output\|:/out" docker.log
check "scanner: stdout is the report, stderr stays out of it" test "$(cat "${FAKE_DIR}/r.md")" = "no findings"
check "scanner: passes the hub auth env by name" logged "hub_user=u" docker.log
check "scanner: passwords are not on the command line" not_logged "=p" docker.log
check "scanner: login uses a private docker config" logged "docker_config=/" docker.log

setup
IMAGE_SCAN_REGISTRY_USER=ru IMAGE_SCAN_REGISTRY_PASSWORD=rp "${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >/dev/null 2>&1
check "scanner: registry credentials passed by name" logged "-e DOCKER_SCOUT_REGISTRY_PASSWORD" docker.log
check "scanner: registry user reaches the container env" logged "registry_user=ru" docker.log
check "scanner: registry password is not on the command line" not_logged "=rp" docker.log

setup
IMAGE_SCAN_REGISTRY_USER="" IMAGE_SCAN_REGISTRY_PASSWORD="" "${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >/dev/null 2>&1
check "scanner: works without registry credentials" test $? -eq 0
check "scanner: empty registry credentials are not passed" not_logged "DOCKER_SCOUT_REGISTRY" docker.log

for bad in 0 abc -1; do
  setup
  IMAGE_SCAN_RETRIES="${bad}" "${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >/dev/null 2>&1
  check "scanner: retries '${bad}' is rejected" test $? -eq 1
done

setup
echo 2 >"${FAKE_DIR}/img_1.rc"
"${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >/dev/null 2>&1
check "scanner: findings exit 2" test $? -eq 2
check "scanner: findings are not retried" count "^run " docker.log 1
check "scanner: findings report written" test -s "${FAKE_DIR}/r.md"

setup
echo 2 >"${FAKE_DIR}/img_1.rc"
chmod 0600 "${FAKE_DIR}/r.md" 2>/dev/null; : >"${FAKE_DIR}/r.md"; chmod 0400 "${FAKE_DIR}/r.md"
[[ -w "${FAKE_DIR}/r.md" ]] || { IMAGE_SCAN_RETRIES=2 "${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >/dev/null 2>&1; check "scanner: unwritable report is an infra failure, not a finding" test $? -eq 10; }

setup
echo 2 >"${FAKE_DIR}/login-fails"
"${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >/dev/null 2>&1
check "scanner: infra failure then success exits 0" test $? -eq 0
check "scanner: login retried" count "^login " docker.log 3

setup
echo 9 >"${FAKE_DIR}/login-fails"
IMAGE_SCAN_RETRIES=2 "${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >/dev/null 2>&1
check "scanner: infra failure after retries exits 10" test $? -eq 10
check "scanner: stops after the retries" count "^login " docker.log 2

setup
echo 1 >"${FAKE_DIR}/img_1.rc"
IMAGE_SCAN_RETRIES=2 "${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >/dev/null 2>&1
check "scanner: unknown scanner exit code is an infra failure" test $? -eq 10

# ---------------------------------------------------------------- gate/scope.sh
setup
repo="$(mktemp -d)"
git -C "${repo}" init -q -b main
git -C "${repo}" -c user.email=t@t -c user.name=t commit -q --allow-empty -m base
echo x >"${repo}/README.md"
git -C "${repo}" add . && git -C "${repo}" -c user.email=t@t -c user.name=t commit -q -m change
scope() { (cd "${repo}" && GITHUB_EVENT_NAME="$1" SCAN_PATHS="$2" "${root}/gate/scope.sh" >/dev/null 2>&1); }
scope_rc() { scope "$@"; echo $?; }

: >"${GITHUB_OUTPUT}"; scope pull_request ""
check "scope: empty scan-paths scans" grep -q "scan=true" "${GITHUB_OUTPUT}"
: >"${GITHUB_OUTPUT}"; scope push "^Dockerfile"
check "scope: push always scans" grep -q "scan=true" "${GITHUB_OUTPUT}"
: >"${GITHUB_OUTPUT}"; scope pull_request $'^Dockerfile\n\n^go\\.mod'
check "scope: pull_request without a matching file skips" grep -q "scan=false" "${GITHUB_OUTPUT}"
: >"${GITHUB_OUTPUT}"; scope pull_request $'^Dockerfile\n^README'
check "scope: pull_request with a matching file scans" grep -q "scan=true" "${GITHUB_OUTPUT}"
: >"${GITHUB_OUTPUT}"; (cd "${repo}" && git checkout -q --orphan shallow && git -c user.email=t@t -c user.name=t commit -q -m only); scope pull_request "^x"
check "scope: missing HEAD^1 fails" test "$(scope_rc pull_request '^x')" -eq 1
check "scope: missing HEAD^1 writes no output" test ! -s "${GITHUB_OUTPUT}"
git -C "${repo}" checkout -q main
: >"${GITHUB_OUTPUT}"
check "scope: invalid regex fails closed" test "$(scope_rc pull_request '^(')" -eq 1
check "scope: invalid regex writes no scan=false" test ! -s "${GITHUB_OUTPUT}"

# ---------------------------------------------------------------- gate/image.sh
setup
resolved() { : >"${GITHUB_OUTPUT}"; (env "$@" "${root}/gate/image.sh" >/dev/null 2>&1) && sed -n 's/^image=//p' "${GITHUB_OUTPUT}"; }
check "image: explicit image is used as is" test "$(resolved IMAGE=x/y:z RUNNER_ARCH=X64 GITHUB_SHA=0123456789abcdef)" = "x/y:z"
check "image: commit and amd64 by default" test "$(resolved IMAGE= IMAGE_REPOSITORY=ghcr.io/o/r RUNNER_ARCH=X64 GITHUB_SHA=0123456789abcdef GITHUB_REF=refs/heads/main)" = "ghcr.io/o/r:0123456-amd64"
check "image: tag name and arm64 on a tag build" test "$(resolved IMAGE= IMAGE_REPOSITORY=ghcr.io/o/r RUNNER_ARCH=ARM64 GITHUB_SHA=0123456789abcdef GITHUB_REF=refs/tags/v1.2.3)" = "ghcr.io/o/r:v1.2.3-arm64"
check "image: unknown runner architecture fails" test -z "$(resolved IMAGE= IMAGE_REPOSITORY=r RUNNER_ARCH=X86 GITHUB_SHA=0123456789abcdef)"

# ---------------------------------------------------------------- gate/promote.sh
digest_a="sha256:$(printf 'a%.0s' {1..64})"
digest_b="sha256:$(printf 'b%.0s' {1..64})"
promote() { IMAGE="${PROMOTE_IMAGE:-ghcr.io/o/r:0123456}" EXPECTED_DIGEST="${digest_a}" PROMOTE_TAGS="$1" "${root}/gate/promote.sh" promote >/dev/null 2>&1; }
promoted() { sed -n '/^promoted<</,/^PROMOTED_EOF/p' "${GITHUB_OUTPUT}" | sed '1d;$d' | paste -sd, -; }

setup
IMAGE=ghcr.io/o/r:0123456 "${root}/gate/promote.sh" resolve >/dev/null 2>&1
check "promote: resolve exits 0" test $? -eq 0
check "promote: resolve writes the digest" grep -q "^digest=${digest_a}$" "${GITHUB_OUTPUT}"
check "promote: resolve inspects the image" logged "buildx imagetools inspect --format {{json .Manifest}} ghcr.io/o/r:0123456" docker.log

setup
echo 9 >"${FAKE_DIR}/inspect-fails"
IMAGE_SCAN_RETRIES=2 IMAGE=ghcr.io/o/r:0123456 "${root}/gate/promote.sh" resolve >/dev/null 2>&1
check "promote: resolve fails when the image cannot be inspected" test $? -eq 1
check "promote: resolve retries" count "imagetools inspect" docker.log 2
check "promote: resolve writes no digest on failure" test ! -s "${GITHUB_OUTPUT}"

setup
promote $'ghcr.io/o/r:v1.2.3\nghcr.io/o/r:latest\n'
check "promote: exits 0" test $? -eq 0
check "promote: one imagetools create for all tags, by digest" \
  logged "buildx imagetools create --tag ghcr.io/o/r:v1.2.3 --tag ghcr.io/o/r:latest ghcr.io/o/r@${digest_a}$" docker.log
check "promote: promoted output lists the tags" test "$(promoted)" = "ghcr.io/o/r:v1.2.3,ghcr.io/o/r:latest"
check "promote: no registry credentials involved" not_logged "login" docker.log

setup
promote "ghcr.io/o/r:v1.2.3, ghcr.io/o/r:latest ,,ghcr.io/o/r:v1.2.3"
check "promote: comma separated, trimmed and deduplicated" test "$(promoted)" = "ghcr.io/o/r:v1.2.3,ghcr.io/o/r:latest"

setup
promote $'ghcr.io/o/r:0123456\nghcr.io/o/r:develop'
check "promote: the scanned image tag is skipped" test "$(promoted)" = "ghcr.io/o/r:develop"
check "promote: ... and not passed to imagetools" not_logged "--tag ghcr.io/o/r:0123456" docker.log

setup
promote "ghcr.io/o/r:0123456"
check "promote: only the scanned tag means nothing to do" test $? -eq 0
check "promote: ... no imagetools create" not_logged "imagetools create" docker.log
check "promote: ... empty promoted output" grep -q "^promoted=$" "${GITHUB_OUTPUT}"

setup
PROMOTE_IMAGE="localhost:5000/o/r:0123456" promote "localhost:5000/o/r:latest"
check "promote: a registry port is not taken for a tag" logged "localhost:5000/o/r@${digest_a}$" docker.log

setup
PROMOTE_IMAGE="ghcr.io/o/r@${digest_a}" promote "ghcr.io/o/r:latest"
check "promote: an image already by digest is promoted as is" logged "ghcr.io/o/r@${digest_a}$" docker.log

setup
printf '%s\n' "${digest_b}" >"${FAKE_DIR}/digest-seq"
promote "ghcr.io/o/r:latest"
check "promote: a tag that moved since the scan started fails" test $? -eq 1
check "promote: ... and promotes nothing" not_logged "imagetools create" docker.log

setup
echo 1 >"${FAKE_DIR}/create-fails"
promote "ghcr.io/o/r:latest"
check "promote: a failed create is retried" test $? -eq 0
check "promote: ... twice" count "imagetools create" docker.log 2

setup
echo 9 >"${FAKE_DIR}/create-fails"
IMAGE_SCAN_RETRIES=2 promote "ghcr.io/o/r:latest"
check "promote: create failing after retries fails" test $? -eq 1
check "promote: ... stops after the retries" count "imagetools create" docker.log 2
check "promote: ... nothing reported promoted" not_logged "promoted" output

setup
IMAGE_SCAN_RETRIES=abc promote "ghcr.io/o/r:latest"
check "promote: invalid retries are rejected" test $? -eq 1

# ---------------------------------------------------------------- gate/skip.sh
decide() { : >"${GITHUB_OUTPUT}"; env "$@" "${root}/gate/skip.sh" decide 2>&1; sed -n 's/^skip=//p' "${GITHUB_OUTPUT}"; }
check "skip: workflow_dispatch with a reason skips" test "$(decide SKIP_REASON=outage GITHUB_EVENT_NAME=workflow_dispatch | tail -n1)" = true
check "skip: no reason scans" test "$(decide SKIP_REASON= GITHUB_EVENT_NAME=workflow_dispatch | tail -n1)" = false
check "skip: blank reason scans" test "$(decide "SKIP_REASON=  " GITHUB_EVENT_NAME=workflow_dispatch | tail -n1)" = false
check "skip: no reason does not warn" test "$(decide SKIP_REASON= GITHUB_EVENT_NAME=push | wc -l)" -eq 1
for event in push pull_request schedule; do
  out="$(decide SKIP_REASON=outage GITHUB_EVENT_NAME=${event})"
  check "skip: ${event} ignores the reason" test "$(tail -n1 <<<"${out}")" = false
  check "skip: ${event} warns" grep -q "^::warning::skip-reason is ignored on a ${event} event" <<<"${out}"
done

digest_c="sha256:$(printf 'c%.0s' {1..64})"
record() { env IMAGE=ghcr.io/o/r:0123456 DIGEST="${digest_c}" SKIP_REASON=$'upstream CVE\nhard fork at 12:00' GITHUB_ACTOR=alice GITHUB_RUN_ID=42 GITHUB_SERVER_URL=https://github.com "$@" "${root}/gate/skip.sh" record 2>&1; }

setup
out="$(record)"
check "skip record: exits 0" test $? -eq 0
check "skip record: warning has image, digest, actor, reason, run" grep -q "^::warning::Image scan SKIPPED for ghcr.io/o/r:0123456@${digest_c} by alice: upstream CVE hard fork at 12:00 (https://github.com/o/r/actions/runs/42)$" <<<"${out}"
check "skip record: warning is a single line" test "$(grep -c '' <<<"$(grep '^::warning::Image scan SKIPPED' <<<"${out}")")" -eq 1
check "skip record: summary has the details" grep -q "alice" "${GITHUB_STEP_SUMMARY}"
check "skip record: summary has the digest" grep -q "${digest_c}" "${GITHUB_STEP_SUMMARY}"
check "skip record: summary has the reason" grep -q "hard fork at 12:00" "${GITHUB_STEP_SUMMARY}"
check "skip record: summary has the run URL" grep -q "https://github.com/o/r/actions/runs/42" "${GITHUB_STEP_SUMMARY}"
check "skip record: summary has the time" grep -qE "20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z" "${GITHUB_STEP_SUMMARY}"
check "skip record: opens an issue titled with the short digest" logged "issue create .*--title Image scan skipped: ghcr.io/o/r:0123456@cccccccccccc " gh.log
check "skip record: issue labels" logged "--label security --label image-scan-skipped" gh.log
check "skip record: issue has the marker" logged "<!-- image-scan-skipped:ghcr.io/o/r:0123456@${digest_c} -->" gh.log
check "skip record: issue asks to re-scan and close" logged "re-run the scan.*then close this issue" gh.log
check "skip record: issue has the actor and reason" logged "Skipped by:\*\* @alice" gh.log
check "skip record: labels are created best-effort" logged "label create image-scan-skipped" gh.log

setup
echo "[{\"number\": 7, \"body\": \"<!-- image-scan-skipped:ghcr.io/o/r:0123456@${digest_c} -->\"}, {\"number\": 8, \"body\": \"<!-- image-scan-skipped:other@${digest_c} -->\"}]" >"${FAKE_DIR}/issues.json"
record >/dev/null
check "skip record: an open issue of the same image@digest is commented" logged "issue comment 7 " gh.log
check "skip record: ... and no other is opened" not_logged "issue create" gh.log

setup
FAKE_GH_FAIL="issue create" record >"${FAKE_DIR}/out.txt"
check "skip record: issue failure still exits 0" test $? -eq 0
check "skip record: issue failure warns" grep -q "^::warning::Cannot record the skipped scan as a GitHub issue" "${FAKE_DIR}/out.txt"
check "skip record: issue failure keeps the summary" grep -q alice "${GITHUB_STEP_SUMMARY}"

setup
FAKE_GH_FAIL="issue list" record >"${FAKE_DIR}/out.txt"
check "skip record: list failure exits 0 and warns" grep -q "^::warning::Cannot record the skipped scan" "${FAKE_DIR}/out.txt"

setup
record DIGEST= >"${FAKE_DIR}/out.txt"
check "skip record: unresolved digest is recorded" grep -q "@unresolved" "${FAKE_DIR}/out.txt"
check "skip record: unresolved digest titles the issue" logged "--title Image scan skipped: ghcr.io/o/r:0123456@unresolved " gh.log

# ---------------------------------------------------------------- gate/comment.sh
setup
echo "report body" >"${FAKE_DIR}/report.md"
echo '[]' >"${FAKE_DIR}/comments.json"
export PR_NUMBER=7
GITHUB_EVENT_NAME=pull_request "${root}/gate/comment.sh" ghcr.io/o/r:abc-amd64 "${FAKE_DIR}/report.md"
check "comment: exits 0" test $? -eq 0
check "comment: summary written" grep -q "Image scan (ghcr.io/o/r:abc-amd64)" "${GITHUB_STEP_SUMMARY}"
check "comment: created when missing" logged "api -X POST repos/o/r/issues/7/comments" gh.log
check "comment: marker carries the image" logged "<!-- image-scan:ghcr.io/o/r:abc-amd64 -->" gh.log

printf '%s\n' '[{"id": 55, "body": "<!-- image-scan:ghcr.io/o/r:abc-amd64 -->\nold"}, {"id": 56, "body": "<!-- image-scan:ghcr.io/o/r:abc-arm64 -->\nold"}]' >"${FAKE_DIR}/comments.json"
: >"${FAKE_DIR}/gh.log"
GITHUB_EVENT_NAME=pull_request "${root}/gate/comment.sh" ghcr.io/o/r:abc-amd64 "${FAKE_DIR}/report.md"
check "comment: updates its own comment only" logged "api -X PATCH repos/o/r/issues/comments/55" gh.log
check "comment: no new comment when found" not_logged "-X POST" gh.log

: >"${FAKE_DIR}/gh.log"
head -c 70000 /dev/zero | tr '\0' a >"${FAKE_DIR}/big.md"
GITHUB_EVENT_NAME=pull_request "${root}/gate/comment.sh" img "${FAKE_DIR}/big.md"
size="$(wc -c <"${FAKE_DIR}/gh.log")"
check "comment: truncated below the 65536 limit" test "${size}" -lt 65000

# A cut in the middle of a multibyte character must not abort the comment
: >"${FAKE_DIR}/gh.log"
{ printf a; for _ in $(seq 40000); do printf 'é'; done; } >"${FAKE_DIR}/utf8.md"
GITHUB_EVENT_NAME=pull_request "${root}/gate/comment.sh" img "${FAKE_DIR}/utf8.md"
check "comment: truncation inside a multibyte character still posts" test $? -eq 0
check "comment: ... and posted" logged "-X POST" gh.log

: >"${FAKE_DIR}/gh.log"
: >"${FAKE_DIR}/empty.md"
GITHUB_EVENT_NAME=pull_request "${root}/gate/comment.sh" img "${FAKE_DIR}/empty.md"
check "comment: nothing without a report" test ! -s "${FAKE_DIR}/gh.log"

: >"${FAKE_DIR}/gh.log"
GITHUB_EVENT_NAME=push "${root}/gate/comment.sh" img "${FAKE_DIR}/report.md"
check "comment: no PR comment on push" test ! -s "${FAKE_DIR}/gh.log"

# ---------------------------------------------------------------- weekly/scan.sh
setup
repo=ghcr.io/o/r
echo 2 >"${FAKE_DIR}/ghcr.io_o_r_v1.2.3-amd64.rc"
cp "${here}/fixtures/critical-and-high.sarif" "${FAKE_DIR}/ghcr.io_o_r_v1.2.3-amd64.sarif"
echo 2 >"${FAKE_DIR}/ghcr.io_o_r_v1.2.3-arm64.rc"
cp "${here}/fixtures/high-only.sarif" "${FAKE_DIR}/ghcr.io_o_r_v1.2.3-arm64.sarif"
"${root}/weekly/scan.sh" "${repo}" v1.2.3 "amd64 arm64" "${FAKE_DIR}/findings.json" >/dev/null 2>&1
check "weekly scan: exits 0 with findings" test $? -eq 0
check "weekly scan: one entry per CVE" test "$(jq length "${FAKE_DIR}/findings.json")" -eq 6
sev() { jq -r --arg id "$1" '.[] | select(.id == $id) | .severity' "${FAKE_DIR}/findings.json"; }
check "weekly scan: cvssV3_severity critical" test "$(sev CVE-2025-0001)" = critical
check "weekly scan: cvssV3_severity high" test "$(sev CVE-2025-0002)" = high
check "weekly scan: security-severity >= 9 is critical" test "$(sev CVE-2025-0003)" = critical
check "weekly scan: unknown severity falls back to high" test "$(sev CVE-2025-0004)" = high
check "weekly scan: ruleId of results without rule" test "$(sev CVE-2025-0005)" = high
check "weekly scan: CVE seen on both arches lists both images" \
  test "$(jq -r '.[] | select(.id == "CVE-2025-0002") | .images | length' "${FAKE_DIR}/findings.json")" -eq 2
check "weekly scan: images use <tag>-<arch>" \
  jq -e '.[] | select(.id == "CVE-2025-0006") | .images == ["ghcr.io/o/r:v1.2.3-arm64"]' "${FAKE_DIR}/findings.json" >/dev/null
check "weekly scan: summary written" grep -q "CVE-2025-0001 (critical)" "${GITHUB_STEP_SUMMARY}"

setup
echo 2 >"${FAKE_DIR}/ghcr.io_o_r_v1.2.3-amd64.rc"
cp "${here}/fixtures/high-only.sarif" "${FAKE_DIR}/ghcr.io_o_r_v1.2.3-amd64.sarif"
echo 9 >"${FAKE_DIR}/login-fails"
IMAGE_SCAN_RETRIES=1 "${root}/weekly/scan.sh" "${repo}" v1.2.3 "amd64 arm64" "${FAKE_DIR}/findings.json" >/dev/null 2>&1
check "weekly scan: infra failure exits 10" test $? -eq 10
check "weekly scan: no findings file for a partial scan" test ! -e "${FAKE_DIR}/findings.json"

for sarif in '{"runs": []}' '{"runs": [{"tool": {"driver": {}}}]}' ''; do
  setup
  echo 2 >"${FAKE_DIR}/ghcr.io_o_r_v1.2.3-amd64.rc"
  printf '%s' "${sarif}" >"${FAKE_DIR}/ghcr.io_o_r_v1.2.3-amd64.sarif"
  "${root}/weekly/scan.sh" "${repo}" v1.2.3 "amd64" "${FAKE_DIR}/findings.json" >/dev/null 2>&1
  check "weekly scan: findings without readable CVE fail (${sarif:-empty report})" test $? -eq 11
  check "weekly scan: no findings file when unreadable (${sarif:-empty report})" test ! -e "${FAKE_DIR}/findings.json"
done

setup
"${root}/weekly/scan.sh" "${repo}" v1.2.3 "amd64" "${FAKE_DIR}/findings.json" >/dev/null 2>&1
check "weekly scan: clean images give an empty list" test "$(jq length "${FAKE_DIR}/findings.json")" -eq 0

# ---------------------------------------------------------------- weekly/issues.sh
setup
cat >"${FAKE_DIR}/findings.json" <<'JSON'
[{"id": "CVE-2025-0001", "severity": "critical", "images": ["ghcr.io/o/r:v1.2.3-amd64"]},
 {"id": "CVE-2025-0002", "severity": "critical", "images": ["ghcr.io/o/r:v1.2.3-amd64", "ghcr.io/o/r:v1.2.3-arm64"]},
 {"id": "CVE-2025-0003", "severity": "high", "images": ["ghcr.io/o/r:v1.2.3-amd64"]},
 {"id": "CVE-2025-0004", "severity": "critical", "images": ["ghcr.io/o/r:v1.2.3-amd64"]},
 {"id": "CVE-2025-0005", "severity": "high", "images": ["ghcr.io/o/r:v1.2.3-amd64"]},
 {"id": "CVE-2025-0007", "severity": "high", "images": ["ghcr.io/o/r:v1.2.3-amd64"]}]
JSON
cat >"${FAKE_DIR}/issues.json" <<'JSON'
[{"number": 10, "state": "OPEN", "labels": [{"name": "security"}, {"name": "severity:high"}], "body": "<!-- image-scan-cve:CVE-2025-0002 -->\ntext\n\n- **Due date:** 2025-12-31\n"},
 {"number": 11, "state": "OPEN", "labels": [{"name": "security"}, {"name": "risk-accepted"}], "body": "<!-- image-scan-cve:CVE-2025-0003 -->\n"},
 {"number": 12, "state": "OPEN", "labels": [{"name": "security"}], "body": "<!-- image-scan-cve:CVE-2024-9999 -->\n"},
 {"number": 13, "state": "OPEN", "labels": [{"name": "security"}], "body": "<!-- scout-cve:CVE-2025-0004 --> not ours"},
 {"number": 14, "state": "OPEN", "labels": [{"name": "security"}], "body": "no marker"},
 {"number": 15, "state": "CLOSED", "labels": [{"name": "security"}, {"name": "risk-accepted"}], "body": "<!-- image-scan-cve:CVE-2025-0005 -->\n"},
 {"number": 16, "state": "CLOSED", "labels": [{"name": "security"}], "body": "<!-- image-scan-cve:CVE-2025-0007 -->\n"},
 {"number": 17, "state": "OPEN", "labels": [{"name": "security"}], "body": "<!-- image-scan-cve:CVE-2024-8888 -->\n"},
 {"number": 18, "state": "OPEN", "labels": [{"name": "security"}], "body": "<!-- image-scan-cve:CVE-2024-8888 -->\n"}]
JSON
SLACK_MESSAGE_FILE="${FAKE_DIR}/slack.txt" "${root}/weekly/issues.sh" v1.2.3 "${FAKE_DIR}/findings.json" >/dev/null 2>&1
check "issues: exits 0" test $? -eq 0
check "issues: lists open and closed issues" logged "issue list .*--state all" gh.log
check "issues: opens the new critical CVE" logged "issue create .*--title Image scan: CVE-2025-0001 (critical)" gh.log
check "issues: new issue has labels" logged "--label security --label severity:critical" gh.log
check "issues: new issue body has the neutral marker" logged "<!-- image-scan-cve:CVE-2025-0001 -->" gh.log
check "issues: new critical is due in 7 days" logged "Due date:\*\* $(date -u -v+7d +%F 2>/dev/null || date -u -d '+7 days' +%F)" gh.log
check "issues: the old scout marker is not matched, so opened anew" logged "issue create .*CVE-2025-0004" gh.log
check "issues: known CVE refreshed" logged "issue edit 10 " gh.log
check "issues: known CVE keeps its due date" logged "Due date:\*\* 2025-12-31" gh.log
check "issues: severity change swaps the label and title" logged "issue edit 10 .*--add-label severity:critical --title Image scan: CVE-2025-0002 (critical)" gh.log
check "issues: severity change removes the other label" logged "issue edit 10 .*--remove-label severity:high" gh.log
check "issues: risk-accepted is skipped" not_logged "issue edit 11" gh.log
check "issues: closed risk-accepted does not open a duplicate" not_logged "issue create .*CVE-2025-0005" gh.log
check "issues: closed issue without the label is opened anew" logged "issue create .*CVE-2025-0007" gh.log
check "issues: fixed CVE closed" logged "issue close 12 .*CVE-2024-9999 is not reported anymore.*v1.2.3.*published 2026-01-02" gh.log
check "issues: duplicate open issues of a fixed CVE are all closed" count "issue close 1[78] " gh.log 2
check "issues: closed issues are not closed again" not_logged "issue close 1[56]" gh.log
check "issues: still reported CVE not closed" not_logged "issue close 10" gh.log
check "issues: issue without marker untouched" not_logged "issue close 14" gh.log
check "slack: lists new issues only" test "$(grep -c '^•' "${FAKE_DIR}/slack.txt")" -eq 3
check "slack: header counts them" grep -q "found 3 new" "${FAKE_DIR}/slack.txt"
check "slack: links the issue with its due date" grep -q "CVE-2025-0001" "${FAKE_DIR}/slack.txt"
check "slack: no leftover lines file" test ! -e "${FAKE_DIR}/slack.txt.lines"

# Duplicates: the oldest (risk-accepted first) is kept, the others closed even while the CVE is live
setup
echo '[{"id": "CVE-2025-0001", "severity": "high", "images": ["i"]}]' >"${FAKE_DIR}/findings.json"
cat >"${FAKE_DIR}/issues.json" <<'JSON'
[{"number": 30, "state": "OPEN", "labels": [], "body": "<!-- image-scan-cve:CVE-2025-0001 -->"},
 {"number": 31, "state": "OPEN", "labels": [], "body": "<!-- image-scan-cve:CVE-2025-0001 -->"}]
JSON
"${root}/weekly/issues.sh" v1.2.3 "${FAKE_DIR}/findings.json" >/dev/null 2>&1
check "issues: the oldest duplicate is refreshed" logged "issue edit 30 " gh.log
check "issues: other duplicates are closed" logged "issue close 31 .*Duplicate of #30" gh.log
check "issues: the refreshed one is not closed" not_logged "issue close 30" gh.log

# A fixed risk-accepted issue loses its label so a regression is tracked again
setup
echo '[]' >"${FAKE_DIR}/findings.json"
echo '[{"number": 40, "state": "OPEN", "labels": [{"name": "risk-accepted"}], "body": "<!-- image-scan-cve:CVE-2024-1 -->"}]' >"${FAKE_DIR}/issues.json"
"${root}/weekly/issues.sh" v1.2.3 "${FAKE_DIR}/findings.json" >/dev/null 2>&1
check "issues: fixed risk-accepted issue is closed" logged "issue close 40 " gh.log
check "issues: ... and loses risk-accepted" logged "issue edit 40 .*--remove-label risk-accepted" gh.log

# A failure after an issue was opened still leaves its announcement behind
setup
echo '[{"id": "CVE-2025-0001", "severity": "critical", "images": ["i"]}]' >"${FAKE_DIR}/findings.json"
echo '[{"number": 20, "state": "OPEN", "labels": [], "body": "<!-- image-scan-cve:CVE-2024-1 -->"}]' >"${FAKE_DIR}/issues.json"
FAKE_GH_FAIL="issue close" SLACK_MESSAGE_FILE="${FAKE_DIR}/slack.txt" "${root}/weekly/issues.sh" v1.2.3 "${FAKE_DIR}/findings.json" >/dev/null 2>&1
check "issues: a gh failure fails the script" test $? -ne 0
check "slack: issue opened before the failure is announced" grep -q "CVE-2025-0001" "${FAKE_DIR}/slack.txt"

# A refreshed issue whose body lost its due date gets one again
setup
echo '[{"id": "CVE-2025-0001", "severity": "critical", "images": ["i"]}]' >"${FAKE_DIR}/findings.json"
printf '%s\n' '[{"number": 21, "state": "OPEN", "labels": [], "body": "<!-- image-scan-cve:CVE-2025-0001 -->\nedited"}]' >"${FAKE_DIR}/issues.json"
"${root}/weekly/issues.sh" v1.2.3 "${FAKE_DIR}/findings.json" >/dev/null 2>&1
check "issues: missing due date is recomputed" logged "Due date:\*\* 20[0-9][0-9]-" gh.log

setup
echo '[]' >"${FAKE_DIR}/findings.json"
SLACK_MESSAGE_FILE="${FAKE_DIR}/slack.txt" "${root}/weekly/issues.sh" v1.2.3 "${FAKE_DIR}/findings.json" >/dev/null 2>&1
check "slack: no message file when nothing was opened" test ! -e "${FAKE_DIR}/slack.txt"

echo
echo "${cases} checks, ${failures} failed"
exit $((failures > 0 ? 1 : 0))
