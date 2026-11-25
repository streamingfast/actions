#!/usr/bin/env bash
# Tests of the image-scan scripts with a fake docker and gh on PATH. Run: image-scan/tests/run.sh
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "${here}")"
failures=0
cases=0

# shellcheck disable=SC2329 # called through check
not() { ! "$@"; }
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
check "scanner: no --output nor bind mount of the report dir" not_logged "--output\|:/out" docker.log
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

# Quiet on a clean scan: nothing to post, a line to update an earlier report
setup
export PR_NUMBER=7
echo "full report" >"${FAKE_DIR}/report.md"
echo "✅ Image scan: no critical/high vulnerabilities in img" >"${FAKE_DIR}/comment.md"
echo '[]' >"${FAKE_DIR}/comments.json"
FINDINGS=false GITHUB_EVENT_NAME=pull_request "${root}/gate/comment.sh" img "${FAKE_DIR}/report.md" "${FAKE_DIR}/comment.md"
check "comment clean: exits 0" test $? -eq 0
check "comment clean: no comment without an existing one" not_logged "-X POST\|-X PATCH" gh.log
check "comment clean: the job summary keeps the full report" grep -q "full report" "${GITHUB_STEP_SUMMARY}"

printf '%s\n' '[{"id": 55, "body": "<!-- image-scan:img -->\nold"}, {"id": 56, "body": "<!-- image-scan:other -->\nold"}]' >"${FAKE_DIR}/comments.json"
FINDINGS=false GITHUB_EVENT_NAME=pull_request "${root}/gate/comment.sh" img "${FAKE_DIR}/report.md" "${FAKE_DIR}/comment.md"
check "comment clean: updates the comment of an earlier failing run" logged "api -X PATCH repos/o/r/issues/comments/55" gh.log
check "comment clean: ... with the one line" logged "no critical/high vulnerabilities in img" gh.log
check "comment clean: ... not the full report" not_logged "full report" gh.log
check "comment clean: the other image is left alone" not_logged "comments/56" gh.log

: >"${FAKE_DIR}/gh.log"
echo '[]' >"${FAKE_DIR}/comments.json"
FINDINGS=true GITHUB_EVENT_NAME=pull_request "${root}/gate/comment.sh" img "${FAKE_DIR}/report.md" "${FAKE_DIR}/comment.md"
check "comment findings: posted when missing" logged "api -X POST repos/o/r/issues/7/comments" gh.log
check "comment findings: ... from the comment file" logged "no critical/high" gh.log

: >"${FAKE_DIR}/gh.log"
{ echo "<details><summary>Scanner report</summary>"; echo; head -c 70000 /dev/zero | tr '\0' a; echo; echo "</details>"; } >"${FAKE_DIR}/cut.md"
FINDINGS=true GITHUB_EVENT_NAME=pull_request "${root}/gate/comment.sh" img "${FAKE_DIR}/report.md" "${FAKE_DIR}/cut.md"
check "comment findings: a truncated report closes its collapsed block" grep -q "</details>$" "${FAKE_DIR}/gh.log"

# ---------------------------------------------------------------- scanner.sh: VEX documents and the findings level
fx="${here}/fixtures"
setup
IMAGE_SCAN_VEX_LOCATION="${fx}/vex" "${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >/dev/null 2>&1
check "scanner vex: directory scan exits 0" test $? -eq 0
check "scanner vex: directory mounted read-only" logged "-v ${fx}/vex:/vex:ro" docker.log
check "scanner vex: --vex-location points at the mount" logged "--vex-location /vex " docker.log
check "scanner vex: authors default to any (Scout only accepts docker.com ones by default)" logged "--vex-author \.\* " docker.log
check "scanner vex: severities still passed" logged "--only-severity critical,high --vex-location" docker.log

setup
IMAGE_SCAN_VEX_LOCATION="${fx}/vex/openvex.json" IMAGE_SCAN_VEX_AUTHOR='<.*@streamingfast.io>' "${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >/dev/null 2>&1
check "scanner vex: a file is mounted as a file" logged "-v ${fx}/vex/openvex.json:/vex/openvex.json:ro" docker.log
check "scanner vex: --vex-location points at the file" logged "--vex-location /vex/openvex.json " docker.log
check "scanner vex: vex-author is passed" logged "--vex-author <.\*@streamingfast.io> " docker.log

setup
(cd "${fx}" && IMAGE_SCAN_VEX_LOCATION="vex" "${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >/dev/null 2>&1)
check "scanner vex: a relative location is mounted by its absolute path" logged "-v ${fx}/vex:/vex:ro" docker.log

setup
IMAGE_SCAN_VEX_LOCATION="${FAKE_DIR}/nope" "${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >"${FAKE_DIR}/out.txt" 2>&1
check "scanner vex: a missing location fails (1)" test $? -eq 1
check "scanner vex: ... with an error naming it" grep -q "::error::vex-location '${FAKE_DIR}/nope' does not exist" "${FAKE_DIR}/out.txt"
check "scanner vex: ... before any scan" not_logged "^run " docker.log

setup
IMAGE_SCAN_VEX_LOCATION="${fx}/vex-invalid" "${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >"${FAKE_DIR}/out.txt" 2>&1
check "scanner vex: a document that is not JSON fails (1)" test $? -eq 1
check "scanner vex: ... naming it" grep -q "bad.json is not valid JSON" "${FAKE_DIR}/out.txt"
check "scanner vex: ... before any scan" not_logged "^run " docker.log

setup
"${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >/dev/null 2>&1
check "scanner vex: no documents, no vex flag" not_logged "vex" docker.log
check "scanner vex: ... and no mount" not_logged " -v " docker.log

setup
echo 2 >"${FAKE_DIR}/img_1.rc"
out="$("${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" 2>&1)"
check "scanner level: findings are an error by default" grep -q "^::error::critical,high vulnerabilities found in img:1$" <<<"${out}"
out="$(IMAGE_SCAN_FINDINGS_LEVEL=warning "${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" 2>&1)"
check "scanner level: a warning on request" grep -q "^::warning::critical,high vulnerabilities found in img:1$" <<<"${out}"
IMAGE_SCAN_FINDINGS_LEVEL=warning "${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >/dev/null 2>&1
check "scanner level: a warning level keeps exit 2" test $? -eq 2
IMAGE_SCAN_FINDINGS_LEVEL=loud "${root}/lib/scanner.sh" img:1 "${FAKE_DIR}/r.md" >/dev/null 2>&1
check "scanner level: an unknown level is rejected" test $? -eq 1

# ---------------------------------------------------------------- lib/report.sh
# shellcheck source=../lib/report.sh
source "${root}/lib/report.sh"
rows="$(sarif_findings "${fx}/table.sarif")"
row() { jq -r --arg id "$1" --arg f "$2" '.[] | select(.id == $id) | .[$f]' <<<"${rows}"; }
check "report: one row per CVE (rules and results)" test "$(jq length <<<"${rows}")" -eq 5
check "report: cvssV3_severity" test "$(row CVE-2025-2222 severity)" = high
check "report: security-severity score without a level" test "$(row CVE-2025-3333 severity)" = critical
check "report: unknown severity" test "$(row CVE-2025-5555 severity)" = unknown
check "report: package from the purl, without type and qualifiers" test "$(row CVE-2025-1111 package)" = openssl
check "report: golang package keeps its module path" test "$(row CVE-2025-2222 package)" = golang.org/x/net
check "report: installed from affected_version" test "$(row CVE-2025-1111 installed)" = 3.0.1-1
check "report: installed from the purl version otherwise" test "$(row CVE-2025-2222 installed)" = 0.10.0
check "report: fixed version" test "$(row CVE-2025-2222 fixed)" = 0.17.0
check "report: 'not fixed' is no fix" test "$(row CVE-2025-1111 fixed)" = ""
check "report: package, installed and fixed from the help text" test "$(row CVE-2025-3333 package):$(row CVE-2025-3333 installed):$(row CVE-2025-3333 fixed)" = "lodash:4.17.0:4.17.21"
check "report: rows are sorted by severity then id" test "$(jq -r 'map(.id) | join(",")' <<<"${rows}")" = "CVE-2025-1111,CVE-2025-3333,CVE-2025-2222,CVE-2025-4444,CVE-2025-5555"
check "report: an unreadable report gives no row" test "$(sarif_findings /dev/null)" = "[]"
echo '{ not json' >"${FAKE_DIR}/bad.sarif"
check "report: ... also when it is not JSON" test "$(sarif_findings "${FAKE_DIR}/bad.sarif")" = "[]"
check "report: text table names the CVEs and says no fix" bash -c "source '${root}/lib/report.sh'; findings_text '${rows//\'/}' | grep -q 'CVE-2025-1111 .*critical.*no fix'"
md="$(findings_markdown "${rows}")"
check "report: markdown table has a header" grep -q "^| CVE | Severity | Package | Installed | Fixed |$" <<<"${md}"
check "report: markdown row" grep -q '^| CVE-2025-2222 | high | `golang.org/x/net` | 0.10.0 | 0.17.0 |$' <<<"${md}"
check "report: markdown escapes pipes" grep -q '1.2.3|bad\|1.2.3\\|bad' <<<"${md}"
check "report: markdown is capped" grep -q "… and 3 more" <<<"$(findings_markdown "${rows}" 2)"

statements="$(vex_statements "${fx}/vex")"
check "report: statements of a directory" test "$(jq length <<<"${statements}")" -eq 3
check "report: statements of a file" test "$(vex_statements "${fx}/vex/openvex.json" | jq length)" -eq 3
check "report: a statement inherits the author of its document" test "$(jq -r '.[0].author' <<<"${statements}")" = "SF Security <security@streamingfast.io>"
check "report: justification and impact" test "$(jq -r '.[0].justification' <<<"${statements}")" = inline_mitigations_already_exist
check "report: string form of the vulnerability (OpenVEX before 0.2)" test "$(jq -r '.[2].id' <<<"${statements}")" = CVE-2025-9999
check "report: no location, no statement" test "$(vex_statements "${FAKE_DIR}/nope")" = "[]"
mkdir "${FAKE_DIR}/two"
for ts in 2026-01-01T00:00:00Z 2026-03-01T00:00:00Z 2026-02-01T00:00:00Z; do
  printf '{"statements": [{"vulnerability": {"name": "CVE-2025-2222"}, "status": "not_affected", "justification": "j-%s", "timestamp": "%s"}]}' "${ts}" "${ts}" >"${FAKE_DIR}/two/${ts}.json"
done
two="$(suppressed_findings "${rows}" '[]' "$(vex_statements "${FAKE_DIR}/two")")"
check "report: the most recent statement wins" test "$(jq -r '.[] | select(.id == "CVE-2025-2222") | .statements | map(.justification) | join(",")' <<<"${two}")" = "j-2026-03-01T00:00:00Z"
check "report: a CVE without statement is suppressed without justification" test "$(jq -r '.[] | select(.id == "CVE-2025-1111") | .status' <<<"${two}")" = ""
check "report: only CVEs missing from the active list are suppressed" test "$(suppressed_findings "${rows}" "${rows}" '[]')" = "[]"

# Statements scoped to the image: the sf-analytics case, two documents (real files of streamingfast/sf-analytics) with the same
# CVEs and different products, the report must show the statements of the scanned image
sfa="${fx}/vex-sf-analytics"
sfa_statements="$(vex_statements "${sfa}")"
check "report scope: products of the statements are read (objects and strings)" test "$(jq -r '[.[].products | length] | min' <<<"${sfa_statements}")" -eq 3
sfa_rows='[{"id":"CVE-2026-107493","severity":"high","package":"openssl","installed":"3.0","fixed":""},{"id":"CVE-2026-107496","severity":"high","package":"openssl","installed":"3.0","fixed":""},{"id":"CVE-2026-84786","severity":"critical","package":"node","installed":"22","fixed":""}]'
dash_img="gcr.io/eoscanada-shared-services/sf-analytics-dashboard@sha256:9ea5d73e$(printf 'a%.0s' {1..56})"
dash="$(suppressed_findings "${sfa_rows}" '[]' "${sfa_statements}" "${dash_img}")"
check "report scope: the dashboard image gets one statement per CVE" test "$(jq -c 'map(.statements | length)' <<<"${dash}")" = "[1,1,1]"
check "report scope: ... from dashboard.openvex.json" test "$(jq -r 'map(.statements[0].file) | unique | join(",")' <<<"${dash}")" = dashboard.openvex.json
check "report scope: ... scoped" test "$(jq -r 'map(.statements[0].scoped) | all' <<<"${dash}")" = true
check "report scope: ... with the dashboard justification, not the dbt-runner one" test "$(jq -r '[.[].statements[0].impact] | join(" ")' <<<"${dash}" | grep -ci 'dbt\|python')" -eq 0
dbt="$(suppressed_findings "${sfa_rows}" '[]' "${sfa_statements}" "gcr.io/eoscanada-shared-services/dbt-runner:latest")"
check "report scope: the dbt-runner image gets the dbt-runner statements" test "$(jq -r 'map(.statements[0].file) | unique | join(",")' <<<"${dbt}")" = dbt-runner.openvex.json
check "report scope: ... and they differ from the dashboard ones" test "$(jq -r '.[0].statements[0].impact' <<<"${dbt}")" != "$(jq -r '.[0].statements[0].impact' <<<"${dash}")"
text="$(suppressed_text "${dash}")"
check "report scope: the log line names the VEX file" grep -q '\[dashboard.openvex.json\]$' <<<"$(grep '^CVE-2026-107493' <<<"${text}")"
check "report scope: ... and no not-scoped mention" test "$(grep -c 'not scoped' <<<"${text}")" -eq 0
md="$(suppressed_markdown "${dash}")"
check "report scope: the markdown shows the file" grep -q 'dashboard.openvex.json' <<<"${md}"
check "report scope: ... not the other one" test "$(grep -c 'dbt-runner.openvex.json' <<<"${md}")" -eq 0

unscoped="$(suppressed_findings "${sfa_rows}" '[]' "${sfa_statements}" "gcr.io/eoscanada-shared-services/other-image:1")"
check "report scope: no product match falls back to the CVE id, marked" test "$(jq -r 'map(.statements | length == 1 and .[0].scoped == false) | all' <<<"${unscoped}")" = true
check "report scope: ... in the log" test "$(suppressed_text "${unscoped}" | grep -c '(statement not scoped to this image)$')" -eq 3
check "report scope: ... in the markdown" grep -q 'statement not scoped to this image' <<<"$(suppressed_markdown "${unscoped}")"

mkdir "${FAKE_DIR}/both"
for n in a b; do
  printf '{"author": "x", "statements": [{"vulnerability": {"name": "CVE-2025-2222"}, "products": [{"@id": "pkg:oci/o/r?repository_url=ghcr.io"}], "status": "not_affected", "justification": "j-%s"}]}' "${n}" >"${FAKE_DIR}/both/${n}.json"
done
both="$(suppressed_findings "${rows}" '[]' "$(vex_statements "${FAKE_DIR}/both")" ghcr.io/o/r:abc)"
check "report scope: several matching statements are all shown" test "$(jq -r '.[] | select(.id == "CVE-2025-2222") | .statements | map(.file) | join(",")' <<<"${both}")" = "a.json,b.json"
check "report scope: ... on one log line" test "$(suppressed_text "${both}" | grep '^CVE-2025-2222' | grep -c ' | ')" -eq 1

# Product forms: each must match the image, and only it
product_match() { # product_match <product> <image> -> true|false
  jq -nr --arg p "$1" --arg i "$2" "${VEX_JQ_DEFS}"'($i | image_ref) as $img | $p | product_matches($img)'
}
gcr=gcr.io/eoscanada-shared-services/img
for p in "pkg:oci/eoscanada-shared-services/img?repository_url=gcr.io" \
  "pkg:oci/eoscanada-shared-services/img@sha256:${dgst:=$(printf 'b%.0s' {1..64})}?repository_url=gcr.io&tag=v1" \
  "pkg:oci/eoscanada-shared-services/img@sha256%3A${dgst}?repository_url=gcr.io&tag=v1" \
  "pkg:oci/eoscanada-shared-services/img" "pkg:oci/img?repository_url=gcr.io%2Feoscanada-shared-services%2Fimg" \
  "pkg:docker/gcr.io/eoscanada-shared-services/img" "pkg:docker/eoscanada-shared-services/img" "eoscanada-shared-services/img" "${gcr}" "${gcr}:v1"; do
  check "product forms: ${p:0:70} matches ${gcr}@sha256:b…" test "$(product_match "${p}" "${gcr}@sha256:${dgst}")" = true
done
check "product forms: a tag only image matches" test "$(product_match "pkg:oci/eoscanada-shared-services/img?repository_url=gcr.io" "${gcr}:v2")" = true
check "product forms: another registry does not match" test "$(product_match "pkg:oci/eoscanada-shared-services/img?repository_url=ghcr.io" "${gcr}:v2")" = false
check "product forms: another repository does not match" test "$(product_match "pkg:oci/eoscanada-shared-services/img2?repository_url=gcr.io" "${gcr}:v2")" = false
check "product forms: a prefix of the repository does not match" test "$(product_match "pkg:docker/eoscanada-shared-services" "${gcr}:v2")" = false
check "product forms: another digest does not match" test "$(product_match "pkg:oci/eoscanada-shared-services/img@sha256:$(printf 'c%.0s' {1..64})?repository_url=gcr.io" "${gcr}@sha256:${dgst}")" = false
check "product forms: ghcr.io purl" test "$(product_match "pkg:oci/streamingfast/foo?repository_url=ghcr.io" "ghcr.io/streamingfast/foo:v1.2.3")" = true
check "product forms: docker hub image by short name" test "$(product_match "pkg:docker/streamingfast/foo" "streamingfast/foo:v1")" = true
check "product forms: ... and by docker.io name" test "$(product_match "pkg:docker/docker.io/streamingfast/foo" "streamingfast/foo:v1")" = true
check "product forms: ... not on ghcr.io" test "$(product_match "pkg:docker/docker.io/streamingfast/foo" "ghcr.io/streamingfast/foo:v1")" = false
check "product forms: a registry with a port" test "$(product_match "localhost:5000/foo" "localhost:5000/foo:1")" = true
check "product forms: garbage does not fail" test "$(product_match "" "${gcr}:1")" = false

# ---------------------------------------------------------------- gate/scan.sh
img=ghcr.io/o/r:abc-amd64
key=ghcr.io_o_r_abc-amd64
gate_scan() { : >"${GITHUB_OUTPUT}"; env IMAGE_SCAN_RETRIES=1 "$@" "${root}/gate/scan.sh" "${img}" "${FAKE_DIR}/report.md" >"${FAKE_DIR}/out.txt" 2>&1; }
# shellcheck disable=SC2329
report_has() { grep -q -- "$1" "${FAKE_DIR}/report.md"; }

setup
gate_scan
check "gate scan: clean image exits 0" test $? -eq 0
check "gate scan: ... findings=false" grep -q "^findings=false$" "${GITHUB_OUTPUT}"
check "gate scan: ... the report is the scanner's, as before" test "$(cat "${FAKE_DIR}/report.md")" = "no findings"
check "gate scan: ... one scan only" count "^run " docker.log 1

setup
echo 2 >"${FAKE_DIR}/${key}.rc"
cp "${fx}/table.sarif" "${FAKE_DIR}/${key}.sarif"
gate_scan
check "gate scan: findings exit 2" test $? -eq 2
check "gate scan: ... findings=true, written before failing" grep -q "^findings=true$" "${GITHUB_OUTPUT}"
check "gate scan: ... an error annotation" grep -q "^::error::critical,high vulnerabilities found in ${img}$" "${FAKE_DIR}/out.txt"
check "gate scan: ... no warning annotation" not_logged "::warning::" out.txt
check "gate scan: ... the log names the CVEs" grep -q "CVE-2025-1111  *critical  *openssl  *3.0.1-1  *no fix" "${FAKE_DIR}/out.txt"
check "gate scan: ... the log shows the fixed version" grep -q "CVE-2025-2222  *high  *golang.org/x/net  *0.10.0  *0.17.0" "${FAKE_DIR}/out.txt"
check "gate scan: ... two scans, the report and the CVEs" count "^run " docker.log 2
check "gate scan: ... the CVEs come from a sarif scan" logged "--format sarif" docker.log
check "gate scan: ... the report has the CVE table" report_has "^### Vulnerabilities (5)$"
check "gate scan: ... first" test "$(head -n1 "${FAKE_DIR}/report.md")" = "### Vulnerabilities (5)"
check "gate scan: ... then the scanner report" report_has "^# findings in ${img}$"
check "gate scan: ... no advisory banner" not report_has "Advisory mode"
check "gate scan: ... no suppressed section" not report_has "Suppressed"

setup
echo 2 >"${FAKE_DIR}/${key}.rc"
cp "${fx}/table.sarif" "${FAKE_DIR}/${key}.sarif"
gate_scan IMAGE_SCAN_ENFORCE=false
check "gate scan advisory: findings exit 0" test $? -eq 0
check "gate scan advisory: ... findings=true" grep -q "^findings=true$" "${GITHUB_OUTPUT}"
check "gate scan advisory: ... a warning annotation, no error" grep -q "^::warning::critical,high vulnerabilities found in ${img}$" "${FAKE_DIR}/out.txt"
check "gate scan advisory: ... says it does not fail" grep -q "^::warning::Advisory mode (enforce: false)" "${FAKE_DIR}/out.txt"
check "gate scan advisory: ... never an error" not_logged "::error::" out.txt
check "gate scan advisory: ... the CVEs are still named in the log" grep -q "CVE-2025-1111" "${FAKE_DIR}/out.txt"
check "gate scan advisory: ... and in the report" report_has "^### Vulnerabilities (5)$"
check "gate scan advisory: ... which says it is advisory" report_has "^> Advisory mode"
check "gate scan advisory: ... above the scanner report" report_has "^### Scanner report$"

setup
echo 2 >"${FAKE_DIR}/${key}.rc"
gate_scan IMAGE_SCAN_ENFORCE=FALSE
check "gate scan advisory: the value is case insensitive" test $? -eq 0
setup
gate_scan IMAGE_SCAN_ENFORCE=maybe
check "gate scan: an invalid enforce is rejected (1)" test $? -eq 1
check "gate scan: ... before any scan" not_logged "^run " docker.log
setup
echo 2 >"${FAKE_DIR}/${key}.rc"
gate_scan IMAGE_SCAN_ENFORCE=
check "gate scan: an empty enforce enforces" test $? -eq 2

setup
echo 9 >"${FAKE_DIR}/login-fails"
gate_scan IMAGE_SCAN_ENFORCE=false
check "gate scan advisory: an infrastructure failure still fails (10)" test $? -eq 10
check "gate scan advisory: ... no findings output" not_logged "findings" output

# VEX scoped to the image, end to end (sf-analytics): the image of the dashboard, the two real documents
sfa_img="gcr.io/eoscanada-shared-services/sf-analytics-dashboard@sha256:9ea5d73e$(printf 'a%.0s' {1..56})"
sfa_key="${sfa_img//[\/:]/_}"
setup
echo 2 >"${FAKE_DIR}/${sfa_key}.rc"
echo 0 >"${FAKE_DIR}/${sfa_key}.vex.rc"
jq -nc '{version: "2.1.0", runs: [{tool: {driver: {rules: [("CVE-2026-107493", "CVE-2026-107496", "CVE-2026-84786") | {id: ., properties: {cvssV3_severity: "HIGH"}}]}}}]}' >"${FAKE_DIR}/${sfa_key}.sarif"
env IMAGE_SCAN_RETRIES=1 IMAGE_SCAN_VEX_LOCATION="${fx}/vex-sf-analytics" "${root}/gate/scan.sh" "${sfa_img}" "${FAKE_DIR}/report.md" >"${FAKE_DIR}/out.txt" 2>&1
check "gate scan vex scope: both documents, all suppressed, passes" test $? -eq 0
check "gate scan vex scope: the log names the dashboard document" grep -q "^CVE-2026-107493 .*\[dashboard.openvex.json\]$" "${FAKE_DIR}/out.txt"
check "gate scan vex scope: ... never the dbt-runner one" not_logged "dbt-runner.openvex.json" out.txt
check "gate scan vex scope: the report names the dashboard document" report_has "dashboard.openvex.json"
check "gate scan vex scope: ... never the dbt-runner one" not report_has "dbt-runner.openvex.json"
check "gate scan vex scope: ... no not-scoped mention" not report_has "not scoped"

# VEX: everything suppressed
setup
echo 2 >"${FAKE_DIR}/${key}.rc"
echo 0 >"${FAKE_DIR}/${key}.vex.rc"
cp "${fx}/stdlib.sarif" "${FAKE_DIR}/${key}.sarif"
gate_scan IMAGE_SCAN_VEX_LOCATION="${fx}/vex"
check "gate scan vex: a suppressed CVE passes the gate" test $? -eq 0
check "gate scan vex: ... findings=false" grep -q "^findings=false$" "${GITHUB_OUTPUT}"
check "gate scan vex: ... the scan decides with the documents" logged "--vex-location /vex .*${img}$" docker.log
check "gate scan vex: ... the CVEs without them are listed too" count "^run " docker.log 2
check "gate scan vex: ... the report lists the suppressed CVE" report_has "^### Suppressed by VEX (1)$"
check "gate scan vex: ... with its id, package and fixed in" report_has "CVE-2026-97054 | high | \`stdlib\` | 1.27.3"
check "gate scan vex: ... its justification" report_has "inline_mitigations_already_exist"
check "gate scan vex: ... its impact statement, with the issue link" report_has "issues/57"
check "gate scan vex: ... its author and date" report_has "SF Security <security@streamingfast.io> | 2026-11-24T10:00:00Z |"
check "gate scan vex: ... no vulnerability section" not report_has "^### Vulnerabilities"
check "gate scan vex: ... the log names it" grep -q "^CVE-2026-97054 (high) stdlib 1.27.3: inline_mitigations_already_exist - Risk accepted" "${FAKE_DIR}/out.txt"
check "gate scan vex: ... as a notice" grep -q "^::notice::1 vulnerabilities of ${img} are suppressed by the VEX documents of ${fx}/vex: CVE-2026-97054$" "${FAKE_DIR}/out.txt"
check "gate scan vex: ... no error" not_logged "::error::" out.txt
check "gate scan vex: a statement Scout ignores warns" grep -q "^::warning::VEX statement for CVE-2025-2222 in .*openvex.json has status under_investigation: only not_affected suppresses" "${FAKE_DIR}/out.txt"
check "gate scan vex: a statement matching nothing is noticed" grep -q "^::notice::VEX statement for CVE-2025-9999 in .*matches no critical/high finding of ${img}, remove it" "${FAKE_DIR}/out.txt"
check "gate scan vex: the documents were mounted in the first scan only" count " -v " docker.log 1
check "gate scan vex: the unfiltered scan has no vex flag" test "$(grep -c -- "--format sarif" "${FAKE_DIR}/docker.log")" -eq 1
check "gate scan vex: ... the sarif scan does not mount the documents" not_logged "-v .*--format sarif" docker.log

# the same report goes to the job summary and the pull request
: >"${FAKE_DIR}/gh.log"; echo '[]' >"${FAKE_DIR}/comments.json"; : >"${GITHUB_STEP_SUMMARY}"
PR_NUMBER=7 GITHUB_EVENT_NAME=pull_request "${root}/gate/comment.sh" "${img}" "${FAKE_DIR}/report.md"
check "gate scan vex: the suppressed CVEs are in the pull request comment" logged "Suppressed by VEX (1)" gh.log
check "gate scan vex: ... and in the job summary" grep -q "CVE-2026-97054" "${GITHUB_STEP_SUMMARY}"

# VEX: findings remain
setup
echo 2 >"${FAKE_DIR}/${key}.rc"
echo 2 >"${FAKE_DIR}/${key}.vex.rc"
jq '.runs[0].tool.driver.rules += [{"id": "CVE-2026-97054", "properties": {"cvssV3_severity": "HIGH", "purls": ["pkg:golang/stdlib@1.27.3"], "fixed_version": "1.27.4"}}]' "${fx}/table.sarif" >"${FAKE_DIR}/${key}.sarif"
cp "${fx}/table.sarif" "${FAKE_DIR}/${key}.vex.sarif"
gate_scan IMAGE_SCAN_VEX_LOCATION="${fx}/vex"
check "gate scan vex: remaining findings still fail (2)" test $? -eq 2
check "gate scan vex: ... findings=true" grep -q "^findings=true$" "${GITHUB_OUTPUT}"
check "gate scan vex: ... three scans" count "^run " docker.log 3
check "gate scan vex: ... the table lists what is left" report_has "^### Vulnerabilities (5)$"
check "gate scan vex: ... the suppressed one is not in it" test "$(sed -n '/^### Vulnerabilities/,/^### Suppressed/p' "${FAKE_DIR}/report.md" | grep -c CVE-2026-97054)" -eq 0
check "gate scan vex: ... but listed as suppressed" report_has "^### Suppressed by VEX (1)$"

setup
echo 2 >"${FAKE_DIR}/${key}.rc"
echo 2 >"${FAKE_DIR}/${key}.vex.rc"
cp "${fx}/table.sarif" "${FAKE_DIR}/${key}.sarif"
gate_scan IMAGE_SCAN_VEX_LOCATION="${fx}/vex" IMAGE_SCAN_ENFORCE=false
check "gate scan vex advisory: remaining findings exit 0" test $? -eq 0
check "gate scan vex advisory: ... findings=true" grep -q "^findings=true$" "${GITHUB_OUTPUT}"
check "gate scan vex: nothing suppressed, no section" not report_has "Suppressed"

# best effort passes
setup
echo 2 >"${FAKE_DIR}/${key}.rc"
echo 10 >"${FAKE_DIR}/${key}.badsarif"
gate_scan
check "gate scan: a failing CVE listing does not change the outcome (2)" test $? -eq 2
check "gate scan: ... it warns" grep -q "^::warning::Cannot list the CVEs of ${img}" "${FAKE_DIR}/out.txt"
check "gate scan: ... the scanner report is kept" report_has "^# findings in ${img}$"
check "gate scan: ... findings=true" grep -q "^findings=true$" "${GITHUB_OUTPUT}"

setup
echo 2 >"${FAKE_DIR}/${key}.rc"
echo 0 >"${FAKE_DIR}/${key}.vex.rc"
echo 10 >"${FAKE_DIR}/${key}.badsarif"
gate_scan IMAGE_SCAN_VEX_LOCATION="${fx}/vex"
check "gate scan vex: failing to list the suppressed CVEs does not fail a clean scan" test $? -eq 0
check "gate scan vex: ... it warns" grep -q "^::warning::Cannot list the CVEs of ${img}" "${FAKE_DIR}/out.txt"
check "gate scan vex: ... the report stays the scanner's" test "$(cat "${FAKE_DIR}/report.md")" = "no findings"

setup
echo 2 >"${FAKE_DIR}/${key}.rc"
printf '{"runs": []}' >"${FAKE_DIR}/${key}.sarif"
gate_scan
check "gate scan: findings without a readable CVE still fail (2)" test $? -eq 2
check "gate scan: ... warn about it" grep -q "^::warning::The scanner reported vulnerabilities in ${img} but none could be read" "${FAKE_DIR}/out.txt"

setup
gate_scan IMAGE_SCAN_VEX_LOCATION="${FAKE_DIR}/nope"
check "gate scan vex: a missing location fails the scan" test $? -eq 1

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

# VEX documents: suppressed CVEs are no findings, so they open no issue
setup
echo 2 >"${FAKE_DIR}/ghcr.io_o_r_v1.2.3-amd64.rc"
echo 0 >"${FAKE_DIR}/ghcr.io_o_r_v1.2.3-amd64.vex.rc"
cp "${here}/fixtures/critical-and-high.sarif" "${FAKE_DIR}/ghcr.io_o_r_v1.2.3-amd64.sarif"
mkdir "${FAKE_DIR}/vex"
echo '{"author": "SF <sec@streamingfast.io>", "statements": [{"vulnerability": {"name": "CVE-2025-0001"}, "status": "not_affected", "justification": "component_not_present", "impact_statement": "risk-accepted #12"}]}' >"${FAKE_DIR}/vex/doc.json"
IMAGE_SCAN_VEX_LOCATION="${FAKE_DIR}/vex" "${root}/weekly/scan.sh" "${repo}" v1.2.3 "amd64" "${FAKE_DIR}/findings.json" >/dev/null 2>&1
check "weekly scan vex: everything suppressed exits 0" test $? -eq 0
check "weekly scan vex: ... no finding, so no issue" test "$(jq length "${FAKE_DIR}/findings.json")" -eq 0
check "weekly scan vex: the documents are mounted in the scan" logged "-v ${FAKE_DIR}/vex:/vex:ro" docker.log
check "weekly scan vex: the summary lists what was suppressed" grep -q "^- CVE-2025-0001 (critical) unknown unknown: component_not_present - risk-accepted #12 \[doc.json\] (statement not scoped to this image) \[ghcr.io/o/r:v1.2.3-amd64\]$" "${GITHUB_STEP_SUMMARY}"
check "weekly scan vex: ... and says no issue is opened" grep -q "no issue opened" "${GITHUB_STEP_SUMMARY}"

setup
echo 2 >"${FAKE_DIR}/ghcr.io_o_r_v1.2.3-amd64.rc"
cp "${here}/fixtures/critical-and-high.sarif" "${FAKE_DIR}/ghcr.io_o_r_v1.2.3-amd64.sarif"
cp "${here}/fixtures/high-only.sarif" "${FAKE_DIR}/ghcr.io_o_r_v1.2.3-amd64.vex.sarif"
echo 2 >"${FAKE_DIR}/ghcr.io_o_r_v1.2.3-amd64.vex.rc"
mkdir "${FAKE_DIR}/vex"
IMAGE_SCAN_VEX_LOCATION="${FAKE_DIR}/vex" "${root}/weekly/scan.sh" "${repo}" v1.2.3 "amd64" "${FAKE_DIR}/findings.json" >/dev/null 2>&1
check "weekly scan vex: remaining findings are reported" test "$(jq length "${FAKE_DIR}/findings.json")" -gt 0
check "weekly scan vex: ... without the suppressed one" test "$(jq '[.[] | select(.id == "CVE-2025-0001")] | length' "${FAKE_DIR}/findings.json")" -eq 0
check "weekly scan vex: ... which is in the summary" grep -q "CVE-2025-0001 (critical)" "${GITHUB_STEP_SUMMARY}"

setup
echo 2 >"${FAKE_DIR}/ghcr.io_o_r_v1.2.3-amd64.rc"
cp "${here}/fixtures/high-only.sarif" "${FAKE_DIR}/ghcr.io_o_r_v1.2.3-amd64.sarif"
"${root}/weekly/scan.sh" "${repo}" v1.2.3 "amd64" "${FAKE_DIR}/findings.json" >/dev/null 2>&1
check "weekly scan: without documents there is no extra scan" count "^run " docker.log 1
check "weekly scan: ... and no suppressed section" not grep -q "Suppressed" "${GITHUB_STEP_SUMMARY}"

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

# ---------------------------------------------------------------- gate/scan.sh: the pull request comment body
comment_has() { grep -q -- "$1" "${FAKE_DIR}/comment.md"; }
digest=sha256:d562353f9ef09d4eb64d75e0e5595268d2d64b21b180d6d6281c2bbcbd170e99
gate_scan_comment() { : >"${GITHUB_OUTPUT}"; env IMAGE_SCAN_RETRIES=1 "$@" "${root}/gate/scan.sh" "${img}" "${FAKE_DIR}/report.md" "${FAKE_DIR}/comment.md" >"${FAKE_DIR}/out.txt" 2>&1; }

setup
gate_scan_comment
check "gate comment: clean is one line" test "$(cat "${FAKE_DIR}/comment.md")" = "✅ Image scan: no critical/high vulnerabilities in ${img}"
check "gate comment: ... the job summary report stays the scanner's" test "$(cat "${FAKE_DIR}/report.md")" = "no findings"

setup
echo "digest	${digest}" >"${FAKE_DIR}/${key}.md"
gate_scan_comment
check "gate comment: clean names the short digest when the report has it" test "$(cat "${FAKE_DIR}/comment.md")" = "✅ Image scan: no critical/high vulnerabilities in ${img} (d562353f9ef0)"

setup
gate_scan_comment IMAGE_SCAN_SEVERITIES="critical, high,medium"
check "gate comment: clean follows the severities" comment_has "no critical/high/medium vulnerabilities"

setup
echo 0 >"${FAKE_DIR}/${key}.rc"
echo 2 >"${FAKE_DIR}/${key}.vex.rc"
cp "${fx}/table.sarif" "${FAKE_DIR}/${key}.vex.sarif"
gate_scan_comment IMAGE_SCAN_VEX_LOCATION="${fx}/vex"
check "gate comment: clean with VEX counts the accepted CVEs" test "$(head -n1 "${FAKE_DIR}/comment.md")" = "✅ Image scan: no critical/high vulnerabilities in ${img}, 5 accepted via VEX"
check "gate comment: ... and lists them collapsed" comment_has "^<details><summary>Accepted via VEX (5)</summary>$"
check "gate comment: ... closed" comment_has "^</details>$"

setup
echo 2 >"${FAKE_DIR}/${key}.rc"
cp "${fx}/table.sarif" "${FAKE_DIR}/${key}.sarif"
gate_scan_comment
check "gate comment findings: the CVE table comes first" test "$(head -n1 "${FAKE_DIR}/comment.md")" = "### Vulnerabilities (5)"
check "gate comment findings: the scanner report is collapsed" comment_has "^<details><summary>Scanner report</summary>$"
check "gate comment findings: ... after the table" test "$(grep -n '^| CVE' "${FAKE_DIR}/comment.md" | head -n1 | cut -d: -f1)" -lt "$(grep -n '<details>' "${FAKE_DIR}/comment.md" | head -n1 | cut -d: -f1)"
check "gate comment findings: ... holding the report" comment_has "^# findings in ${img}$"
check "gate comment findings: ... closed" comment_has "^</details>$"
check "gate comment findings: the job summary report is not collapsed" not report_has "<details>"

setup
echo 2 >"${FAKE_DIR}/${key}.rc"
cp "${fx}/table.sarif" "${FAKE_DIR}/${key}.sarif"
gate_scan_comment IMAGE_SCAN_ENFORCE=false
check "gate comment advisory: keeps the banner first" test "$(head -n1 "${FAKE_DIR}/comment.md")" = "> [!WARNING]"
check "gate comment advisory: ... and the collapsed report" comment_has "<details><summary>Scanner report</summary>"
