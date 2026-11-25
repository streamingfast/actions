#!/usr/bin/env bash
# Scan a container image for vulnerabilities and report the outcome through the exit code.
#
# This is the only file that knows which scanner runs. Today it is Docker Scout (run from the docker/scout-cli
# image rather than docker/scout-action, which downloads a ~187 MB binary from a GitHub release on every run and
# flakes with 'Unexpected HTTP response: 403'). Switching to Trivy/Grype means changing this file and the
# machine-readable parsing in weekly/scan.sh, not the action names or inputs.
#
# Usage: scanner.sh <image> <output-file> [format]
#   format: markdown (default) or sarif
#
# Env:
#   IMAGE_SCAN_DOCKERHUB_USER / IMAGE_SCAN_DOCKERHUB_PASSWORD   Docker Hub credentials (pull of the scanner image + auth to the Scout backend), required
#   IMAGE_SCAN_REGISTRY_USER / IMAGE_SCAN_REGISTRY_PASSWORD     credentials to read <image> from its registry (optional)
#   IMAGE_SCAN_SEVERITIES (default critical,high)
#   IMAGE_SCAN_RETRIES (default 3) / IMAGE_SCAN_BACKOFF (default 15, seconds, multiplied by the attempt number)
#   IMAGE_SCAN_VEX_LOCATION   file or directory of OpenVEX documents, mounted read-only into the scanner container and passed to
#                             `--vex-location`. Only `not_affected` statements suppress a CVE (Scout ignores the other statuses).
#                             Relative to the current directory. Suppressed CVEs count neither in the report nor in the exit code
#   IMAGE_SCAN_VEX_AUTHOR     `--vex-author`, which VEX statement authors to accept (default .*, Scout's own default only accepts
#                             <.*@docker.com>, so no statement of ours would ever apply)
#   IMAGE_SCAN_FINDINGS_LEVEL workflow command level of the message printed on findings: error (default), warning, notice or debug
#
# Exit codes ('docker scout cves --exit-code': 0 = clean, 2 = vulnerabilities, anything else = error):
#   0   no finding at the requested severities
#   2   finding(s), report written to <output-file>. Never retried.
#   10  infra/setup failure (login, pull, auth, DB fetch, ...) after all retries
set -uo pipefail

# The scanner image, pinned by digest (supply-chain hygiene), bump by hand.
SCANNER_IMAGE="${IMAGE_SCAN_SCANNER_IMAGE:-docker/scout-cli:1.30.0@sha256:01f7e63d8ee0668b2c19f09920d7e7eff8d3e507ca931df2b8c00ae19b71d588}"

image="${1:?image required}"
output="${2:?output file required}"
format="${3:-markdown}"

severities="${IMAGE_SCAN_SEVERITIES:-critical,high}"
retries="${IMAGE_SCAN_RETRIES:-3}"
backoff="${IMAGE_SCAN_BACKOFF:-15}"

level="${IMAGE_SCAN_FINDINGS_LEVEL:-error}"
case "${level}" in
  error | warning | notice | debug) ;;
  *) echo "::error::IMAGE_SCAN_FINDINGS_LEVEL must be error, warning, notice or debug, got '${level}'"; exit 1 ;;
esac

if ! [[ "${retries}" =~ ^[1-9][0-9]*$ ]]; then
  echo "::error::retries must be a positive integer, got '${retries}'"
  exit 1
fi

: "${IMAGE_SCAN_DOCKERHUB_USER:?dockerhub-user required}"
: "${IMAGE_SCAN_DOCKERHUB_PASSWORD:?dockerhub-password required}"

# Keep the Docker Hub credentials out of ~/.docker/config.json of a non-ephemeral runner
DOCKER_CONFIG="$(mktemp -d)"
export DOCKER_CONFIG
trap 'rm -rf "${DOCKER_CONFIG}"' EXIT

# VEX documents: the scanner container only sees them through a read-only bind mount. A misconfiguration (missing path, a
# document that is not JSON) fails right away, retrying cannot fix it and an exception silently not applied is worse.
vex_mount=()
vex_args=()
if [[ -n "${IMAGE_SCAN_VEX_LOCATION:-}" ]]; then
  vex_path="${IMAGE_SCAN_VEX_LOCATION}"
  if [[ ! -e "${vex_path}" ]]; then
    echo "::error::vex-location '${vex_path}' does not exist"
    exit 1
  fi
  if [[ -d "${vex_path}" ]]; then
    vex_host="$(cd "${vex_path}" && pwd)"
    vex_target="/vex"
  else
    vex_host="$(cd "$(dirname "${vex_path}")" && pwd)/$(basename "${vex_path}")"
    vex_target="/vex/$(basename "${vex_path}")"
  fi
  if command -v jq >/dev/null 2>&1; then
    while IFS= read -r -d '' document; do
      if ! jq empty "${document}" 2>/dev/null; then
        echo "::error::vex-location: ${document} is not valid JSON"
        exit 1
      fi
    done < <(find "${vex_host}" -type f \( -name '*.json' -o -name '*.jsonld' \) -print0)
  fi
  vex_mount=(-v "${vex_host}:${vex_target}:ro")
  vex_args=(--vex-location "${vex_target}" --vex-author "${IMAGE_SCAN_VEX_AUTHOR:-.*}")
fi

# Registry credentials are optional, empty values are not passed at all
registry_env=()
if [[ -n "${IMAGE_SCAN_REGISTRY_USER:-}" && -n "${IMAGE_SCAN_REGISTRY_PASSWORD:-}" ]]; then
  registry_env=(-e DOCKER_SCOUT_REGISTRY_USER -e DOCKER_SCOUT_REGISTRY_PASSWORD)
fi

attempt() {
  # Login on every attempt: it can be the flaky part.
  printf '%s' "${IMAGE_SCAN_DOCKERHUB_PASSWORD}" | docker login --username "${IMAGE_SCAN_DOCKERHUB_USER}" --password-stdin >/dev/null || return 10
  docker pull --quiet "${SCANNER_IMAGE}" >/dev/null || return 10

  local rc

  # No Docker socket is mounted: the scanner pulls the image from its registry, which must be readable by the scanner.
  # Credentials are passed by name so they stay out of the process list.
  #
  # The report is not written by the container (--output): the scanner image runs as the non-root 'docker-scout' user
  # and cannot open a file created by the runner user (mktemp makes it 0600). Scout prints progress and logs on stderr
  # and only the report on stdout, so the host redirects stdout. No -t, which would merge the two streams. A redirect
  # that cannot be opened fails before docker runs (exit 1, retried), it can never mask a finding (exit 2).
  DOCKER_SCOUT_HUB_USER="${IMAGE_SCAN_DOCKERHUB_USER}" \
  DOCKER_SCOUT_HUB_PASSWORD="${IMAGE_SCAN_DOCKERHUB_PASSWORD}" \
  DOCKER_SCOUT_REGISTRY_USER="${IMAGE_SCAN_REGISTRY_USER:-}" \
  DOCKER_SCOUT_REGISTRY_PASSWORD="${IMAGE_SCAN_REGISTRY_PASSWORD:-}" \
  docker run --rm \
    -e DOCKER_SCOUT_HUB_USER \
    -e DOCKER_SCOUT_HUB_PASSWORD \
    ${registry_env[@]+"${registry_env[@]}"} \
    ${vex_mount[@]+"${vex_mount[@]}"} \
    "${SCANNER_IMAGE}" cves \
      --only-severity "${severities}" \
      ${vex_args[@]+"${vex_args[@]}"} \
      --exit-code \
      --format "${format}" \
      "${image}" >"${output}"
  rc=$?
  return "${rc}"
}

for ((i = 1; i <= retries; i++)); do
  echo "::group::Image scan of ${image} (attempt ${i}/${retries})"
  attempt
  rc=$?
  echo "::endgroup::"

  case "${rc}" in
    0) echo "No ${severities} vulnerability found in ${image}"; exit 0 ;;
    2) echo "::${level}::${severities} vulnerabilities found in ${image}"; exit 2 ;;
    *)
      echo "::warning::Scanner setup/infra failure (exit ${rc}) on attempt ${i}/${retries}"
      if ((i < retries)); then sleep $((backoff * i)); fi
      ;;
  esac
done

echo "::error::The image scan could not run on ${image} after ${retries} attempts"
exit 10
