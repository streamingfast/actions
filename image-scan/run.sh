#!/usr/bin/env bash
# Runs `image-scan <gate|weekly>` in the container image of this release, pinned by digest: the pull is retried (3 attempts,
# linear backoff), then the action inputs (IMAGE_SCAN_*) and the GitHub context (GITHUB_*, RUNNER_*) go in by name, never on the
# command line. Mounts: the runner temp directory (GITHUB_OUTPUT, GITHUB_STEP_SUMMARY), the workspace read-only (vex-location,
# scan-paths) and the Docker config of the runner read-only (registry credentials of promote-tags). The exit code is the one of
# the program: 0 clean, 2 findings, 10 infrastructure failure, 1 anything else.
set -euo pipefail

# pinned at release (see image-scan/RELEASING.md), IMAGE_SCAN_RUNNER_IMAGE overrides it for the self-scan of the build workflow
image="${IMAGE_SCAN_RUNNER_IMAGE:-ghcr.io/streamingfast/image-scan@sha256:0000000000000000000000000000000000000000000000000000000000000000}"

for attempt in 1 2 3; do
  docker pull --quiet "${image}" >/dev/null && break
  if ((attempt == 3)); then echo "::error::Cannot pull ${image}"; exit 10; fi
  echo "::warning::Pulling the image-scan image failed on attempt ${attempt}/3"; sleep $((attempt * 10))
done

args=(--rm --user "$(id -u):$(id -g)" -w "${GITHUB_WORKSPACE}" -v "${RUNNER_TEMP}:${RUNNER_TEMP}" -v "${GITHUB_WORKSPACE}:${GITHUB_WORKSPACE}:ro")
while IFS= read -r name; do args+=(-e "${name}"); done < <(compgen -e | grep -E '^(IMAGE_SCAN_|GITHUB_|RUNNER_)')
docker_config="${DOCKER_CONFIG:-${HOME}/.docker}"
if [[ -d "${docker_config}" ]]; then args+=(-v "${docker_config}:/docker-config:ro" -e DOCKER_CONFIG=/docker-config); fi

exec docker run "${args[@]}" "${image}" "$1"
