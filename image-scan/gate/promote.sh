#!/usr/bin/env bash
# Add tags to the scanned image once it is known to be clean, a registry-side retag (no rebuild, the multi-arch index and
# its attestations are kept).
#
# Usage: promote.sh resolve|promote
#
#   resolve   Resolve IMAGE to its manifest digest, writes `digest=` to $GITHUB_OUTPUT. Run before the scan.
#   promote   Re-resolve IMAGE, fail when its digest is not EXPECTED_DIGEST anymore (the tag moved during the scan, what
#             was scanned is not what would be promoted), then add every PROMOTE_TAGS tag to <repository>@<digest> with
#             `docker buildx imagetools create`. Writes `promoted=` (newline separated tags) to $GITHUB_OUTPUT.
#
# Env:
#   IMAGE            the scanned image
#   PROMOTE_TAGS     newline or comma separated full image refs, the tag equal to IMAGE is skipped
#   EXPECTED_DIGEST  digest returned by `resolve` (promote only)
#   IMAGE_SCAN_RETRIES (default 3) / IMAGE_SCAN_BACKOFF (default 15, seconds, multiplied by the attempt number)
#
# The runner's Docker daemon does the work: the caller must already be logged in to the registry of the image and of the
# tags (the build step needs it too). Registry credentials are never given to the scanner for this.
set -uo pipefail

mode="${1:?resolve or promote required}"
image="${IMAGE:?image required}"
retries="${IMAGE_SCAN_RETRIES:-3}"
backoff="${IMAGE_SCAN_BACKOFF:-15}"

if ! [[ "${retries}" =~ ^[1-9][0-9]*$ ]]; then
  echo "::error::retries must be a positive integer, got '${retries}'"
  exit 1
fi

# retry <description> <command...>
retry() {
  local what="$1" i
  shift
  for ((i = 1; i <= retries; i++)); do
    if "$@"; then return 0; fi
    echo "::warning::${what} failed on attempt ${i}/${retries}"
    if ((i < retries)); then sleep $((backoff * i)); fi
  done
  return 1
}

# Writes the digest of "$1" in ${digest}
digest=""
inspect_digest() {
  local manifest
  manifest="$(docker buildx imagetools inspect --format '{{json .Manifest}}' "$1")" || return 1
  digest="$(jq -er '.digest' <<<"${manifest}")" || return 1
  [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]
}

resolve() {
  if ! retry "Resolving the digest of ${image}" inspect_digest "${image}"; then
    echo "::error::Cannot resolve the digest of ${image} after ${retries} attempts, is the image pushed and the runner logged in to its registry?"
    return 1
  fi
}

case "${mode}" in
  resolve)
    resolve || exit 1
    echo "Digest of ${image}: ${digest}"
    echo "digest=${digest}" >>"${GITHUB_OUTPUT:?}"
    ;;

  promote)
    expected="${EXPECTED_DIGEST:?expected digest required}"
    resolve || exit 1
    if [[ "${digest}" != "${expected}" ]]; then
      echo "::error::${image} points to ${digest} now, it was ${expected} when the scan started: nothing promoted, the scan does not cover that image"
      exit 1
    fi

    # <repository>@<digest>, the repository being the image without its tag or digest
    repository="${image%%@*}"
    if [[ "${repository##*/}" == *:* ]]; then repository="${repository%:*}"; fi
    source="${repository}@${digest}"

    tags=()
    while IFS= read -r tag; do
      tag="${tag//[[:space:]]/}"
      if [[ -z "${tag}" || "${tag}" == "${image}" || "${tag}" == "${source}" ]]; then continue; fi
      if [[ " ${tags[*]-} " == *" ${tag} "* ]]; then continue; fi
      tags+=("${tag}")
    done < <(tr ',' '\n' <<<"${PROMOTE_TAGS:-}")

    if ((${#tags[@]} == 0)); then
      echo "No tag to add to ${source}"
      echo "promoted=" >>"${GITHUB_OUTPUT:?}"
      exit 0
    fi

    args=()
    for tag in "${tags[@]}"; do args+=(--tag "${tag}"); done

    echo "Adding ${tags[*]} to ${source}"
    if ! retry "Adding the tags" docker buildx imagetools create "${args[@]}" "${source}"; then
      echo "::error::Cannot add ${tags[*]} to ${source} after ${retries} attempts, the image is clean but not promoted. Is the runner logged in to the registry of these tags with push access?"
      exit 1
    fi

    {
      echo "promoted<<PROMOTED_EOF"
      printf '%s\n' "${tags[@]}"
      echo "PROMOTED_EOF"
    } >>"${GITHUB_OUTPUT:?}"
    ;;

  *)
    echo "::error::unknown mode '${mode}'"
    exit 1
    ;;
esac
