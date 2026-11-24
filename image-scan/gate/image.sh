#!/usr/bin/env bash
# Resolve the image to scan, writes `image=` to $GITHUB_OUTPUT.
#
# IMAGE is used as is when set. Otherwise it is <IMAGE_REPOSITORY>:<version>-<architecture>, the tags of the StreamingFast
# docker workflows: version is the tag name on a tag build, the first 7 characters of the commit otherwise, and the
# architecture the one of the runner.
set -euo pipefail

image="${IMAGE:-}"

if [[ -z "${image}" ]]; then
  repository="${IMAGE_REPOSITORY:?image-repository required when image is empty}"
  ref="${GITHUB_REF:-}"
  version="${GITHUB_SHA:?}"
  version="${version::7}"
  if [[ "${ref}" == refs/tags/* ]]; then version="${ref#refs/tags/}"; fi

  case "${RUNNER_ARCH:?}" in
    X64) arch=amd64 ;;
    ARM64) arch=arm64 ;;
    *)
      echo "::error::Unsupported runner architecture ${RUNNER_ARCH}, set image"
      exit 1
      ;;
  esac

  image="${repository}:${version}-${arch}"
fi

echo "Image to scan: ${image}"
echo "image=${image}" >>"${GITHUB_OUTPUT:?}"
