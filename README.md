# streamingfast/actions

Public composite GitHub Actions shared across StreamingFast repositories.

## sfreleaser

Releases a project from its `CHANGELOG.md` with [sfreleaser](https://github.com/streamingfast/sfreleaser). A pull request adding a version to the changelog drafts the release, merging it publishes the release.

| Action | Purpose |
|---|---|
| `sfreleaser/detect` | Installs sfreleaser, outputs `version`, `is_release_pr`, `variant` and `preview_comment` |
| `sfreleaser/prepare` | Runs `sfreleaser release prepare` |
| `sfreleaser/publish` | Runs `sfreleaser release publish`, then starts `build-workflow` on the tag unless the variant is `chain` |

A tag made with the GitHub Actions token triggers no workflow, so `publish` starts the build workflow itself. That workflow needs a `workflow_dispatch` trigger and must exist on the default branch.

### `.github/workflows/draft-release.yml`

```yaml
name: Draft release

on:
  pull_request:
    branches:
      - "develop"
    paths:
      - "CHANGELOG.md"

permissions:
  contents: write
  pull-requests: write

concurrency:
  group: draft-release-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  draft-release:
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout repository
        uses: actions/checkout@v6
        with:
          ref: ${{ github.head_ref }}
          fetch-depth: 0

      - name: Detect version
        id: detect
        uses: streamingfast/actions/sfreleaser/detect@v1

      - name: Prepare release
        if: steps.detect.outputs.is_release_pr
        uses: streamingfast/actions/sfreleaser/prepare@v1
        with:
          version: ${{ steps.detect.outputs.version }}
          homebrew-tap-token: ${{ secrets.HOMEBREW_TAP_TOKEN }}
```

A Go application sets up Go before `Prepare release` (`actions/setup-go`, and the `~/.cache/sfreleaser` and `~/.cache/zig` cache).

### `.github/workflows/publish-release.yml`

```yaml
name: Publish release

on:
  pull_request:
    types:
      - closed
    branches:
      - "develop"
    paths:
      - "CHANGELOG.md"

permissions:
  actions: write
  contents: write

concurrency:
  group: publish-release-${{ github.event.pull_request.number }}
  cancel-in-progress: false

jobs:
  publish:
    if: github.event.pull_request.merged && github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout repository
        uses: actions/checkout@v6
        with:
          ref: ${{ github.event.pull_request.merge_commit_sha }}
          fetch-depth: 0

      - name: Detect version
        id: detect
        uses: streamingfast/actions/sfreleaser/detect@v1
        with:
          before: ${{ github.event.pull_request.merge_commit_sha }}^1

      - name: Publish release
        if: steps.detect.outputs.is_release_pr
        uses: streamingfast/actions/sfreleaser/publish@v1
        with:
          version: ${{ steps.detect.outputs.version }}
          variant: ${{ steps.detect.outputs.variant }}
          build-workflow: docker.yml
          homebrew-tap-token: ${{ secrets.HOMEBREW_TAP_TOKEN }}
```

## Tagging

Consumers pin to `@v1`, a moving tag updated on every backward-compatible change:

```bash
git tag -f v1 && git push origin v1 --force
```
