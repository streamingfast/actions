# streamingfast/actions

Public composite GitHub Actions shared across StreamingFast repositories.

## sfreleaser

Releases a project from its `CHANGELOG.md` with [sfreleaser](https://github.com/streamingfast/sfreleaser). A pull request adding a version to the changelog drafts the release, merging it publishes the release.

| Action | Purpose |
|---|---|
| `sfreleaser/detect` | Installs sfreleaser (`sfreleaser-version`, latest by default), outputs `version`, `is_release_pr` and `preview_comment` |
| `sfreleaser/prepare` | Runs `sfreleaser release prepare` |
| `sfreleaser/publish` | Runs `sfreleaser release publish` (installing sfreleaser when `detect` did not run), then starts `build-workflow` on the tag when set |

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
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write

concurrency:
  group: draft-release-${{ github.event.pull_request.number || github.ref_name }}
  cancel-in-progress: true

jobs:
  draft-release:
    if: github.event_name == 'workflow_dispatch' || github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout repository
        uses: actions/checkout@v6
        with:
          ref: ${{ github.head_ref || github.ref_name }}
          fetch-depth: 0

      - name: Detect release PR
        id: detect
        uses: streamingfast/actions/sfreleaser/detect@v1

      - name: Prepare release
        if: steps.detect.outputs.is_release_pr
        uses: streamingfast/actions/sfreleaser/prepare@v1
        with:
          version: ${{ steps.detect.outputs.version }}
          homebrew-tap-token: ${{ secrets.HOMEBREW_TAP_TOKEN }}
```

A Go application built with `builder: native` adds these steps before `Prepare release`. A repo linking wasmtime-go pins `go-version: '1.27.3'` instead of `go-version-file`, as Go 1.27.4 rejects the `libwasmtime.a` it bundles:

```yaml
      - name: Set up Go
        if: steps.detect.outputs.is_release_pr
        uses: actions/setup-go@v6
        with:
          go-version-file: go.mod

      - name: Cache zig
        if: steps.detect.outputs.is_release_pr
        uses: actions/cache@v6
        with:
          path: |
            ~/.cache/sfreleaser
            ~/.cache/zig
          key: ${{ runner.os }}-zig-${{ github.base_ref }}
```

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
  workflow_dispatch:
    inputs:
      tag:
        description: "Release tag to run the publish steps for again, e.g. v1.2.3"
        required: true

permissions:
  actions: write
  contents: write

concurrency:
  group: publish-release-${{ github.event.pull_request.number || inputs.tag }}
  cancel-in-progress: false

jobs:
  publish:
    if: github.event_name == 'workflow_dispatch' || (github.event.pull_request.merged && github.event.pull_request.head.repo.full_name == github.repository)
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout repository
        uses: actions/checkout@v6
        with:
          ref: ${{ github.event.pull_request.merge_commit_sha || inputs.tag }}
          fetch-depth: 0

      - name: Detect release PR
        id: detect
        if: github.event_name == 'pull_request'
        uses: streamingfast/actions/sfreleaser/detect@v1
        with:
          before: ${{ github.event.pull_request.merge_commit_sha }}^1

      - name: Publish release
        if: steps.detect.outputs.is_release_pr || github.event_name == 'workflow_dispatch'
        uses: streamingfast/actions/sfreleaser/publish@v1
        with:
          version: ${{ steps.detect.outputs.version || inputs.tag }}
          build-workflow: docker.yml
          homebrew-tap-token: ${{ secrets.HOMEBREW_TAP_TOKEN }}
```

Started by hand with a `tag`, it publishes that release again, for a run that failed partway.

A repo publishing crates with crates.io Trusted Publishing adds `id-token: write` to `permissions`, this step before `Publish release`, and `cargo-registry-token: ${{ steps.crates-io.outputs.token }}` to its inputs:

```yaml
      - name: Authenticate with crates.io
        id: crates-io
        if: steps.detect.outputs.is_release_pr || github.event_name == 'workflow_dispatch'
        uses: rust-lang/crates-io-auth-action@v1
```

`sfreleaser tools crates setup-trusted-publisher` registers `publish-release.yml` as the Trusted Publisher of the repository's crates.

## Tagging

Consumers pin to `@v1`, a moving tag updated on every backward-compatible change:

```bash
git tag -f v1 && git push origin v1 --force
```
