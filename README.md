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

## image-scan

Scans container images for critical/high vulnerabilities. The scanner is an implementation detail (Docker Scout today, run from the pinned `docker/scout-cli` image in `image-scan/lib/scanner.sh`), names and inputs are scanner-agnostic so a switch to Trivy or Grype renames nothing.

| Action | Purpose |
|---|---|
| `image-scan/gate` | CI gate: fails on findings, writes the report to the job summary and, on a pull request, to a comment |
| `image-scan/weekly` | Scans the latest release and keeps one GitHub issue per CVE |

Both need a Docker Hub account for the scanner (`dockerhub-user`, `dockerhub-password`) and run on a `ubuntu-*` runner (`date -d` is GNU only, `image-scan/weekly/issues.sh` falls back to BSD `date -v`).

### `image-scan/gate`

| Input | Default | |
|---|---|---|
| `image` | `<image-repository>:<tag or commit[:7]>-<runner arch>` | Image to scan, it must be pushed to a registry the scanner can read (the runner's local Docker daemon is not visible to the scanner). The default is the tag of the StreamingFast docker workflows: the tag name on a tag build, the first 7 characters of the commit otherwise, `amd64` or `arm64` from the runner |
| `image-repository` | `ghcr.io/<repository>` | Used when `image` is empty |
| `dockerhub-user`, `dockerhub-password` | required | Docker Hub credentials |
| `registry-user`, `registry-password` | `github.actor`, `github.token` | To read the image from its registry |
| `severities` | `critical,high` | |
| `retries` | `3` | Attempts for infrastructure failures, findings fail at once |
| `scan-paths` | empty | Newline separated extended regexes (anchor with `^`). On a `pull_request` the scan is skipped unless a file changed by the PR matches one. Empty always scans |
| `promote-tags` | empty | Newline or comma separated full image refs added to the image once the scan is clean, see [Blocking a single-push release](#blocking-a-single-push-release) |
| `skip-reason` | empty | Audited emergency bypass of the scan, only honored on `workflow_dispatch`, see [Emergency bypass](#emergency-bypass) |
| `github-token` | `github.token` | Posts the PR comment (shown as `github-actions[bot]`, needs `pull-requests: write`) and the issue of a skipped scan (needs `issues: write`). Pass the bot user's token to post as that user |

Output `scanned` is `true` when the scan was needed and `false` when `scan-paths` or `skip-reason` skipped it (a failing scan fails the action). Output `skipped` is `true` when `skip-reason` bypassed the scan, `false` otherwise. Output `promoted` is the newline separated list of tags added by `promote-tags`, empty when none was.

Exit codes of the scanner: findings fail the step right away (no retry), anything else (login, pull, authentication, database fetch) is retried with a linear backoff and then fails. The PR comment is found by a hidden marker containing the image, so a matrix of architectures keeps one comment each, and is best-effort (`continue-on-error`).

`scan-paths` diffs `HEAD^1 HEAD`, the checkout of a `pull_request` being the merge commit: check out with `fetch-depth: 2`. The image build stays the caller's and runs either way. The caller keeps its own `if:` for fork and dependabot pull requests, which have no access to secrets.

In the `docker.yml` of the repository, after `Build and push Docker image`, with `Check if scan is needed`, `Docker Scout` and `Publish Scout report` replaced by:

```yaml
      - uses: actions/checkout@v7
        with:
          # 2 commits so a PR merge commit can be diffed against its base (first parent)
          fetch-depth: ${{ github.event_name == 'pull_request' && 2 || 1 }}

      # ... build and push the image ...

      # The image is always built, only the scan is skipped on pull requests that cannot change its contents.
      - name: Scan the image
        if: ${{ (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository) && github.actor != 'dependabot[bot]' }}
        uses: streamingfast/actions/image-scan/gate@v1
        with:
          dockerhub-user: ${{ secrets.DOCKER_SCOUT_USER }}
          dockerhub-password: ${{ secrets.DOCKER_SCOUT_PASSWORD }}
          # Comment as the bot user (sf-slack-ops forwards GitHub comments to Slack), github-actions[bot] when omitted
          github-token: ${{ secrets.PR_COMMENTER }}
          # Paths that affect the image contents, keep in sync with the Dockerfile COPY/ADD sources
          scan-paths: |
            ^Dockerfile
            ^go\.mod
            ^go\.sum
            ^\.dockerignore
            ^docker/

      - name: Get Job ID from GH API
        # ... Slack failure steps unchanged ...
```

With the defaults the image is `ghcr.io/<repository>:<version>-<architecture>`, set `image` when the repository tags differently. The job needs `permissions: contents: read`, `packages: write` and `pull-requests: write`.

#### Blocking a single-push release

A repository that builds and pushes one multi-arch image with a single `docker/build-push-action` step, release tags included (`vX.Y.Z`, `develop`, `latest`, ...), cannot be blocked by the gate: the tags are live before the scan runs. Push only the immutable commit tag in the build and let the gate add the others with `promote-tags`:

1. Before the scan, the gate resolves the image to its digest.
2. After a **clean** scan, it checks the image still has that digest (a moved tag fails the action) and adds each tag to it with `docker buildx imagetools create --tag <tag> ... <image>@<digest>`: a registry-side retag, no rebuild, the multi-arch index and its attestations are kept. The tag equal to the scanned image is skipped, a failed call is retried (`retries`) and a promotion that still fails fails the action.
3. On findings (exit 2) or when the scanner cannot run (exit 10), nothing is promoted and the release tags never exist.

When `scan-paths` skips the scan (only on a pull request) the tags are promoted anyway: the skip means the pull request cannot change the image, and the tags of a pull request build are throwaway.

`imagetools` runs on the runner's Docker daemon, so the job must already be logged in to the registry of the image and of the tags with push access (the build needs it as well), the registry credentials of the gate are not used for this and never reach the scanner container.

```yaml
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ github.token }}

      # Release and moving tags, promoted by the gate once the image is clean
      - name: Tags to promote
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ghcr.io/${{ github.repository }}
          tags: |
            type=ref,event=branch
            type=semver,pattern={{version}}
            type=raw,value=latest,enable={{is_default_branch}}

      # The immutable tag only: the commit sha, `image` of the gate
      - name: Tag to push
        id: sha
        uses: docker/metadata-action@v5
        with:
          images: ghcr.io/${{ github.repository }}
          tags: type=sha,format=short,prefix=

      - uses: docker/build-push-action@v6
        with:
          push: true
          platforms: linux/amd64,linux/arm64
          tags: ${{ steps.sha.outputs.tags }}

      - uses: streamingfast/actions/image-scan/gate@v1
        with:
          image: ${{ steps.sha.outputs.tags }}
          promote-tags: ${{ steps.meta.outputs.tags }}
          dockerhub-user: ${{ secrets.DOCKER_SCOUT_USER }}
          dockerhub-password: ${{ secrets.DOCKER_SCOUT_PASSWORD }}
```

Two `docker/metadata-action` steps produce the two lists, one with only `type=sha` for `build-push-action`, the other with all the tags for `promote-tags` (a sha tag listed in both is skipped by the gate as it is the scanned image). Filtering one list instead works too, `image` must be a single tag. The commit sha tag stays in the registry whatever the scan says, it is the only tag that exists for an image that failed.

#### Emergency bypass

A release can be urgent (a hard-fork upgrade with a deadline) while the gate fails on a CVE in upstream code that cannot be fixed in time, or the scanner is down. `skip-reason` is a documented, auditable exception, not a silent skip. When it is not blank **and** the run is a `workflow_dispatch`:

- the scan does not run, `promote-tags` still does (the digest is resolved first, as usual) and the outputs are `skipped=true`, `scanned=false`;
- a `::warning::` and a job summary section record the image and digest, `github.actor`, the reason, the run URL and the time;
- a GitHub issue titled `Image scan skipped: <image>@<short digest>`, labelled `security` and `image-scan-skipped`, holds the same details and asks to re-scan the image and close the issue. The same image and digest skipped again comments the open issue instead. It needs `issues: write` on `github-token`: when the issue cannot be created the action warns and goes on, the release is not failed and the summary is still recorded.

On any other event (`push`, `pull_request`, `schedule`, ...) `skip-reason` is **ignored**, with a warning, and the image is scanned normally: a misconfigured workflow cannot bypass the gate. Without `skip-reason` nothing changes.

```yaml
on:
  push:
  workflow_dispatch:
    inputs:
      skip-scan-reason:
        description: Emergency only, skip the image scan. The reason is recorded in a GitHub issue
        required: false
        default: ""

permissions:
  contents: read
  packages: write
  issues: write # the issue recording a skipped scan

jobs:
  docker:
    runs-on: ubuntu-latest
    steps:
      # ... build and push the image ...
      - uses: streamingfast/actions/image-scan/gate@v1
        with:
          dockerhub-user: ${{ secrets.DOCKER_SCOUT_USER }}
          dockerhub-password: ${{ secrets.DOCKER_SCOUT_PASSWORD }}
          skip-reason: ${{ inputs.skip-scan-reason }}
```

Anyone who can dispatch the workflow (write access to the repository) can use the bypass. To require an approval, run the job in a protected GitHub environment (`environment:` on the job, with required reviewers): the dispatch then waits for a reviewer, whose approval is part of the audit trail. The issue is the record to follow up on, close it only once the image is scanned.

### `image-scan/weekly`

| Input | Default | |
|---|---|---|
| `image-repository` | `ghcr.io/<repository>` | Scanned as `<image-repository>:<release tag>-<architecture>` |
| `architectures` | `amd64 arm64` | Space separated |
| `dockerhub-user`, `dockerhub-password` | required | Docker Hub credentials |
| `registry-user`, `registry-password` | `github.actor`, `github.token` | To read the images from their registry |
| `retries` | `3` | Per image |
| `github-token` | `github.token` | Resolves the release and manages issues |

Output `slack-message` is multiline and empty when this run opened no issue. It is set even when the issue sync fails halfway, hence `!cancelled()` in the Slack step below, so issues already opened are still announced.

One issue per CVE, deduped by the hidden marker `<!-- image-scan-cve:ID -->`, labelled `security` and `severity:critical|high`. The due date is in the body (critical +7 days, high +30 days from the first detection, kept on refresh). A `risk-accepted` label makes the action leave the issue alone. An issue closed while labelled `risk-accepted` is not opened again, but one closed because the CVE was fixed loses that label, so a regression is tracked again. Duplicate open issues of a CVE are closed in favour of the oldest. An issue is closed, with a comment naming the release and its publish date, only when a complete scan (every architecture) of the latest release no longer reports the CVE: an infrastructure failure, or findings that cannot be read from the report, fails the job before any issue is touched. The issue title and description are rewritten on every scan, discuss in comments.

The severity comes from the report (`cvssV3_severity`, else `security-severity`) and defaults to `high` when absent.

### `.github/workflows/docker-scan-weekly.yml`

```yaml
name: Docker scan weekly

on:
  schedule:
    - cron: "17 6 * * 1" # Mondays 06:17 UTC
  workflow_dispatch:

permissions:
  contents: read
  packages: read
  issues: write

jobs:
  scan:
    runs-on: ubuntu-24.04
    steps:
      - name: Scan the latest release
        id: scan
        uses: streamingfast/actions/image-scan/weekly@v1
        with:
          dockerhub-user: ${{ secrets.DOCKER_SCOUT_USER }}
          dockerhub-password: ${{ secrets.DOCKER_SCOUT_PASSWORD }}

      - name: Notify new CVE issues on Slack
        if: ${{ !cancelled() && steps.scan.outputs.slack-message != '' }}
        env:
          SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
        uses: Ilshidur/action-slack@689ad44a9c9092315abd286d0e3a9a74d31ab78a # 2.1.0
        with:
          args: ${{ steps.scan.outputs.slack-message }}

      - name: Notify scan failure on Slack
        if: ${{ failure() }}
        env:
          SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
        uses: Ilshidur/action-slack@689ad44a9c9092315abd286d0e3a9a74d31ab78a # 2.1.0
        with:
          args: ":x: *${{ github.repository }}* Weekly image scan failed (<https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }}|See Actions Logs>) :broken_heart:"
```

The scripts are tested with a fake `docker` and `gh`: `image-scan/tests/run.sh`.

## Tagging

Consumers pin to `@v1`, a moving tag updated on every backward-compatible change:

```bash
git tag -f v1 && git push origin v1 --force
```
