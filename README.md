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
| `image-scan/gate` | CI gate: fails on findings (unless advisory), names the CVEs, honors VEX risk acceptances, writes the report to the job summary and, on a pull request, a quiet comment (nothing when clean) |
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
| `vex-location` | empty | File or directory of [OpenVEX](https://openvex.dev) documents in the caller repository (like `.github/vex/`): a `not_affected` statement suppresses its CVE, see [Risk acceptance with VEX](#risk-acceptance-with-vex). Needs the repository checked out |
| `vex-author` | `.*` | Regular expression of the statement authors to accept (`docker scout --vex-author`, whose own default only accepts `docker.com` authors) |
| `enforce` | `true` | `false` is the [advisory mode](#advisory-mode): findings are reported as warnings, never fail the build and never block `promote-tags` |
| `github-token` | `github.token` | Posts the PR comment (shown as `github-actions[bot]`, needs `pull-requests: write`) and the issue of a skipped scan (needs `issues: write`). Pass the bot user's token to post as that user |

Output `findings` is `true` when the scan found vulnerabilities (the ones suppressed by `vex-location` do not count), `false` otherwise, also when the scan did not run. With `enforce: true` the action fails on findings anyway, so the output is for `enforce: false` callers. Output `scanned` is `true` when the scan was needed and `false` when `scan-paths` or `skip-reason` skipped it (a failing scan fails the action). Output `skipped` is `true` when `skip-reason` bypassed the scan, `false` otherwise. Output `promoted` is the newline separated list of tags added by `promote-tags`, empty when none was.

On findings the log and the job summary (and so the PR comment) name the CVEs first, before the scanner's own report, from a second scan in SARIF (`Detected 11 vulnerable packages with a total of 53 vulnerabilities` only counts them):

```
CVE             SEVERITY  PACKAGE  INSTALLED  FIXED
CVE-2026-97054  high      stdlib   1.27.3     1.27.4
```

`FIXED` is `no fix` when there is no fixed version. The listing is best effort: when that second scan fails the action warns, the report has no table and the outcome is the one of the first scan.

Exit codes of the scanner: findings fail the step right away (no retry), anything else (login, pull, authentication, database fetch) is retried with a linear backoff and then fails. The PR comment is found by a hidden marker containing the image, so a matrix of architectures keeps one comment each, and is best-effort (`continue-on-error`).

The job summary always holds the full report. The PR comment is quieter:

- **clean scan**: nothing is posted. When an earlier (failing) run of the pull request already left the comment, it is updated to one line, `✅ Image scan: no critical/high vulnerabilities in <image> (<short digest>)`, so the pull request shows the problem is resolved. With `vex-location` the line adds `, N accepted via VEX` and a collapsed list of those CVEs, an accepted risk stays visible;
- **findings** (also in advisory mode, with its banner): the CVE table first, the long scanner report in a collapsed `<details>` block;
- **skipped scan** (`scan-paths` or `skip-reason`): no comment is added (`skip-reason` still records itself in the summary and the issue).

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

#### Risk acceptance with VEX

A CVE that cannot be fixed yet (the fix is not released) can be accepted with a [VEX](https://openvex.dev) statement kept in the repository, reviewed in a pull request, instead of bypassing the whole gate with `skip-reason`. Set `vex-location` to a file or a directory of OpenVEX documents (`*.json`, `*.jsonld`): it is mounted read-only into the scanner container and passed to `docker scout cves --vex-location` with `--vex-author`.

What Docker Scout does with the documents ([Docker documentation](https://docs.docker.com/scout/how-tos/create-exceptions-vex/)):

- **only `not_affected` suppresses a CVE.** `fixed`, `affected` and `under_investigation` are documentation, they suppress nothing, and the gate warns about such a statement (`under_investigation` is therefore not a risk acceptance, the gate keeps failing);
- the default `--vex-author` only accepts `<.*@docker.com>` authors, the gate passes `.*` (`vex-author`) so the statements of the repository apply; restrict it to your team if the repository accepts documents from other places;
- a suppressed CVE is neither in the report nor in the exit code.

An exception must stay visible, so on every run the log, the job summary and the PR comment list the suppressed CVEs under **Suppressed by VEX** with the justification, impact statement, author and date of the statement, and the action warns about statements that cannot work (not `not_affected`) or match no finding any more (the fix shipped, remove them). To list them the gate scans a second time without the documents.

Example, `.github/vex/firehose-stellar.openvex.json`, for the Go standard library CVE of a binary copied from `firehose-core` (built with Go 1.27.3, fixed in Go 1.27.4):

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/streamingfast/firehose-stellar/.github/vex/firehose-stellar.openvex.json",
  "author": "Platform Team <platform@streamingfast.io>",
  "timestamp": "2026-11-24T00:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2026-97054"},
      "products": [{"@id": "pkg:docker/streamingfast/firehose-stellar"}],
      "status": "not_affected",
      "justification": "inline_mitigations_already_exist",
      "impact_statement": "Risk accepted, see https://github.com/streamingfast/firehose-stellar/issues/57. Fixed in Go 1.27.4, remove when firecore is rebuilt with it",
      "timestamp": "2026-11-24T10:00:00Z"
    }
  ]
}
```

```yaml
      - uses: actions/checkout@v7 # the documents are read from the workspace
      # ... build and push the image ...
      - uses: streamingfast/actions/image-scan/gate@v1
        with:
          dockerhub-user: ${{ secrets.DOCKER_SCOUT_USER }}
          dockerhub-password: ${{ secrets.DOCKER_SCOUT_PASSWORD }}
          vex-location: .github/vex/
```

Rules of the exceptions (SDLC policy):

- every statement links its `risk-accepted` issue in `impact_statement` (the issue holds the risk assessment and the approval) and the pull request adding it is the approval trail;
- `justification` is one of the OpenVEX values (`component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`), the statement must be true: pick the one that holds, and if none does the CVE is not an exception to hide but a bypass to record with `skip-reason`;
- remove the statement (and close the issue) in the pull request that ships the fix. The gate notices the statement matching no finding any more, but only a person removes it;
- `products` must match the image: the example uses the purl of the repository without a version, so it holds for every tag and digest. The OpenVEX document is not validated against the image by the gate, check the first run: the CVE must be listed under **Suppressed by VEX**, if it stays in **Vulnerabilities** the product or the author did not match.

`image-scan/weekly` takes the same `vex-location` and `vex-author` inputs: a CVE suppressed by a statement is not reported, so it opens no issue, an issue open for it is closed (with the usual comment, which then reads as a fix) and the job summary lists the suppressed CVEs.

#### Advisory mode

A repository that ships binaries of an upstream project cannot fix their CVEs (a fork of an upstream chain node, for example) and may decide not to enforce the gate. `enforce: false`:

- scans and reports as usual: job summary, CVE table, PR comment (with an advisory banner) and the CVEs named in the log;
- annotates the findings with `::warning::` instead of `::error::` and exits 0;
- applies `promote-tags` as it does on a clean scan: nothing blocks the release;
- sets the output `findings` to `true`, for a later step to alert on (a Slack message, an issue).

A scan that cannot run (login, pull, database fetch, after the retries) still fails the action even then: nothing is known about the image, and a silent pass would hide a broken scanner. `skip-reason` and `scan-paths` work as usual.

```yaml
      - id: scan
        uses: streamingfast/actions/image-scan/gate@v1
        with:
          dockerhub-user: ${{ secrets.DOCKER_SCOUT_USER }}
          dockerhub-password: ${{ secrets.DOCKER_SCOUT_PASSWORD }}
          enforce: false
          promote-tags: ${{ steps.meta.outputs.tags }}

      - name: Alert on findings
        if: ${{ steps.scan.outputs.findings == 'true' }}
        run: echo "::notice::Vulnerabilities in the image, see the job summary"
```

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
| `vex-location`, `vex-author` | empty, `.*` | OpenVEX documents, see [Risk acceptance with VEX](#risk-acceptance-with-vex) |
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
