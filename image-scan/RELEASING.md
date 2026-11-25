# image-scan: layout and release

## Layout

```
image-scan/
  gate/action.yml, weekly/action.yml   the actions: inputs/outputs of v1, one step running run.sh
  run.sh                               the shim: docker pull (3 attempts), docker run with the mounts and env
  Dockerfile                           Go program + Docker Scout CLI, every base pinned by digest
  cmd/image-scan                       `image-scan gate|weekly|version`, reads IMAGE_SCAN_* and GITHUB_* from the environment
  internal/gate                        scope, image, skip, scan, report, comment, promote
  internal/weekly                      weekly scan, one issue per CVE
  internal/scanner                     the Docker Scout subprocess: retries, exit codes, VEX validation
  internal/scout                       SARIF reading (rules, severities, purls)
  internal/vex                         OpenVEX statements, product matching to the scanned image
  internal/report                      log table, markdown tables
  internal/github, internal/registry   GitHub REST client, digest and registry-side retag (go-containerregistry)
  internal/testutil, testdata          fakes (scanner, GitHub, registry) and the fixtures, the real sf-analytics VEX files included
```

`cd image-scan && go test ./...` runs everything, no network.

What the shim passes to the container: `IMAGE_SCAN_*`, `GITHUB_*` and `RUNNER_*` variables by name (never `-e NAME=value`, so secrets stay off the command line), the runner temp directory (read-write: `GITHUB_OUTPUT`, `GITHUB_STEP_SUMMARY`), the workspace read-only (`vex-location`, `scan-paths`), the Docker config of the runner read-only (`promote-tags`), and runs as the runner user. The pull request number reaches the program as `IMAGE_SCAN_PR_NUMBER`, the event payload is not mounted. The Docker Scout CLI runs in the same container with its own empty Docker config.

## Release sequence

`run.sh` pins the image by digest, which only exists once the image is built, so the pin is its own commit:

1. Merge to `main`. The workflow builds the image from the commit (`ghcr.io/streamingfast/image-scan:sha-<commit>`, amd64 + arm64), writes its digest in the job summary, and scans it with the gate it contains.
2. Commit the digest in `image-scan/run.sh` (the `image=` line). Nothing the image is built from changes, so the pin commit does not rebuild it.
3. Add `## v1.x.y` to `CHANGELOG.md`, tag the pin commit `v1.x.y` and push the tag.
4. The workflow checks that `run.sh` pins a built image whose revision label has the same `Dockerfile`, `go.*`, `cmd` and `internal` as the tag, then adds the tags `v1.x.y` and `v1` to the image by digest (no rebuild, an existing version tag is never overwritten).
5. Move the `v1` git tag: `git tag -f v1 && git push origin v1 --force`. Every caller of `@v1` runs the new release from then on: try it from one repository with `@v1.x.y` before moving `v1`.

Bootstrap: the first pin of `run.sh` is the digest of the first build, until then the action fails on purpose. The workflow needs the `DOCKERHUB_USER` and `DOCKERHUB_PASSWORD` secrets for the self-scan, and the `ghcr.io/streamingfast/image-scan` package must be readable by the callers (public, or internal and shared with the organisation repositories).

## One release line

The tags of the repository cover every action (`sfreleaser/*` too), and image-scan keeps the `v1` line: the Go rewrite has the same inputs, outputs and exit codes as the bash version, differences found after the release are fixed in `v1.x.y`. A `v1.x.y` tag that only changes `sfreleaser/*` also adds its tags to the pinned image, which must still have been built from the code of the tag.

## The Docker Scout CLI

`docker/scout-cli` is released under the [Docker Subscription Service Agreement](https://www.docker.com/legal/docker-subscription-service-agreement/), not an open source licence, and the image republishes its binary. Bump it by hand in the `Dockerfile` (tag and digest).
