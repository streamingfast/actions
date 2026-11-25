# Changelog

## v1.4.3

### Fixed

- Fix the **Suppressed by VEX** report of `image-scan/gate` and `image-scan/weekly` (log, job summary, PR comment, weekly summary) showing the wrong justification when several VEX documents speak about the same CVE: the statement was picked by CVE id only, across all documents. It is now picked among the statements whose `products` match the scanned image (`pkg:oci/<repo>?repository_url=<registry>` with or without `@sha256:` digest and `tag`, `pkg:docker/<registry>/<repo>`, plain repository names), all of them when several match, each with the name of its VEX file. A CVE suppressed only by a statement of another image falls back to the CVE id match, marked `(statement not scoped to this image)`. What Scout suppresses is unchanged, inputs, outputs and exit codes too
- Fix the VEX example of the README, `pkg:docker/...` products never match an image named by Scout (`pkg:oci/<repo>?repository_url=<registry>`): add the `ghcr.io` and `gcr.io` forms and a "VEX loaded but nothing suppressed?" troubleshooting note

## v1.4.2

### Fixed

- Fix `sfreleaser/publish` skipping `build-workflow` when `sfreleaser release publish` fails after the tag is created (like a Homebrew tap pull request merge failure), the build now still starts on an existing tag so the image is built and scanned

## v1.4.1

### Changed

- Quiet the pull request comment of `image-scan/gate`. A clean scan posts nothing, and when an earlier failing run already left the comment it is updated to one line, `✅ Image scan: no critical/high vulnerabilities in <image> (<short digest>)`, with `, N accepted via VEX` and a collapsed list of the CVEs suppressed by `vex-location`. On findings (also in advisory mode) the CVE table comes first and the scanner report is in a collapsed `<details>` block. The job summary keeps the full report in every case, and a skipped scan still adds no comment

## v1.4.0

### Added

- Add the optional `vex-location` and `vex-author` inputs to `image-scan/gate` and `image-scan/weekly`, a per-CVE risk acceptance: a file or directory of OpenVEX documents of the caller repository is mounted read-only into the scanner and passed to `docker scout cves --vex-location`, so a `not_affected` statement suppresses its CVE (Scout ignores the other statuses, the gate warns about them, and about statements matching no finding any more). `vex-author` (default `.*`) replaces Scout's default that only accepts `docker.com` authors. The gate lists the suppressed CVEs with the justification, author and date of the statement in the log, the job summary and the PR comment, from a second scan without the documents. The weekly action opens no issue for a suppressed CVE and lists them in its summary
- Add the CVE table to `image-scan/gate`: on findings the log, the job summary and the PR comment name each CVE with its severity, package, installed version and fixed version (`no fix` when none) before the scanner report, read from a second scan in SARIF (best effort, a failure only warns)
- Add the optional `enforce` input (default `true`) and the `findings` output to `image-scan/gate`. With `enforce: false` (advisory mode) the scan and the report run as usual but findings are `::warning::`, the action exits 0 and `promote-tags` applies, `findings` is `true` for the caller to alert on. A scanner that cannot run still fails

## v1.3.0

### Added

- Add the optional `skip-reason` input and `skipped` output to `image-scan/gate`, an audited emergency bypass: on a `workflow_dispatch` run a non-blank reason skips the scan (`promote-tags` still applies) and is recorded in a warning, the job summary and a GitHub issue (labels `security` and `image-scan-skipped`, needs `issues: write`, a failure to open it only warns) with the image, digest, actor, reason, run URL and time. On any other event the reason is ignored, with a warning, and the scan runs

### Changed

- Change the `scanned` output of `image-scan/gate` to `false` when `skip-reason` skipped the scan

## v1.2.0

### Added

- Add the optional `promote-tags` input and `promoted` output to `image-scan/gate`: once the scan is clean, the tags (like the `tags` output of `docker/metadata-action`) are added to the scanned digest with `docker buildx imagetools create`, so a repository pushing a single multi-arch image can have the gate block the release tags. Nothing is promoted on findings or scanner failures

## v1.1.4

### Changed

- Change `sfreleaser/detect` and `sfreleaser/publish` to log the sfreleaser version they install (resolving `latest` to its tag), the download URL and how long it took, and `prepare` and `publish` to log which sfreleaser (version and path) they reuse when one is already installed

## v1.1.3

### Changed

- Change `sfreleaser/detect` and `sfreleaser/publish` to log the sfreleaser version they install (resolving `latest` to its tag), the download URL and how long it took, and `publish` to log which sfreleaser it reuses when one is already installed
- Change the sfreleaser download to retry 3 times with a 20s connect timeout and a 120s overall limit, instead of waiting on a stalled connection

## v1.1.2

### Security

- Stop mounting the runner's Docker socket in the `image-scan` scanner container: it runs as non-root and could not use it anyway, the image is pulled from the registry, so it must be pushed before the scan

## v1.1.1

### Fixed

- Fix `image-scan/gate` and `image-scan/weekly` always failing with `permission denied` when writing the report: the scanner container runs as a non-root user and could not open the runner's `0600` report file, the report is now captured from the container's stdout on the host

## v1.1.0

### Added

- Add `image-scan/gate`, a CVE gate for a built container image with a job summary, a pull request comment and `scan-paths` to skip pull requests that cannot change the image
- Add `image-scan/weekly`, a weekly scan of the latest release keeping one GitHub issue per critical/high CVE, with a `slack-message` output
