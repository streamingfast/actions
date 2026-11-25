# Changelog

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
