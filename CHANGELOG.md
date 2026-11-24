# Changelog

## Unreleased

### Added

- Add `image-scan/gate`, a CVE gate for a built container image with a job summary, a pull request comment and `scan-paths` to skip pull requests that cannot change the image
- Add `image-scan/weekly`, a weekly scan of the latest release keeping one GitHub issue per critical/high CVE, with a `slack-message` output

### Changed

- Change `sfreleaser/detect` and `sfreleaser/publish` to log the sfreleaser version they install (resolving `latest` to its tag), the download URL and how long it took, and `publish` to log which sfreleaser it reuses when one is already installed
- Change the sfreleaser download to retry 3 times with a 20s connect timeout and a 120s overall limit, instead of waiting on a stalled connection

### Fixed

- Fix `image-scan/gate` and `image-scan/weekly` always failing with `permission denied` when writing the report: the scanner container runs as a non-root user and could not open the runner's `0600` report file, the report is now captured from the container's stdout on the host

### Security

- Stop mounting the runner's Docker socket in the `image-scan` scanner container: it runs as non-root and could not use it anyway, the image is pulled from the registry, so it must be pushed before the scan
