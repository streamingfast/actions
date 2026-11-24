# Changelog

## Unreleased

### Added

- Add `image-scan/gate`, a CVE gate for a built container image with a job summary, a pull request comment and `scan-paths` to skip pull requests that cannot change the image
- Add `image-scan/weekly`, a weekly scan of the latest release keeping one GitHub issue per critical/high CVE, with a `slack-message` output

### Fixed

- Fix `image-scan/gate` and `image-scan/weekly` always failing with `permission denied` when writing the report: the scanner container runs as a non-root user and could not open the runner's `0600` report file, the report is now captured from the container's stdout on the host
