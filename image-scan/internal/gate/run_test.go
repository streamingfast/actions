package gate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/streamingfast/actions/image-scan/internal/gate"
	"github.com/streamingfast/actions/image-scan/internal/testutil"
)

const promoteList = "ghcr.io/o/r:v1.2.3\nghcr.io/o/r:latest"

func TestRunCleanScan(t *testing.T) {
	h := newHarness(t, retries(1))
	assert.Equal(t, 0, h.g.Run(t.Context()))
	assert.Equal(t, map[string]string{"scanned": "true", "skipped": "false", "findings": "false", "promoted": ""}, h.out())
	assert.Empty(t, h.reg.DigestCalls, "the digest is only resolved to promote or to audit a skip")
}

func TestRunFindingsAreWrittenBeforeFailing(t *testing.T) {
	h := newHarness(t, retries(1), config(func(c *gate.Config) { c.PromoteTags = promoteList }))
	findingsOf(h, tableSARIF(t))
	assert.Equal(t, 2, h.g.Run(t.Context()), "findings exit 2")
	assert.Equal(t, "true", h.out()["findings"])
	assert.Empty(t, h.reg.Copies, "nothing is promoted on findings")
	assert.Contains(t, h.readSummary(), "### Vulnerabilities (5)", "the report is published before failing")
}

func TestRunPromotesACleanImage(t *testing.T) {
	h := newHarness(t, retries(1), config(func(c *gate.Config) { c.PromoteTags = promoteList }))
	assert.Equal(t, 0, h.g.Run(t.Context()))
	assert.Equal(t, "ghcr.io/o/r:v1.2.3\nghcr.io/o/r:latest", h.out()["promoted"])
	assert.Len(t, h.reg.Copies, 2)
	assert.Len(t, h.reg.DigestCalls, 2, "resolved before the scan, re-checked before the promotion")
}

func TestRunAdvisoryPromotes(t *testing.T) {
	h := newHarness(t, retries(1), config(func(c *gate.Config) { c.PromoteTags, c.Enforce = promoteList, "false" }))
	findingsOf(h, tableSARIF(t))
	assert.Equal(t, 0, h.g.Run(t.Context()))
	assert.Equal(t, "true", h.out()["findings"], "the findings output tells the caller")
	assert.Len(t, h.reg.Copies, 2, "promote-tags always applies in advisory mode")
}

func TestRunInfrastructureFailure(t *testing.T) {
	h := newHarness(t, retries(2), config(func(c *gate.Config) { c.PromoteTags = promoteList }))
	h.scout.Failures = 9
	assert.Equal(t, 10, h.g.Run(t.Context()))
	assert.Empty(t, h.reg.Copies)
	assert.Empty(t, h.readSummary(), "no report when the scanner could not run")
}

func TestRunTheDigestMovedDuringTheScan(t *testing.T) {
	h := newHarness(t, retries(1), config(func(c *gate.Config) { c.PromoteTags = promoteList }))
	h.reg.Digests = []string{testutil.Digest("a"), testutil.Digest("b")}
	assert.Equal(t, 1, h.g.Run(t.Context()))
	assert.Empty(t, h.reg.Copies, "nothing promoted")
}

func TestRunPromoteTagsNeedTheDigestBeforeTheScan(t *testing.T) {
	h := newHarness(t, retries(1), config(func(c *gate.Config) { c.PromoteTags = promoteList }))
	h.reg.DigestFailures = 9
	assert.Equal(t, 1, h.g.Run(t.Context()))
	assert.Empty(t, h.scout.Calls, "the scan does not start")
}

func TestRunPromotionAppliesWhenScanPathsSkipTheScan(t *testing.T) {
	dir := repository(t)
	h := newHarness(t, retries(1), config(func(c *gate.Config) {
		c.EventName, c.ScanPaths, c.PromoteTags = "pull_request", "^Dockerfile", promoteList
	}))
	h.g.ChangedFiles = gate.GitChangedFiles(dir)
	assert.Equal(t, 0, h.g.Run(t.Context()))
	assert.Equal(t, "false", h.out()["scanned"])
	assert.Empty(t, h.scout.Calls)
	assert.Len(t, h.reg.Copies, 2, "promote-tags applies when scan-paths skips the scan too")
}

func TestRunSkipReason(t *testing.T) {
	skip := func(c *gate.Config) {
		c.EventName, c.SkipReason, c.Actor, c.PromoteTags = "workflow_dispatch", "outage", "alice", promoteList
	}

	h := newHarness(t, retries(1), config(skip))
	assert.Equal(t, 0, h.g.Run(t.Context()))
	assert.Equal(t, map[string]string{"scanned": "false", "skipped": "true", "promoted": promoteList}, h.out())
	assert.Empty(t, h.scout.Calls, "the scan is skipped")
	assert.Contains(t, h.log.String(), "::warning::Image scan SKIPPED")
	assert.Len(t, h.gh.Logged("issue create"), 1, "and audited")
	assert.Len(t, h.reg.Copies, 2, "promote-tags still applies")

	t.Run("without promote-tags the digest must not block the emergency release", func(t *testing.T) {
		h := newHarness(t, retries(1), config(skip), config(func(c *gate.Config) { c.PromoteTags = "" }))
		h.reg.DigestFailures = 9
		assert.Equal(t, 0, h.g.Run(t.Context()))
		assert.Contains(t, h.gh.Logged("issue create")[0], "@unresolved")
	})
}

func TestRunWithoutAnImageBuildsTheName(t *testing.T) {
	h := newHarness(t, retries(1), config(func(c *gate.Config) {
		c.Image, c.ImageRepository, c.Arch, c.SHA, c.Ref = "", "ghcr.io/o/r", "ARM64", "0123456789abcdef", "refs/tags/v1.2.3"
	}))
	assert.Equal(t, 0, h.g.Run(t.Context()))
	assert.Contains(t, h.scout.Lines()[0], "ghcr.io/o/r:v1.2.3-arm64")
}
