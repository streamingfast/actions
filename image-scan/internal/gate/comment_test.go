package gate_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/streamingfast/actions/image-scan/internal/gate"
	"github.com/streamingfast/actions/image-scan/internal/github"
)

func commentHarness(t *testing.T, event string) *harness {
	return newHarness(t, config(func(c *gate.Config) { c.EventName, c.PRNumber = event, "7" }))
}

func findings(report, comment string) gate.ScanResult {
	return gate.ScanResult{Code: 2, Enforce: true, Findings: true, Report: report, Comment: comment}
}

func TestPublish(t *testing.T) {
	const image = "ghcr.io/o/r:abc-amd64"

	t.Run("created when missing", func(t *testing.T) {
		h := commentHarness(t, "pull_request")
		require.NoError(t, h.g.Publish(t.Context(), image, findings("report body\n", "report body\n")))
		assert.Contains(t, h.readSummary(), "## Image scan ("+image+")", "summary written")
		assert.Len(t, h.gh.Logged("comment create"), 1, "created when missing")
		assert.Contains(t, h.gh.Logged("comment create")[0], "o/r#7 <!-- image-scan:"+image+" -->\n## Image scan ("+image+")\n\nreport body", "marker carries the image")
	})

	t.Run("updates its own comment only", func(t *testing.T) {
		h := commentHarness(t, "pull_request")
		h.gh.Comments = []github.Comment{
			{ID: 55, Body: "<!-- image-scan:ghcr.io/o/r:abc-amd64 -->\nold"},
			{ID: 56, Body: "<!-- image-scan:ghcr.io/o/r:abc-arm64 -->\nold"},
		}
		require.NoError(t, h.g.Publish(t.Context(), image, findings("report body\n", "report body\n")))
		assert.Len(t, h.gh.Logged("comment update"), 1)
		assert.True(t, strings.HasPrefix(h.gh.Logged("comment update")[0], "o/r/55 "), "updates its own comment only")
		assert.Empty(t, h.gh.Logged("comment create"), "no new comment when found")
	})

	t.Run("a long report is truncated below the 65536 limit", func(t *testing.T) {
		h := commentHarness(t, "pull_request")
		big := strings.Repeat("a", 70000)
		require.NoError(t, h.g.Publish(t.Context(), "img", findings(big, big)))
		assert.Less(t, len(h.gh.Logged("comment create")[0]), 65000)
	})

	t.Run("a cut inside a multibyte character still posts", func(t *testing.T) {
		h := commentHarness(t, "pull_request")
		body := "a" + strings.Repeat("é", 40000)
		require.NoError(t, h.g.Publish(t.Context(), "img", findings(body, body)))
		require.Len(t, h.gh.Logged("comment create"), 1, "posted")
		assert.True(t, utf8.ValidString(h.gh.Logged("comment create")[0]))
	})

	t.Run("nothing without a report", func(t *testing.T) {
		h := commentHarness(t, "pull_request")
		require.NoError(t, h.g.Publish(t.Context(), "img", findings("", "")))
		assert.Empty(t, h.gh.Log)
		assert.Empty(t, h.readSummary())
	})

	t.Run("no pull request comment on push", func(t *testing.T) {
		h := commentHarness(t, "push")
		require.NoError(t, h.g.Publish(t.Context(), "img", findings("report body\n", "report body\n")))
		assert.Empty(t, h.gh.Log)
		assert.Contains(t, h.readSummary(), "report body", "the job summary still has the report")
	})

	t.Run("a truncated report closes its collapsed block", func(t *testing.T) {
		h := commentHarness(t, "pull_request")
		cut := "<details><summary>Scanner report</summary>\n\n" + strings.Repeat("a", 70000) + "\n\n</details>\n"
		require.NoError(t, h.g.Publish(t.Context(), "img", findings("full report", cut)))
		assert.True(t, strings.HasSuffix(h.gh.Logged("comment create")[0], "</details>"))
	})
}

func TestPublishCleanScanIsQuiet(t *testing.T) {
	clean := gate.ScanResult{Code: 0, Enforce: true, Report: "full report\n", Comment: "✅ Image scan: no critical/high vulnerabilities in img\n"}

	h := commentHarness(t, "pull_request")
	require.NoError(t, h.g.Publish(t.Context(), "img", clean))
	assert.Empty(t, h.gh.Logged("comment create"), "no comment without an existing one")
	assert.Empty(t, h.gh.Logged("comment update"))
	assert.Contains(t, h.readSummary(), "full report", "the job summary keeps the full report")

	h = commentHarness(t, "pull_request")
	h.gh.Comments = []github.Comment{{ID: 55, Body: "<!-- image-scan:img -->\nold"}, {ID: 56, Body: "<!-- image-scan:other -->\nold"}}
	require.NoError(t, h.g.Publish(t.Context(), "img", clean))
	require.Len(t, h.gh.Logged("comment update"), 1, "updates the comment of an earlier failing run")
	update := h.gh.Logged("comment update")[0]
	assert.True(t, strings.HasPrefix(update, "o/r/55 "))
	assert.Contains(t, update, "no critical/high vulnerabilities in img", "with the one line")
	assert.NotContains(t, update, "full report", "not the full report")
	assert.NotContains(t, h.gh.Log, "56", "the other image is left alone")
}

func TestPublishFindingsPostsTheCommentFile(t *testing.T) {
	h := commentHarness(t, "pull_request")
	r := findings("full report", "no critical/high")
	require.NoError(t, h.g.Publish(t.Context(), "img", r))
	require.Len(t, h.gh.Logged("comment create"), 1, "posted when missing")
	assert.Contains(t, h.gh.Logged("comment create")[0], "no critical/high", "from the comment, not the report")
	assert.NotContains(t, h.gh.Logged("comment create")[0], "full report")
}

func TestPublishNeedsThePullRequestNumber(t *testing.T) {
	h := newHarness(t, config(func(c *gate.Config) { c.EventName = "pull_request" }))
	assert.Error(t, h.g.Publish(t.Context(), "img", findings("r", "r")))
}
