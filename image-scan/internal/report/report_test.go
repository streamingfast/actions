package report_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/streamingfast/actions/image-scan/internal/report"
	"github.com/streamingfast/actions/image-scan/internal/scout"
	"github.com/streamingfast/actions/image-scan/internal/testutil"
	"github.com/streamingfast/actions/image-scan/internal/vex"
)

func rows(t *testing.T) []scout.Finding {
	return scout.Findings(testutil.ReadFixture(t, "table.sarif"))
}

func TestFindingsText(t *testing.T) {
	text := report.FindingsText(rows(t))
	assert.Regexp(t, `(?m)^CVE-2025-1111  +critical +openssl .*no fix$`, text, "text table names the CVEs and says no fix")
	assert.Regexp(t, `(?m)^CVE-2025-2222  +high  +golang.org/x/net  +0.10.0  +0.17.0$`, text)
}

func TestFindingsMarkdown(t *testing.T) {
	md := report.FindingsMarkdown(rows(t), 100)
	assert.Contains(t, md, "| CVE | Severity | Package | Installed | Fixed |\n", "markdown table has a header")
	assert.Contains(t, md, "| CVE-2025-2222 | high | `golang.org/x/net` | 0.10.0 | 0.17.0 |\n", "markdown row")
	assert.Contains(t, md, `musl`, "the pipe row is there")
	assert.Contains(t, md, `1.2.3\|bad`, "markdown escapes pipes")
	assert.Contains(t, report.FindingsMarkdown(rows(t), 2), "… and 3 more", "markdown is capped")
	assert.NotContains(t, md, "… and")
}

func TestStatementCells(t *testing.T) {
	long := vex.Suppressed{
		Finding: scout.Finding{ID: "CVE-1", Severity: "high", Package: "p", Installed: "1"},
		Status:  vex.NotAffected,
		Statements: []vex.StatementOfSuppressed{
			{Justification: "j", Impact: strings.Repeat("x", 400) + "|\nz", Author: "a", Timestamp: "t", File: "f.json", Scoped: true},
		},
	}
	md := report.SuppressedMarkdown([]vex.Suppressed{long}, 100)
	assert.Contains(t, md, strings.Repeat("x", 300)+"…", "an impact is cut at 300 characters")
	assert.NotContains(t, md, strings.Repeat("x", 301))
	assert.Contains(t, md, "| j: ")
	assert.Contains(t, md, " (`f.json`) | a | t |")

	assert.Contains(t, report.SuppressedMarkdown([]vex.Suppressed{long, long, long}, 2), "… and 1 more")
}

func TestSuppressedWithoutStatement(t *testing.T) {
	s := []vex.Suppressed{{Finding: scout.Finding{ID: "CVE-1", Severity: "high", Package: "p", Installed: "1"}}}
	assert.Contains(t, report.SuppressedMarkdown(s, 100), "_suppressed, not by a statement of vex-location_")
	assert.Equal(t, "CVE-1 (high) p 1: suppressed, not by a vex-location statement", report.SuppressedText(s))
}

func TestSuppressedOfTheScannedImage(t *testing.T) {
	statements := vex.Statements(testutil.Fixture("vex-sf-analytics"))
	all := []scout.Finding{
		{ID: "CVE-2026-107493", Severity: "high", Package: "openssl", Installed: "3.0"},
		{ID: "CVE-2026-107496", Severity: "high", Package: "openssl", Installed: "3.0"},
		{ID: "CVE-2026-84786", Severity: "critical", Package: "node", Installed: "22"},
	}
	dash := vex.SuppressedFindings(all, nil, statements, "gcr.io/eoscanada-shared-services/sf-analytics-dashboard@sha256:9ea5d73e"+strings.Repeat("a", 56))

	text := report.SuppressedText(dash)
	line := lineStarting(text, "CVE-2026-107493")
	assert.True(t, strings.HasSuffix(line, "[dashboard.openvex.json]"), "the log line names the VEX file: %s", line)
	assert.NotContains(t, text, "not scoped", "and no not-scoped mention")

	md := report.SuppressedMarkdown(dash, 100)
	assert.Contains(t, md, "dashboard.openvex.json", "the markdown shows the file")
	assert.NotContains(t, md, "dbt-runner.openvex.json", "not the other one")

	unscoped := vex.SuppressedFindings(all, nil, statements, "gcr.io/eoscanada-shared-services/other-image:1")
	n := 0
	for line := range strings.Lines(strings.TrimRight(report.SuppressedText(unscoped), "\n")) {
		if strings.HasSuffix(strings.TrimRight(line, "\n"), "(statement not scoped to this image)") {
			n++
		}
	}
	assert.Equal(t, 3, n, "no product match is marked in the log")
	assert.Contains(t, report.SuppressedMarkdown(unscoped, 100), "statement not scoped to this image", "and in the markdown")
}

func lineStarting(text, prefix string) string {
	for line := range strings.Lines(text) {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimRight(line, "\n")
		}
	}
	return fmt.Sprintf("no line starts with %q", prefix)
}
