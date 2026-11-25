package scout_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/streamingfast/actions/image-scan/internal/scout"
	"github.com/streamingfast/actions/image-scan/internal/testutil"
)

func TestFindings(t *testing.T) {
	rows := scout.Findings(testutil.ReadFixture(t, "table.sarif"))
	byID := map[string]scout.Finding{}
	for _, r := range rows {
		byID[r.ID] = r
	}

	assert.Len(t, rows, 5, "one row per CVE (rules and results)")

	severities := []struct{ id, severity, why string }{
		{"CVE-2025-2222", "high", "cvssV3_severity"},
		{"CVE-2025-3333", "critical", "security-severity score without a level"},
		{"CVE-2025-5555", "unknown", "unknown severity"},
	}
	for _, tt := range severities {
		assert.Equal(t, tt.severity, byID[tt.id].Severity, tt.why)
	}

	assert.Equal(t, "openssl", byID["CVE-2025-1111"].Package, "package from the purl, without type and qualifiers")
	assert.Equal(t, "golang.org/x/net", byID["CVE-2025-2222"].Package, "golang package keeps its module path")
	assert.Equal(t, "3.0.1-1", byID["CVE-2025-1111"].Installed, "installed from affected_version")
	assert.Equal(t, "0.10.0", byID["CVE-2025-2222"].Installed, "installed from the purl version otherwise")
	assert.Equal(t, "0.17.0", byID["CVE-2025-2222"].Fixed, "fixed version")
	assert.Equal(t, "", byID["CVE-2025-1111"].Fixed, "'not fixed' is no fix")

	lodash := byID["CVE-2025-3333"]
	assert.Equal(t, "lodash:4.17.0:4.17.21", lodash.Package+":"+lodash.Installed+":"+lodash.Fixed, "package, installed and fixed from the help text")

	var ids []string
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	assert.Equal(t, "CVE-2025-1111,CVE-2025-3333,CVE-2025-2222,CVE-2025-4444,CVE-2025-5555", strings.Join(ids, ","), "rows are sorted by severity then id")
}

func TestFindingsOfAnUnreadableReport(t *testing.T) {
	assert.Empty(t, scout.Findings(nil), "an empty report gives no row")
	assert.Empty(t, scout.Findings([]byte("{ not json")), "also when it is not JSON")
	assert.Empty(t, scout.Findings([]byte("[]")), "or not a SARIF document")
}

func TestTrackedFindings(t *testing.T) {
	rows := scout.TrackedFindings(testutil.ReadFixture(t, "critical-and-high.sarif"))
	severity := map[string]string{}
	for _, r := range rows {
		severity[r.ID] = r.Severity
	}

	assert.Equal(t, map[string]string{
		"CVE-2025-0001": "critical", // cvssV3_severity critical
		"CVE-2025-0002": "high",     // cvssV3_severity high
		"CVE-2025-0003": "critical", // security-severity >= 9 is critical
		"CVE-2025-0004": "high",     // unknown severity falls back to high
		"CVE-2025-0005": "high",     // ruleId of results without rule
	}, severity)

	for _, bad := range []string{`{"runs": []}`, `{"runs": [{"tool": {"driver": {}}}]}`, ``} {
		require.Empty(t, scout.TrackedFindings([]byte(bad)), "nothing to read from %q", bad)
	}
}
