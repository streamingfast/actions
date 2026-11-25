package vex_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/streamingfast/actions/image-scan/internal/scout"
	"github.com/streamingfast/actions/image-scan/internal/testutil"
	"github.com/streamingfast/actions/image-scan/internal/vex"
)

func tableRows(t *testing.T) []scout.Finding {
	return scout.Findings(testutil.ReadFixture(t, "table.sarif"))
}

func TestStatements(t *testing.T) {
	statements := vex.Statements(testutil.Fixture("vex"))
	assert.Len(t, statements, 3, "statements of a directory")
	assert.Len(t, vex.Statements(testutil.Fixture("vex", "openvex.json")), 3, "statements of a file")
	assert.Equal(t, "SF Security <security@streamingfast.io>", statements[0].Author, "a statement inherits the author of its document")
	assert.Equal(t, "inline_mitigations_already_exist", statements[0].Justification)
	assert.Equal(t, "CVE-2025-9999", statements[2].ID, "string form of the vulnerability (OpenVEX before 0.2)")
	assert.Empty(t, vex.Statements(filepath.Join(t.TempDir(), "nope")), "no location, no statement")
}

func writeStatement(t *testing.T, dir, name, document string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(document), 0o644))
}

func TestMostRecentStatementWins(t *testing.T) {
	dir := t.TempDir()
	for _, ts := range []string{"2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z", "2026-02-01T00:00:00Z"} {
		writeStatement(t, dir, ts+".json", fmt.Sprintf(`{"statements": [{"vulnerability": {"name": "CVE-2025-2222"}, "status": "not_affected", "justification": "j-%s", "timestamp": "%s"}]}`, ts, ts))
	}
	rows := tableRows(t)
	suppressed := vex.SuppressedFindings(rows, nil, vex.Statements(dir), "")

	bySuppressed := map[string]vex.Suppressed{}
	for _, s := range suppressed {
		bySuppressed[s.ID] = s
	}
	require.Len(t, bySuppressed["CVE-2025-2222"].Statements, 1)
	assert.Equal(t, "j-2026-03-01T00:00:00Z", bySuppressed["CVE-2025-2222"].Statements[0].Justification, "the most recent statement wins")
	assert.Equal(t, "", bySuppressed["CVE-2025-1111"].Status, "a CVE without statement is suppressed without justification")
	assert.Empty(t, vex.SuppressedFindings(rows, rows, nil, ""), "only CVEs missing from the active list are suppressed")
}

func TestStatementsScopedToTheImage(t *testing.T) {
	statements := vex.Statements(testutil.Fixture("vex-sf-analytics"))
	for _, s := range statements {
		assert.GreaterOrEqual(t, len(s.Products), 3, "products of the statements are read (objects and strings)")
	}
	all := []scout.Finding{
		{ID: "CVE-2026-107493", Severity: "high", Package: "openssl", Installed: "3.0"},
		{ID: "CVE-2026-107496", Severity: "high", Package: "openssl", Installed: "3.0"},
		{ID: "CVE-2026-84786", Severity: "critical", Package: "node", Installed: "22"},
	}

	dash := vex.SuppressedFindings(all, nil, statements, "gcr.io/eoscanada-shared-services/sf-analytics-dashboard@sha256:9ea5d73e"+strings.Repeat("a", 56))
	dbt := vex.SuppressedFindings(all, nil, statements, "gcr.io/eoscanada-shared-services/dbt-runner:latest")
	require.Len(t, dash, 3)
	require.Len(t, dbt, 3)

	for _, s := range dash {
		require.Len(t, s.Statements, 1, "the dashboard image gets one statement per CVE")
		assert.Equal(t, "dashboard.openvex.json", s.Statements[0].File)
		assert.True(t, s.Statements[0].Scoped)
		assert.NotContains(t, strings.ToLower(s.Statements[0].Impact), "dbt", "the dashboard justification, not the dbt-runner one")
		assert.NotContains(t, strings.ToLower(s.Statements[0].Impact), "python")
	}
	for _, s := range dbt {
		assert.Equal(t, "dbt-runner.openvex.json", s.Statements[0].File, "the dbt-runner image gets the dbt-runner statements")
	}
	assert.NotEqual(t, dbt[0].Statements[0].Impact, dash[0].Statements[0].Impact, "and they differ from the dashboard ones")

	unscoped := vex.SuppressedFindings(all, nil, statements, "gcr.io/eoscanada-shared-services/other-image:1")
	for _, s := range unscoped {
		require.Len(t, s.Statements, 1, "no product match falls back to the CVE id")
		assert.False(t, s.Statements[0].Scoped, "marked not scoped")
	}
}

func TestSeveralMatchingStatementsAreAllShown(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a", "b"} {
		writeStatement(t, dir, n+".json", fmt.Sprintf(`{"author": "x", "statements": [{"vulnerability": {"name": "CVE-2025-2222"}, "products": [{"@id": "pkg:oci/o/r?repository_url=ghcr.io"}], "status": "not_affected", "justification": "j-%s"}]}`, n))
	}
	suppressed := vex.SuppressedFindings(tableRows(t), nil, vex.Statements(dir), "ghcr.io/o/r:abc")
	for _, s := range suppressed {
		if s.ID != "CVE-2025-2222" {
			continue
		}
		var files []string
		for _, st := range s.Statements {
			files = append(files, st.File)
		}
		assert.Equal(t, "a.json,b.json", strings.Join(files, ","), "several matching statements are all shown")
	}
}

func TestStaleAndIneffective(t *testing.T) {
	statements := vex.Statements(testutil.Fixture("vex"))
	all := []scout.Finding{{ID: "CVE-2025-2222"}, {ID: "CVE-2026-97054"}}

	ineffective := vex.Ineffective(statements)
	require.Len(t, ineffective, 1)
	assert.Equal(t, "under_investigation", ineffective[0].Status, "a statement Scout ignores")

	stale := vex.Stale(all, statements)
	require.Len(t, stale, 1)
	assert.Equal(t, "CVE-2025-9999", stale[0].ID, "a statement matching nothing")
}

func TestProductForms(t *testing.T) {
	const gcr = "gcr.io/eoscanada-shared-services/img"
	dgst := strings.Repeat("b", 64)
	image := vex.ParseImage(gcr + "@sha256:" + dgst)

	for _, p := range []string{
		"pkg:oci/eoscanada-shared-services/img?repository_url=gcr.io",
		"pkg:oci/eoscanada-shared-services/img@sha256:" + dgst + "?repository_url=gcr.io&tag=v1",
		"pkg:oci/eoscanada-shared-services/img@sha256%3A" + dgst + "?repository_url=gcr.io&tag=v1",
		"pkg:oci/eoscanada-shared-services/img",
		"pkg:oci/img?repository_url=gcr.io%2Feoscanada-shared-services%2Fimg",
		"pkg:docker/gcr.io/eoscanada-shared-services/img",
		"pkg:docker/eoscanada-shared-services/img",
		"eoscanada-shared-services/img",
		gcr,
		gcr + ":v1",
	} {
		assert.True(t, vex.ProductMatches(p, image), "%s matches %s@sha256:b…", p, gcr)
	}

	tests := []struct {
		name, product, image string
		want                 bool
	}{
		{"a tag only image matches", "pkg:oci/eoscanada-shared-services/img?repository_url=gcr.io", gcr + ":v2", true},
		{"another registry does not match", "pkg:oci/eoscanada-shared-services/img?repository_url=ghcr.io", gcr + ":v2", false},
		{"another repository does not match", "pkg:oci/eoscanada-shared-services/img2?repository_url=gcr.io", gcr + ":v2", false},
		{"a prefix of the repository does not match", "pkg:docker/eoscanada-shared-services", gcr + ":v2", false},
		{"another digest does not match", "pkg:oci/eoscanada-shared-services/img@sha256:" + strings.Repeat("c", 64) + "?repository_url=gcr.io", gcr + "@sha256:" + dgst, false},
		{"ghcr.io purl", "pkg:oci/streamingfast/foo?repository_url=ghcr.io", "ghcr.io/streamingfast/foo:v1.2.3", true},
		{"docker hub image by short name", "pkg:docker/streamingfast/foo", "streamingfast/foo:v1", true},
		{"... and by docker.io name", "pkg:docker/docker.io/streamingfast/foo", "streamingfast/foo:v1", true},
		{"... not on ghcr.io", "pkg:docker/docker.io/streamingfast/foo", "ghcr.io/streamingfast/foo:v1", false},
		{"a registry with a port", "localhost:5000/foo", "localhost:5000/foo:1", true},
		{"garbage does not fail", "", gcr + ":1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, vex.ProductMatches(tt.product, vex.ParseImage(tt.image)))
		})
	}
}
