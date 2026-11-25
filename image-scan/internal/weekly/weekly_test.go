package weekly_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/streamingfast/actions/image-scan/internal/gha"
	"github.com/streamingfast/actions/image-scan/internal/github"
	"github.com/streamingfast/actions/image-scan/internal/retry"
	"github.com/streamingfast/actions/image-scan/internal/scanner"
	"github.com/streamingfast/actions/image-scan/internal/testutil"
	"github.com/streamingfast/actions/image-scan/internal/weekly"
)

const repository = "ghcr.io/o/r"

type harness struct {
	t       *testing.T
	w       *weekly.Weekly
	scout   *testutil.FakeScout
	gh      *testutil.FakeGitHub
	log     *bytes.Buffer
	outputs string
	summary string
}

func newHarness(t *testing.T, architectures string, retries int) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{t: t, scout: testutil.NewFakeScout(), gh: testutil.NewFakeGitHub(), log: &bytes.Buffer{},
		outputs: filepath.Join(dir, "output"), summary: filepath.Join(dir, "summary")}
	log := gha.NewLogger(h.log)
	sc, err := scanner.New(scanner.Config{
		DockerHubUser: "u", DockerHubPassword: "p", Severities: "critical,high",
		Retry: retry.Policy{Attempts: retries, Sleep: func(time.Duration) {}},
	}, log, h.scout.Exec, &bytes.Buffer{})
	require.NoError(t, err)
	t.Cleanup(sc.Close)

	h.w = &weekly.Weekly{
		Config:  weekly.Config{ImageRepository: repository, Architectures: architectures, Repo: "o/r"},
		Log:     log,
		Files:   gha.Files{Output: h.outputs, Summary: h.summary},
		Scanner: sc,
		GitHub:  h.gh,
		Now:     func() time.Time { return time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC) },
	}
	return h
}

func (h *harness) image(arch string) *testutil.FakeImage {
	return h.scout.Image(repository + ":v1.2.3-" + arch)
}

func (h *harness) summaryText() string {
	data, err := os.ReadFile(h.summary)
	if os.IsNotExist(err) {
		return ""
	}
	require.NoError(h.t, err)
	return string(data)
}

func fixture(t *testing.T, name string) string { return string(testutil.ReadFixture(t, name)) }

func byID(findings []weekly.Finding) map[string]weekly.Finding {
	m := map[string]weekly.Finding{}
	for _, f := range findings {
		m[f.ID] = f
	}
	return m
}

func TestScan(t *testing.T) {
	h := newHarness(t, "amd64 arm64", 3)
	h.image("amd64").RC, h.image("amd64").SARIF = testutil.Code(2), fixture(t, "critical-and-high.sarif")
	h.image("arm64").RC, h.image("arm64").SARIF = testutil.Code(2), fixture(t, "high-only.sarif")

	findings, code := h.w.Scan(t.Context(), "v1.2.3")
	require.Equal(t, 0, code, "exits 0 with findings")
	assert.Len(t, findings, 6, "one entry per CVE")

	severity := map[string]string{}
	for _, f := range findings {
		severity[f.ID] = f.Severity
	}
	assert.Equal(t, "critical", severity["CVE-2025-0001"], "cvssV3_severity critical")
	assert.Equal(t, "high", severity["CVE-2025-0002"], "cvssV3_severity high")
	assert.Equal(t, "critical", severity["CVE-2025-0003"], "security-severity >= 9 is critical")
	assert.Equal(t, "high", severity["CVE-2025-0004"], "unknown severity falls back to high")
	assert.Equal(t, "high", severity["CVE-2025-0005"], "ruleId of results without rule")

	m := byID(findings)
	assert.Equal(t, []string{repository + ":v1.2.3-amd64", repository + ":v1.2.3-arm64"}, m["CVE-2025-0002"].Images, "CVE seen on both arches lists both images")
	assert.Equal(t, []string{repository + ":v1.2.3-arm64"}, m["CVE-2025-0006"].Images, "images use <tag>-<arch>")
	assert.Contains(t, h.summaryText(), "- CVE-2025-0001 (critical)\n", "summary written")
}

func TestScanTakesTheMostSevereAcrossArchitectures(t *testing.T) {
	h := newHarness(t, "amd64 arm64", 3)
	h.image("amd64").RC, h.image("amd64").SARIF = testutil.Code(2), `{"runs":[{"tool":{"driver":{"rules":[{"id":"CVE-1","properties":{"cvssV3_severity":"HIGH"}}]}}}]}`
	h.image("arm64").RC, h.image("arm64").SARIF = testutil.Code(2), `{"runs":[{"tool":{"driver":{"rules":[{"id":"CVE-1","properties":{"cvssV3_severity":"CRITICAL"}}]}}}]}`
	findings, code := h.w.Scan(t.Context(), "v1.2.3")
	require.Equal(t, 0, code)
	require.Len(t, findings, 1)
	assert.Equal(t, "critical", findings[0].Severity)
}

func TestScanInfrastructureFailure(t *testing.T) {
	h := newHarness(t, "amd64 arm64", 1)
	h.image("amd64").RC, h.image("amd64").SARIF = testutil.Code(2), fixture(t, "high-only.sarif")
	h.scout.Failures = 9
	findings, code := h.w.Scan(t.Context(), "v1.2.3")
	assert.Equal(t, 10, code, "infra failure exits 10")
	assert.Nil(t, findings, "no findings for a partial scan")
	assert.Empty(t, h.summaryText())
}

func TestScanUnreadableFindings(t *testing.T) {
	for _, sarif := range []string{`{"runs": []}`, `{"runs": [{"tool": {"driver": {}}}]}`, ``} {
		t.Run("report "+sarif, func(t *testing.T) {
			h := newHarness(t, "amd64", 3)
			h.image("amd64").RC, h.image("amd64").SARIF = testutil.Code(2), sarif
			findings, code := h.w.Scan(t.Context(), "v1.2.3")
			assert.Equal(t, 11, code, "findings without readable CVE fail")
			assert.Nil(t, findings, "no findings when unreadable")
		})
	}
}

func TestScanCleanImages(t *testing.T) {
	h := newHarness(t, "amd64", 3)
	findings, code := h.w.Scan(t.Context(), "v1.2.3")
	assert.Equal(t, 0, code)
	assert.Empty(t, findings, "clean images give an empty list")
	assert.Contains(t, h.summaryText(), "No critical/high vulnerability.")
}

func TestScanWithoutDocumentsThereIsNoExtraScan(t *testing.T) {
	h := newHarness(t, "amd64", 3)
	h.image("amd64").RC, h.image("amd64").SARIF = testutil.Code(2), fixture(t, "high-only.sarif")
	_, code := h.w.Scan(t.Context(), "v1.2.3")
	require.Equal(t, 0, code)
	assert.Len(t, h.scout.Calls, 1, "without documents there is no extra scan")
	assert.NotContains(t, h.summaryText(), "Suppressed", "and no suppressed section")
}

func vexDirectory(t *testing.T) string {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "doc.json"), []byte(`{"author": "SF <sec@streamingfast.io>", "statements": [{"vulnerability": {"name": "CVE-2025-0001"}, "status": "not_affected", "justification": "component_not_present", "impact_statement": "risk-accepted #12"}]}`), 0o644))
	return dir
}

func TestScanVexSuppressedCVEsOpenNoIssue(t *testing.T) {
	h := newHarness(t, "amd64", 3)
	dir := vexDirectory(t)
	h.w.Config.VexLocation = dir
	fake := h.image("amd64")
	fake.RC, fake.VexRC, fake.SARIF = testutil.Code(2), testutil.Code(0), fixture(t, "critical-and-high.sarif")

	findings, code := h.w.Scan(t.Context(), "v1.2.3")
	assert.Equal(t, 0, code, "everything suppressed exits 0")
	assert.Empty(t, findings, "no finding, so no issue")
	assert.Contains(t, h.scout.Lines()[0], "--vex-location "+dir+" ", "the documents are given to the scan")
	assert.Contains(t, h.summaryText(), "\n- CVE-2025-0001 (critical) unknown unknown: component_not_present - risk-accepted #12 [doc.json] (statement not scoped to this image) ["+repository+":v1.2.3-amd64]\n", "the summary lists what was suppressed")
	assert.Contains(t, h.summaryText(), "no issue opened", "and says no issue is opened")
}

func TestScanVexRemainingFindingsAreReported(t *testing.T) {
	h := newHarness(t, "amd64", 3)
	h.w.Config.VexLocation = vexDirectory(t)
	fake := h.image("amd64")
	fake.RC, fake.SARIF = testutil.Code(2), fixture(t, "critical-and-high.sarif")
	fake.VexRC, fake.VexSARIF = testutil.Code(2), fixture(t, "high-only.sarif")

	findings, code := h.w.Scan(t.Context(), "v1.2.3")
	require.Equal(t, 0, code)
	assert.NotEmpty(t, findings, "remaining findings are reported")
	assert.NotContains(t, byID(findings), "CVE-2025-0001", "without the suppressed one")
	assert.Contains(t, h.summaryText(), "CVE-2025-0001 (critical)", "which is in the summary")
}

func TestScanVexListingFailureOnlyWarns(t *testing.T) {
	h := newHarness(t, "amd64", 1)
	h.w.Config.VexLocation = vexDirectory(t)
	fake := h.image("amd64")
	fake.RC, fake.VexRC, fake.BadSARIF = testutil.Code(2), testutil.Code(0), 10
	_, code := h.w.Scan(t.Context(), "v1.2.3")
	assert.Equal(t, 0, code)
	assert.Contains(t, h.log.String(), "::warning::Cannot list the CVEs suppressed by the VEX documents on "+repository+":v1.2.3-amd64 (scanner exit ")
}

func TestRun(t *testing.T) {
	h := newHarness(t, "amd64", 1)
	h.image("amd64").RC, h.image("amd64").SARIF = testutil.Code(2), fixture(t, "high-only.sarif")
	h.gh.Issues = []github.Issue{}

	assert.Equal(t, 0, h.w.Run(t.Context()))
	out := testutil.Outputs(t, h.outputs)
	assert.Contains(t, out["slack-message"], "found 2 new critical/high CVE(s) in `v1.2.3`")
	assert.Contains(t, h.log.String(), "Latest release: v1.2.3")

	t.Run("an infrastructure failure touches no issue", func(t *testing.T) {
		h := newHarness(t, "amd64", 1)
		h.scout.Failures = 9
		h.gh.Issues = []github.Issue{{Number: 1, State: "OPEN", Body: "<!-- image-scan-cve:CVE-2024-1 -->"}}
		assert.Equal(t, 10, h.w.Run(t.Context()))
		assert.Empty(t, h.gh.Logged("issue close"), "a partial scan must never close issues")
		assert.Empty(t, h.gh.Logged("issue list"))
	})

	t.Run("the message is written even when the sync fails halfway", func(t *testing.T) {
		h := newHarness(t, "amd64", 1)
		h.image("amd64").RC = testutil.Code(2)
		h.image("amd64").SARIF = `{"runs":[{"tool":{"driver":{"rules":[{"id":"CVE-2025-0001","properties":{"cvssV3_severity":"CRITICAL"}}]}}}]}`
		h.gh.Issues = []github.Issue{{Number: 20, State: "OPEN", Body: "<!-- image-scan-cve:CVE-2024-1 -->"}}
		h.gh.Fail["issue close"] = true
		assert.Equal(t, 1, h.w.Run(t.Context()))
		assert.Contains(t, testutil.Outputs(t, h.outputs)["slack-message"], "CVE-2025-0001")
	})

	t.Run("no release fails", func(t *testing.T) {
		h := newHarness(t, "amd64", 1)
		h.gh.Fail["release latest"] = true
		assert.Equal(t, 1, h.w.Run(t.Context()))
	})
}
