package gate_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/streamingfast/actions/image-scan/internal/gate"
	"github.com/streamingfast/actions/image-scan/internal/scanner"
	"github.com/streamingfast/actions/image-scan/internal/testutil"
)

var (
	tableSARIF  = func(t *testing.T) string { return string(testutil.ReadFixture(t, "table.sarif")) }
	stdlibSARIF = func(t *testing.T) string { return string(testutil.ReadFixture(t, "stdlib.sarif")) }
)

func scan(t *testing.T, h *harness) gate.ScanResult {
	t.Helper()
	result, err := h.g.Scan(t.Context(), h.g.Config.Image)
	require.NoError(t, err)
	return result
}

func scanWithVex(modify ...func(*gate.Config)) []option {
	return []option{config(func(c *gate.Config) {
		c.VexLocation = testutil.Fixture("vex")
		for _, m := range modify {
			m(c)
		}
	}), retries(1)}
}

func TestScanCleanImage(t *testing.T) {
	h := newHarness(t, retries(1))
	result := scan(t, h)
	assert.Equal(t, scanner.ExitClean, result.Code, "clean image exits 0")
	assert.False(t, result.Findings)
	assert.Equal(t, "no findings\n", result.Report, "the report is the scanner's, as before")
	assert.Len(t, h.scout.Calls, 1, "one scan only")
}

func TestScanFindings(t *testing.T) {
	h := newHarness(t, retries(1))
	findingsOf(h, tableSARIF(t))
	result := scan(t, h)

	assert.Equal(t, scanner.ExitFindings, result.Code, "findings exit 2")
	assert.True(t, result.Findings)
	assert.True(t, h.logHas("::error::critical,high vulnerabilities found in "+img), "an error annotation")
	assert.NotContains(t, h.log.String(), "::warning::", "no warning annotation")
	assert.Regexp(t, `(?m)^CVE-2025-1111  +critical  +openssl  +3.0.1-1  +no fix$`, h.log.String(), "the log names the CVEs")
	assert.Regexp(t, `(?m)^CVE-2025-2222  +high  +golang.org/x/net  +0.10.0  +0.17.0$`, h.log.String(), "the log shows the fixed version")
	assert.Len(t, h.scout.Calls, 2, "two scans, the report and the CVEs")
	assert.Equal(t, 1, h.scout.Count("--format sarif"), "the CVEs come from a sarif scan")

	assert.True(t, strings.HasPrefix(result.Report, "### Vulnerabilities (5)\n"), "the report has the CVE table first")
	assert.Contains(t, result.Report, "\n# findings in "+img+"\n", "then the scanner report")
	assert.NotContains(t, result.Report, "Advisory mode")
	assert.NotContains(t, result.Report, "Suppressed")
}

func TestScanAdvisory(t *testing.T) {
	h := newHarness(t, retries(1), config(func(c *gate.Config) { c.Enforce = "false" }))
	findingsOf(h, tableSARIF(t))
	result := scan(t, h)

	assert.True(t, result.Findings)
	assert.True(t, h.logHas("::warning::critical,high vulnerabilities found in "+img), "a warning annotation, no error")
	assert.Contains(t, h.log.String(), "::warning::Advisory mode (enforce: false)", "says it does not fail")
	assert.NotContains(t, h.log.String(), "::error::", "never an error")
	assert.Contains(t, h.log.String(), "CVE-2025-1111", "the CVEs are still named in the log")
	assert.Contains(t, result.Report, "### Vulnerabilities (5)\n", "and in the report")
	assert.Contains(t, result.Report, "> Advisory mode", "which says it is advisory")
	assert.Contains(t, result.Report, "\n### Scanner report\n", "above the scanner report")
}

func TestScanEnforceValues(t *testing.T) {
	tests := []struct {
		enforce string
		exit    int
	}{
		{"FALSE", 0}, // case insensitive
		{"", 2},      // an empty enforce enforces
		{"true", 2},
		{"maybe", 1}, // rejected before any scan
	}
	for _, tt := range tests {
		t.Run("enforce '"+tt.enforce+"'", func(t *testing.T) {
			h := newHarness(t, retries(1), config(func(c *gate.Config) { c.Enforce = tt.enforce }))
			findingsOf(h, tableSARIF(t))
			assert.Equal(t, tt.exit, h.g.Run(t.Context()))
			if tt.exit == 1 {
				assert.Empty(t, h.scout.Calls, "before any scan")
			}
		})
	}
}

func TestScanAdvisoryInfrastructureFailureStillFails(t *testing.T) {
	h := newHarness(t, retries(1), config(func(c *gate.Config) { c.Enforce = "false" }))
	h.scout.Failures = 9
	assert.Equal(t, 10, h.g.Run(t.Context()), "an infrastructure failure still fails (10)")
	assert.NotContains(t, h.out(), "findings", "no findings output")
}

func TestScanVexScopedToTheImage(t *testing.T) {
	sfaImage := "gcr.io/eoscanada-shared-services/sf-analytics-dashboard@sha256:9ea5d73e" + strings.Repeat("a", 56)
	h := newHarness(t, retries(1), config(func(c *gate.Config) { c.Image, c.VexLocation = sfaImage, testutil.Fixture("vex-sf-analytics") }))
	fake := h.scout.Image(sfaImage)
	fake.RC, fake.VexRC = testutil.Code(2), testutil.Code(0)
	rules := []map[string]any{}
	for _, id := range []string{"CVE-2026-107493", "CVE-2026-107496", "CVE-2026-84786"} {
		rules = append(rules, map[string]any{"id": id, "properties": map[string]any{"cvssV3_severity": "HIGH"}})
	}
	sarif, err := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"rules": rules}}}}})
	require.NoError(t, err)
	fake.SARIF = string(sarif)

	result := scan(t, h)
	assert.Equal(t, scanner.ExitClean, result.Code, "both documents, all suppressed, passes")
	assert.Regexp(t, `(?m)^CVE-2026-107493 .*\[dashboard.openvex.json\]$`, h.log.String(), "the log names the dashboard document")
	assert.NotContains(t, h.log.String(), "dbt-runner.openvex.json", "never the dbt-runner one")
	assert.Contains(t, result.Report, "dashboard.openvex.json", "the report names the dashboard document")
	assert.NotContains(t, result.Report, "dbt-runner.openvex.json")
	assert.NotContains(t, result.Report, "not scoped")
}

func TestScanVexSuppressesEverything(t *testing.T) {
	h := newHarness(t, scanWithVex()...)
	fake := h.fakeImage()
	fake.RC, fake.VexRC, fake.SARIF = testutil.Code(2), testutil.Code(0), stdlibSARIF(t)

	result := scan(t, h)
	log := h.log.String()
	assert.Equal(t, scanner.ExitClean, result.Code, "a suppressed CVE passes the gate")
	assert.False(t, result.Findings)
	assert.Regexp(t, `--vex-location \S+ --vex-author \.\* --exit-code --format markdown `+img+`$`, h.scout.Lines()[0], "the scan decides with the documents")
	assert.Len(t, h.scout.Calls, 2, "the CVEs without them are listed too")

	assert.Contains(t, result.Report, "### Suppressed by VEX (1)\n", "the report lists the suppressed CVE")
	assert.Contains(t, result.Report, "| CVE-2026-97054 | high | `stdlib` | 1.27.3", "with its id, package and installed version")
	assert.Contains(t, result.Report, "inline_mitigations_already_exist", "its justification")
	assert.Contains(t, result.Report, "issues/57", "its impact statement, with the issue link")
	assert.Contains(t, result.Report, "SF Security <security@streamingfast.io> | 2026-11-24T10:00:00Z |", "its author and date")
	assert.NotContains(t, result.Report, "### Vulnerabilities", "no vulnerability section")

	assert.Contains(t, log, "\nCVE-2026-97054 (high) stdlib 1.27.3: inline_mitigations_already_exist - Risk accepted", "the log names it")
	assert.True(t, h.logHas("::notice::1 vulnerabilities of "+img+" are suppressed by the VEX documents of "+testutil.Fixture("vex")+": CVE-2026-97054"), "as a notice")
	assert.NotContains(t, log, "::error::", "no error")
	assert.Regexp(t, `(?m)^::warning::VEX statement for CVE-2025-2222 in .*openvex.json has status under_investigation: only not_affected suppresses`, log, "a statement Scout ignores warns")
	assert.Regexp(t, `(?m)^::notice::VEX statement for CVE-2025-9999 in .*matches no critical/high finding of `+img+`, remove it`, log, "a statement matching nothing is noticed")

	assert.Equal(t, 1, h.scout.Count("--vex-location"), "the documents were given to the first scan only")
	assert.Equal(t, 1, h.scout.Count("--format sarif"), "the unfiltered scan has no vex flag")
	assert.NotContains(t, h.scout.Lines()[1], "--vex-location")

	// the same report goes to the job summary and the pull request
	h.g.Config.EventName, h.g.Config.PRNumber = "pull_request", "7"
	require.NoError(t, h.g.Publish(t.Context(), img, findings(result.Report, result.Report)))
	assert.True(t, h.gh.Contains("Suppressed by VEX (1)"), "the suppressed CVEs are in the pull request comment")
	assert.Contains(t, h.readSummary(), "CVE-2026-97054", "and in the job summary")
}

func TestScanVexLeavesFindings(t *testing.T) {
	var doc map[string]any
	require.NoError(t, json.Unmarshal(testutil.ReadFixture(t, "table.sarif"), &doc))
	runs := doc["runs"].([]any)
	driver := runs[0].(map[string]any)["tool"].(map[string]any)["driver"].(map[string]any)
	driver["rules"] = append(driver["rules"].([]any), map[string]any{"id": "CVE-2026-97054", "properties": map[string]any{
		"cvssV3_severity": "HIGH", "purls": []string{"pkg:golang/stdlib@1.27.3"}, "fixed_version": "1.27.4"}})
	withStdlib, err := json.Marshal(doc)
	require.NoError(t, err)

	h := newHarness(t, scanWithVex()...)
	fake := h.fakeImage()
	fake.RC, fake.VexRC, fake.SARIF, fake.VexSARIF = testutil.Code(2), testutil.Code(2), string(withStdlib), tableSARIF(t)

	result := scan(t, h)
	assert.Equal(t, scanner.ExitFindings, result.Code, "remaining findings still fail (2)")
	assert.True(t, result.Findings)
	assert.Len(t, h.scout.Calls, 3, "three scans")
	assert.Contains(t, result.Report, "### Vulnerabilities (5)\n", "the table lists what is left")
	table, _, _ := strings.Cut(result.Report, "### Suppressed")
	assert.NotContains(t, table, "CVE-2026-97054", "the suppressed one is not in it")
	assert.Contains(t, result.Report, "### Suppressed by VEX (1)\n", "but listed as suppressed")
}

func TestScanVexAdvisoryWithNothingSuppressed(t *testing.T) {
	h := newHarness(t, scanWithVex(func(c *gate.Config) { c.Enforce = "false" })...)
	fake := h.fakeImage()
	fake.RC, fake.VexRC, fake.SARIF = testutil.Code(2), testutil.Code(2), tableSARIF(t)

	assert.Equal(t, 0, h.g.Run(t.Context()), "remaining findings exit 0")
	assert.Equal(t, "true", h.out()["findings"])
	result := scan(t, h)
	assert.NotContains(t, result.Report, "Suppressed", "nothing suppressed, no section")
}

func TestScanBestEffortPasses(t *testing.T) {
	t.Run("a failing CVE listing does not change the outcome", func(t *testing.T) {
		h := newHarness(t, retries(1))
		h.fakeImage().RC = testutil.Code(2)
		h.fakeImage().BadSARIF = 10
		result := scan(t, h)
		assert.Equal(t, scanner.ExitFindings, result.Code)
		assert.Contains(t, h.log.String(), "::warning::Cannot list the CVEs of "+img, "it warns")
		assert.Contains(t, result.Report, "# findings in "+img+"\n", "the scanner report is kept")
		assert.True(t, result.Findings)
	})

	t.Run("failing to list the suppressed CVEs does not fail a clean scan", func(t *testing.T) {
		h := newHarness(t, scanWithVex()...)
		fake := h.fakeImage()
		fake.RC, fake.VexRC, fake.BadSARIF = testutil.Code(2), testutil.Code(0), 10
		result := scan(t, h)
		assert.Equal(t, scanner.ExitClean, result.Code)
		assert.Contains(t, h.log.String(), "::warning::Cannot list the CVEs of "+img, "it warns")
		assert.Equal(t, "no findings\n", result.Report, "the report stays the scanner's")
	})

	t.Run("findings without a readable CVE still fail", func(t *testing.T) {
		h := newHarness(t, retries(1))
		findingsOf(h, `{"runs": []}`)
		assert.Equal(t, scanner.ExitFindings, scan(t, h).Code)
		assert.Contains(t, h.log.String(), "::warning::The scanner reported vulnerabilities in "+img+" but none could be read")
	})
}

func TestScanMissingVexLocationFails(t *testing.T) {
	h := newHarness(t, retries(1), config(func(c *gate.Config) { c.VexLocation = t.TempDir() + "/nope" }))
	assert.Equal(t, 1, h.g.Run(t.Context()), "a missing location fails the scan")
	assert.Empty(t, h.scout.Calls)
}

func commentOf(t *testing.T, h *harness) string {
	t.Helper()
	return scan(t, h).Comment
}

func TestScanCommentBody(t *testing.T) {
	t.Run("clean is one line", func(t *testing.T) {
		h := newHarness(t, retries(1))
		assert.Equal(t, "✅ Image scan: no critical/high vulnerabilities in "+img+"\n", commentOf(t, h))
	})

	t.Run("clean names the short digest when the report has it", func(t *testing.T) {
		h := newHarness(t, retries(1))
		h.fakeImage().CleanMarkdown = "digest\tsha256:d562353f9ef09d4eb64d75e0e5595268d2d64b21b180d6d6281c2bbcbd170e99\n"
		assert.Equal(t, "✅ Image scan: no critical/high vulnerabilities in "+img+" (d562353f9ef0)\n", commentOf(t, h))
	})

	t.Run("clean follows the severities", func(t *testing.T) {
		h := newHarness(t, retries(1), config(func(c *gate.Config) { c.Severities = "critical, high,medium" }))
		assert.Contains(t, commentOf(t, h), "no critical/high/medium vulnerabilities")
	})

	t.Run("clean with VEX counts the accepted CVEs", func(t *testing.T) {
		h := newHarness(t, scanWithVex()...)
		fake := h.fakeImage()
		fake.RC, fake.VexRC, fake.SARIF = testutil.Code(2), testutil.Code(0), tableSARIF(t)
		comment := commentOf(t, h)
		assert.True(t, strings.HasPrefix(comment, "✅ Image scan: no critical/high vulnerabilities in "+img+", 5 accepted via VEX\n"))
		assert.Contains(t, comment, "\n<details><summary>Accepted via VEX (5)</summary>\n", "and lists them collapsed")
		assert.Contains(t, comment, "\n</details>\n", "closed")
	})

	t.Run("findings: the CVE table first, the scanner report collapsed", func(t *testing.T) {
		h := newHarness(t, retries(1))
		findingsOf(h, tableSARIF(t))
		comment := commentOf(t, h)
		assert.True(t, strings.HasPrefix(comment, "### Vulnerabilities (5)\n"), "the CVE table comes first")
		assert.Contains(t, comment, "\n<details><summary>Scanner report</summary>\n", "the scanner report is collapsed")
		assert.Less(t, strings.Index(comment, "| CVE"), strings.Index(comment, "<details>"), "after the table")
		assert.Contains(t, comment, "\n# findings in "+img+"\n", "holding the report")
		assert.Contains(t, comment, "\n</details>\n", "closed")
		assert.NotContains(t, scan(t, h).Report, "<details>", "the job summary report is not collapsed")
	})

	t.Run("advisory keeps the banner first", func(t *testing.T) {
		h := newHarness(t, retries(1), config(func(c *gate.Config) { c.Enforce = "false" }))
		findingsOf(h, tableSARIF(t))
		comment := commentOf(t, h)
		assert.True(t, strings.HasPrefix(comment, "> [!WARNING]\n"))
		assert.Contains(t, comment, "<details><summary>Scanner report</summary>", "and the collapsed report")
	})
}
