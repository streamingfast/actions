package weekly_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/streamingfast/actions/image-scan/internal/github"
	"github.com/streamingfast/actions/image-scan/internal/weekly"
)

func issue(number int, state, body string, labels ...string) github.Issue {
	return github.Issue{Number: number, State: state, Body: body, Labels: append([]string{"security"}, labels...)}
}

func cveBody(id string, rest ...string) string {
	return "<!-- image-scan-cve:" + id + " -->\n" + strings.Join(rest, "\n")
}

func finding(id, severity string, images ...string) weekly.Finding {
	return weekly.Finding{ID: id, Severity: severity, Images: images}
}

func sync(t *testing.T, h *harness, findings ...weekly.Finding) string {
	t.Helper()
	message, err := h.w.SyncIssues(t.Context(), "v1.2.3", findings)
	require.NoError(t, err)
	return message
}

func TestSyncIssues(t *testing.T) {
	h := newHarness(t, "amd64", 1)
	h.gh.Issues = []github.Issue{
		issue(10, "OPEN", cveBody("CVE-2025-0002", "text", "", "- **Due date:** 2025-12-31"), "severity:high"),
		issue(11, "OPEN", cveBody("CVE-2025-0003"), "risk-accepted"),
		issue(12, "OPEN", cveBody("CVE-2024-9999")),
		issue(13, "OPEN", "<!-- scout-cve:CVE-2025-0004 --> not ours"),
		issue(14, "OPEN", "no marker"),
		issue(15, "CLOSED", cveBody("CVE-2025-0005"), "risk-accepted"),
		issue(16, "CLOSED", cveBody("CVE-2025-0007")),
		issue(17, "OPEN", cveBody("CVE-2024-8888")),
		issue(18, "OPEN", cveBody("CVE-2024-8888")),
	}
	amd64, arm64 := repository+":v1.2.3-amd64", repository+":v1.2.3-arm64"
	message := sync(t, h,
		finding("CVE-2025-0001", "critical", amd64),
		finding("CVE-2025-0002", "critical", amd64, arm64),
		finding("CVE-2025-0003", "high", amd64),
		finding("CVE-2025-0004", "critical", amd64),
		finding("CVE-2025-0005", "high", amd64),
		finding("CVE-2025-0007", "high", amd64),
	)
	gh := h.gh

	assert.Contains(t, gh.Logged("issue list"), "--label security --state all", "lists open and closed issues")

	created := strings.Join(gh.Logged("issue create"), "\n")
	assert.Contains(t, created, "--title Image scan: CVE-2025-0001 (critical) --label security --label severity:critical", "opens the new critical CVE with its labels")
	assert.Contains(t, created, "<!-- image-scan-cve:CVE-2025-0001 -->", "new issue body has the neutral marker")
	assert.Contains(t, created, "**Due date:** 2026-12-01", "new critical is due in 7 days")
	assert.Contains(t, created, "CVE-2025-0004", "the old scout marker is not matched, so opened anew")
	assert.NotContains(t, created, "CVE-2025-0005", "closed risk-accepted does not open a duplicate")
	assert.Contains(t, created, "CVE-2025-0007 (high)", "closed issue without the label is opened anew")
	assert.Contains(t, created, "**Due date:** 2026-12-24", "a new high is due in 30 days")

	edits := gh.Logged("issue edit")
	require.Len(t, edits, 1, "known CVE refreshed, risk-accepted skipped")
	assert.True(t, strings.HasPrefix(edits[0], "10 --title Image scan: CVE-2025-0002 (critical) "), "severity change swaps the title")
	assert.Contains(t, edits[0], "**Due date:** 2025-12-31", "known CVE keeps its due date")
	assert.Contains(t, edits[0], "**Affected images:** `"+amd64+"`, `"+arm64+"`")
	assert.Contains(t, gh.Logged("issue label add"), "10 severity:critical", "severity change swaps the label")
	assert.Contains(t, gh.Logged("issue label remove"), "10 severity:high", "and removes the other label")
	assert.False(t, gh.Contains("issue edit 11"), "risk-accepted is skipped")

	closed := strings.Join(gh.Logged("issue close"), "\n")
	assert.Contains(t, closed, "12 CVE-2024-9999 is not reported anymore by the image scan in latest release `v1.2.3` (published 2026-01-02)", "fixed CVE closed")
	assert.Contains(t, closed, "17 ")
	assert.Contains(t, closed, "18 ", "duplicate open issues of a fixed CVE are all closed")
	assert.Len(t, gh.Logged("issue close"), 3, "closed issues are not closed again, a still reported CVE is not closed, an issue without marker is untouched")

	assert.Equal(t, 3, strings.Count(message, "•"), "slack lists new issues only")
	assert.Contains(t, message, "found 3 new", "header counts them")
	assert.Contains(t, message, "<https://github.com/o/r/issues/99|CVE-2025-0001> (critical), due 2026-12-01", "links the issue with its due date")
}

func TestSyncIssuesDuplicates(t *testing.T) {
	h := newHarness(t, "amd64", 1)
	h.gh.Issues = []github.Issue{
		issue(30, "OPEN", cveBody("CVE-2025-0001")),
		issue(31, "OPEN", cveBody("CVE-2025-0001")),
	}
	sync(t, h, finding("CVE-2025-0001", "high", "i"))
	assert.Len(t, h.gh.Logged("issue edit"), 1)
	assert.True(t, strings.HasPrefix(h.gh.Logged("issue edit")[0], "30 "), "the oldest duplicate is refreshed")
	require.Len(t, h.gh.Logged("issue close"), 1)
	assert.True(t, strings.HasPrefix(h.gh.Logged("issue close")[0], "31 Duplicate of #30."), "other duplicates are closed")

	// a risk-accepted one is kept over an older one
	h = newHarness(t, "amd64", 1)
	h.gh.Issues = []github.Issue{
		issue(30, "OPEN", cveBody("CVE-2025-0001")),
		issue(31, "OPEN", cveBody("CVE-2025-0001"), "risk-accepted"),
	}
	sync(t, h, finding("CVE-2025-0001", "high", "i"))
	assert.Empty(t, h.gh.Logged("issue edit"), "the risk-accepted issue is kept, so nothing is refreshed")
	assert.True(t, strings.HasPrefix(h.gh.Logged("issue close")[0], "30 Duplicate of #31."))
}

func TestSyncIssuesFixedRiskAcceptedIsTrackedAgain(t *testing.T) {
	h := newHarness(t, "amd64", 1)
	h.gh.Issues = []github.Issue{issue(40, "OPEN", cveBody("CVE-2024-1"), "risk-accepted")}
	sync(t, h)
	assert.True(t, strings.HasPrefix(h.gh.Logged("issue close")[0], "40 "), "fixed risk-accepted issue is closed")
	assert.Contains(t, h.gh.Logged("issue label remove"), "40 risk-accepted", "and loses risk-accepted")
}

func TestSyncIssuesFailureStillAnnounces(t *testing.T) {
	h := newHarness(t, "amd64", 1)
	h.gh.Issues = []github.Issue{issue(20, "OPEN", cveBody("CVE-2024-1"))}
	h.gh.Fail["issue close"] = true
	message, err := h.w.SyncIssues(t.Context(), "v1.2.3", []weekly.Finding{finding("CVE-2025-0001", "critical", "i")})
	require.Error(t, err, "a gh failure fails the sync")
	assert.Contains(t, message, "CVE-2025-0001", "issue opened before the failure is announced")
}

func TestSyncIssuesMissingDueDateIsRecomputed(t *testing.T) {
	h := newHarness(t, "amd64", 1)
	h.gh.Issues = []github.Issue{issue(21, "OPEN", cveBody("CVE-2025-0001", "edited"))}
	sync(t, h, finding("CVE-2025-0001", "critical", "i"))
	assert.Contains(t, h.gh.Logged("issue edit")[0], "**Due date:** 2026-12-01")
	assert.Contains(t, h.gh.Logged("issue edit")[0], "(last seen 2026-11-24)")
}

func TestSyncIssuesWithNothingOpenedSaysNothing(t *testing.T) {
	h := newHarness(t, "amd64", 1)
	assert.Equal(t, "", sync(t, h), "no message when nothing was opened")
}

func TestSyncIssuesReleaseDateFallsBackToToday(t *testing.T) {
	h := newHarness(t, "amd64", 1)
	h.gh.Fail["release view"] = true
	h.gh.Issues = []github.Issue{issue(12, "OPEN", cveBody("CVE-2024-9999"))}
	sync(t, h)
	assert.Contains(t, h.gh.Logged("issue close")[0], "(published 2026-11-24)")
}
