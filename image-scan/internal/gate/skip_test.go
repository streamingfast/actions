package gate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/streamingfast/actions/image-scan/internal/gate"
	"github.com/streamingfast/actions/image-scan/internal/github"
	"github.com/streamingfast/actions/image-scan/internal/testutil"
)

func TestDecideSkip(t *testing.T) {
	decide := func(reason, event string) (bool, *harness) {
		h := newHarness(t, config(func(c *gate.Config) { c.SkipReason, c.EventName = reason, event }))
		return h.g.DecideSkip(), h
	}

	skip, _ := decide("outage", "workflow_dispatch")
	assert.True(t, skip, "workflow_dispatch with a reason skips")
	skip, _ = decide("", "workflow_dispatch")
	assert.False(t, skip, "no reason scans")
	skip, _ = decide("  ", "workflow_dispatch")
	assert.False(t, skip, "blank reason scans")
	_, h := decide("", "push")
	assert.Empty(t, h.log.String(), "no reason does not warn")

	for _, event := range []string{"push", "pull_request", "schedule"} {
		skip, h := decide("outage", event)
		assert.False(t, skip, "%s ignores the reason", event)
		assert.Contains(t, h.log.String(), "::warning::skip-reason is ignored on a "+event+" event", "%s warns", event)
	}
}

func recordHarness(t *testing.T) *harness {
	return newHarness(t, config(func(c *gate.Config) {
		c.Image = "ghcr.io/o/r:0123456"
		c.SkipReason = "upstream CVE\nhard fork at 12:00"
		c.Actor, c.RunID, c.ServerURL = "alice", "42", "https://github.com"
	}))
}

func TestRecordSkip(t *testing.T) {
	digest := testutil.Digest("c")
	image := "ghcr.io/o/r:0123456"

	t.Run("opens an issue", func(t *testing.T) {
		h := recordHarness(t)
		h.g.RecordSkip(t.Context(), image, digest)

		warning := "::warning::Image scan SKIPPED for " + image + "@" + digest + " by alice: upstream CVE hard fork at 12:00 (https://github.com/o/r/actions/runs/42)"
		assert.True(t, h.logHas(warning), "warning has image, digest, actor, reason, run, on a single line")

		summary := h.readSummary()
		for _, want := range []string{"alice", digest, "hard fork at 12:00", "https://github.com/o/r/actions/runs/42", "2026-11-24T10:00:00Z"} {
			assert.Contains(t, summary, want, "summary has %s", want)
		}

		created := h.gh.Logged("issue create")
		if assert.Len(t, created, 1) {
			issue := created[0]
			assert.Contains(t, issue, "--title Image scan skipped: ghcr.io/o/r:0123456@cccccccccccc --label", "issue titled with the short digest")
			assert.Contains(t, issue, "--label security --label image-scan-skipped", "issue labels")
			assert.Contains(t, issue, "<!-- image-scan-skipped:ghcr.io/o/r:0123456@"+digest+" -->", "issue has the marker")
			assert.Regexp(t, `re-run the scan.*then close this issue`, issue, "issue asks to re-scan and close")
			assert.Contains(t, issue, "Skipped by:** @alice", "issue has the actor")
			assert.Contains(t, issue, "  > hard fork at 12:00", "issue has the reason, quoted")
		}
		assert.Contains(t, h.gh.Logged("label create"), "image-scan-skipped", "labels are created best-effort")
	})

	t.Run("an open issue of the same image@digest is commented", func(t *testing.T) {
		h := recordHarness(t)
		h.gh.Issues = []github.Issue{
			{Number: 7, State: "OPEN", Body: "<!-- image-scan-skipped:ghcr.io/o/r:0123456@" + digest + " -->"},
			{Number: 8, State: "OPEN", Body: "<!-- image-scan-skipped:other@" + digest + " -->"},
		}
		h.g.RecordSkip(t.Context(), image, digest)
		if assert.Len(t, h.gh.Logged("issue comment"), 1) {
			assert.Regexp(t, `^7 The scan of this image was skipped again`, h.gh.Logged("issue comment")[0])
		}
		assert.Empty(t, h.gh.Logged("issue create"), "no other is opened")
	})

	t.Run("an issue failure still records the warning and the summary", func(t *testing.T) {
		for _, op := range []string{"issue create", "issue list"} {
			h := recordHarness(t)
			h.gh.Fail[op] = true
			h.g.RecordSkip(t.Context(), image, digest)
			assert.Contains(t, h.log.String(), "::warning::Cannot record the skipped scan as a GitHub issue", op)
			assert.Contains(t, h.readSummary(), "alice", "%s keeps the summary", op)
		}
	})

	t.Run("an unresolved digest is recorded", func(t *testing.T) {
		h := recordHarness(t)
		h.g.RecordSkip(t.Context(), image, "")
		assert.Contains(t, h.log.String(), "@unresolved")
		assert.Contains(t, h.gh.Logged("issue create")[0], "--title Image scan skipped: ghcr.io/o/r:0123456@unresolved --label")
	})
}
