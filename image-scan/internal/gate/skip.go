package gate

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/streamingfast/actions/image-scan/internal/gha"
)

const skippedLabel = "image-scan-skipped"

// decideSkip tells whether the scan is bypassed: only when skip-reason is not blank AND the event is workflow_dispatch (a
// person triggered the run). On any other event the reason is ignored, with a warning, and the scan runs normally: a
// misconfigured workflow must not bypass the gate.
func (g *Gate) decideSkip() bool {
	if strings.TrimSpace(g.Config.SkipReason) == "" {
		return false
	}
	if g.Config.EventName == "workflow_dispatch" {
		return true
	}
	event := g.Config.EventName
	if event == "" {
		event = "unknown"
	}
	g.Log.Warningf("skip-reason is ignored on a %s event, the scan runs: the scan can only be skipped on a manual workflow_dispatch run", event)
	return false
}

var dashRuns = regexp.MustCompile(`-+`)

// htmlSafe collapses runs of dashes: `--` would end an HTML comment early.
func htmlSafe(s string) string { return dashRuns.ReplaceAllString(s, "-") }

// recordSkip is the audit trail of a bypass: a warning, a job summary section and a GitHub issue (opened, or commented when
// one is already open for that image@digest). It never fails: the issue is best-effort (missing issues: write permission,
// ...) since the warning and the job summary are always recorded.
func (g *Gate) recordSkip(ctx context.Context, image, digest string) {
	reason := strings.TrimSpace(g.Config.SkipReason)
	actor := cmpOr(g.Config.Actor, "unknown")
	repo := g.Config.Repo
	serverURL := cmpOr(g.Config.ServerURL, "https://github.com")
	runID := cmpOr(g.Config.RunID, "0")
	runURL := fmt.Sprintf("%s/%s/actions/runs/%s", serverURL, repo, runID)
	when := g.now().Format("2006-01-02T15:04:05Z")
	digestText := cmpOr(digest, "unresolved")

	short := strings.TrimPrefix(digest, "sha256:")
	if len(short) > 12 {
		short = short[:12]
	}
	title := fmt.Sprintf("Image scan skipped: %s@%s", image, cmpOr(short, "unresolved"))
	// Hidden marker, one issue per image@digest
	marker := fmt.Sprintf("<!-- image-scan-skipped:%s -->", htmlSafe(image+"@"+digest))

	g.Log.Warningf("Image scan SKIPPED for %s@%s by %s: %s (%s)", image, digestText, actor, gha.OneLine(reason), runURL)

	var quoted strings.Builder
	for line := range strings.Lines(reason) {
		quoted.WriteString("  > " + line)
	}
	if !strings.HasSuffix(reason, "\n") {
		quoted.WriteString("\n")
	}
	details := strings.TrimRight(fmt.Sprintf("- **Image:** `%s`\n- **Digest:** `%s`\n- **Skipped by:** @%s\n- **Time:** %s\n- **Run:** %s\n- **Reason:**\n\n%s",
		image, digestText, actor, when, runURL, quoted.String()), "\n")

	summary := fmt.Sprintf("## Image scan skipped (%s)\n\nThe vulnerability scan was bypassed with `skip-reason`, an audited exception.\n\n%s\n", image, details)
	if err := g.Files.AppendSummary(summary); err != nil {
		g.Log.Warningf("Cannot write the job summary: %v", err)
	}

	issueFailed := func(what string, err error) {
		g.Log.Warningf("Cannot record the skipped scan as a GitHub issue (%s: %v), the warning and the job summary are the only record. Does the token have issues: write?", what, err)
	}

	// Best-effort, the labels may exist already
	for _, label := range []string{"security", skippedLabel} {
		_ = g.GitHub.CreateLabel(ctx, repo, label, "ededed")
	}

	open, err := g.GitHub.ListIssues(ctx, repo, skippedLabel, "open", 200)
	if err != nil {
		issueFailed("listing the issues", err)
		return
	}
	for _, issue := range open {
		if !strings.Contains(issue.Body, marker) {
			continue
		}
		comment := fmt.Sprintf("The scan of this image was skipped again.\n\n%s", details)
		if err := g.GitHub.CommentIssue(ctx, repo, issue.Number, comment); err != nil {
			issueFailed(fmt.Sprintf("commenting #%d", issue.Number), err)
			return
		}
		g.Log.Printf("Updated issue #%d", issue.Number)
		return
	}

	body := fmt.Sprintf("%s\nThe vulnerability scan of this image was **skipped** with an audited emergency bypass (`skip-reason`).\n\n%s\n\n**Follow up:** scan this image as soon as possible (re-run the scan, or the `image-scan/gate` workflow without `skip-reason`), fix or document the findings, then close this issue.", marker, details)
	url, err := g.GitHub.CreateIssue(ctx, repo, title, body, []string{"security", skippedLabel})
	if err != nil {
		issueFailed("creating the issue", err)
		return
	}
	g.Log.Printf("Opened %s", url)
}
