package weekly

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/streamingfast/actions/image-scan/internal/github"
)

const riskAccepted = "risk-accepted"

var (
	cveMarker = regexp.MustCompile(`<!-- image-scan-cve:(\S+) -->`)
	dueDate   = regexp.MustCompile(`\*\*Due date:\*\* ([0-9-]+)`)
)

type trackedIssue struct {
	github.Issue
	cve string
}

func severityLabel(severity string) string { return "severity:" + severity }

func (w *Weekly) dueDate(severity string) string {
	days := 30
	if severity == "critical" {
		days = 7
	}
	return w.now().AddDate(0, 0, days).Format(time.DateOnly)
}

func issueTitle(id, severity string) string { return fmt.Sprintf("Image scan: %s (%s)", id, severity) }

// syncIssues syncs the GitHub issues with the findings of a COMPLETE scan of the latest release (all architectures),
// otherwise CVEs would be closed wrongly. One issue per CVE, deduped by the hidden marker `<!-- image-scan-cve:ID -->`:
//
//   - new CVE            -> issue opened (labels security + severity:*), due date critical +7d, high +30d
//   - known CVE          -> issue title/body refreshed, due date kept; skipped when labelled `risk-accepted` (open or closed:
//     closing a risk-accepted issue does not open a new one)
//   - CVE no longer seen -> open issue(s) closed with the release it was fixed in
//
// It returns the slack message listing the issues opened, empty when none was, also on an error: the announcement of the
// issues opened before the failure must not be lost.
func (w *Weekly) syncIssues(ctx context.Context, tag string, findings []Finding) (message string, err error) {
	repo := w.Config.Repo

	for _, label := range [][2]string{{"security", "B60205"}, {"severity:critical", "B60205"}, {"severity:high", "D93F0B"}, {riskAccepted, "FBCA04"}} {
		_ = w.GitHub.CreateLabel(ctx, repo, label[0], label[1])
	}

	releaseDate, dateErr := w.GitHub.ReleasePublishedAt(ctx, repo, tag)
	if dateErr != nil {
		releaseDate = w.now().Format(time.DateOnly)
	}

	// Issues of the scan (open and closed) with their CVE id from the hidden marker
	listed, err := w.GitHub.ListIssues(ctx, repo, "security", "all", 1000)
	if err != nil {
		return "", fmt.Errorf("listing the issues: %w", err)
	}
	var all, openList []trackedIssue
	for _, issue := range listed {
		m := cveMarker.FindStringSubmatch(issue.Body)
		if m == nil {
			continue
		}
		t := trackedIssue{Issue: issue, cve: m[1]}
		all = append(all, t)
		if issue.State == "OPEN" {
			openList = append(openList, t)
		}
	}

	// The one kept per CVE is the oldest, a risk-accepted one first
	kept := map[string]trackedIssue{}
	for _, t := range openList {
		current, ok := kept[t.cve]
		if !ok || better(t, current) {
			kept[t.cve] = t
		}
	}
	// CVE ids whose issue, open or closed, is risk-accepted
	accepted := map[string]bool{}
	for _, t := range all {
		if t.HasLabel(riskAccepted) {
			accepted[t.cve] = true
		}
	}

	var lines []string
	defer func() {
		if len(lines) > 0 {
			message = fmt.Sprintf(":warning: *%s* image scan found %d new critical/high CVE(s) in `%s`:\n%s", repo, len(lines), tag, strings.Join(lines, "\n"))
		}
	}()

	for _, f := range findings {
		images := make([]string, len(f.Images))
		for i, image := range f.Images {
			images[i] = "`" + image + "`"
		}
		imageList := strings.Join(images, ", ")

		if existing, ok := kept[f.ID]; ok {
			// Extra open issues of the same CVE
			for _, t := range openList {
				if t.cve == f.ID && t.Number != existing.Number {
					if err := w.GitHub.CloseIssue(ctx, repo, t.Number, fmt.Sprintf("Duplicate of #%d.", existing.Number)); err != nil {
						return "", err
					}
					w.Log.Printf("%s: closed duplicate #%d", f.ID, t.Number)
				}
			}
			if existing.HasLabel(riskAccepted) {
				w.Log.Printf("%s: #%d is risk-accepted, skipping", f.ID, existing.Number)
				continue
			}
			// Due date of the first detection, recomputed from the severity if the body lost it
			due := w.dueDate(f.Severity)
			if m := dueDate.FindStringSubmatch(existing.Body); m != nil {
				due = m[1]
			}
			body := fmt.Sprintf("<!-- image-scan-cve:%s -->\nThe image scan reports **%s** (%s) in release `%s` (last seen %s).\n\n- **Due date:** %s\n- **Affected images:** %s\n\nClosed automatically once a release no longer reports it. Add the `%s` label to stop tracking.\nThis description is rewritten on every scan, discuss in comments.",
				f.ID, f.ID, f.Severity, tag, w.now().Format(time.DateOnly), due, imageList, riskAccepted)
			if err := w.GitHub.AddLabel(ctx, repo, existing.Number, severityLabel(f.Severity)); err != nil {
				return "", err
			}
			if err := w.GitHub.EditIssue(ctx, repo, existing.Number, issueTitle(f.ID, f.Severity), body); err != nil {
				return "", err
			}
			for _, other := range []string{"critical", "high"} {
				if other != f.Severity {
					_ = w.GitHub.RemoveLabel(ctx, repo, existing.Number, severityLabel(other))
				}
			}
			w.Log.Printf("%s: updated #%d", f.ID, existing.Number)
			continue
		}

		if accepted[f.ID] {
			w.Log.Printf("%s: has a risk-accepted issue, skipping", f.ID)
			continue
		}

		due := w.dueDate(f.Severity)
		body := fmt.Sprintf("<!-- image-scan-cve:%s -->\nThe image scan reports **%s** (%s) in release `%s`.\n\n- **Due date:** %s\n- **Affected images:** %s\n\nClosed automatically once a release no longer reports it. Add the `%s` label to stop tracking.",
			f.ID, f.ID, f.Severity, tag, due, imageList, riskAccepted)
		url, err := w.GitHub.CreateIssue(ctx, repo, issueTitle(f.ID, f.Severity), body, []string{"security", severityLabel(f.Severity)})
		if err != nil {
			return "", err
		}
		w.Log.Printf("%s: opened %s", f.ID, url)
		lines = append(lines, fmt.Sprintf("• <%s|%s> (%s), due %s", url, f.ID, f.Severity, due))
	}

	// Close issues whose CVE is not reported by the latest release anymore
	for _, t := range openList {
		if slices.ContainsFunc(findings, func(f Finding) bool { return f.ID == t.cve }) {
			continue
		}
		comment := fmt.Sprintf("%s is not reported anymore by the image scan in latest release `%s` (published %s). Closing as remediated.", t.cve, tag, releaseDate)
		if err := w.GitHub.CloseIssue(ctx, repo, t.Number, comment); err != nil {
			return "", err
		}
		// A fixed CVE that comes back later must be tracked again
		_ = w.GitHub.RemoveLabel(ctx, repo, t.Number, riskAccepted)
		w.Log.Printf("%s: closed #%d", t.cve, t.Number)
	}
	return "", nil
}

// better tells whether the issue is the one to keep over the current one: risk-accepted first, then the oldest.
func better(candidate, current trackedIssue) bool {
	if a, b := candidate.HasLabel(riskAccepted), current.HasLabel(riskAccepted); a != b {
		return a
	}
	return candidate.Number < current.Number
}
