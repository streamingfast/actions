// Package weekly scans the per-architecture images of the latest release and keeps one GitHub issue per critical/high CVE.
//
// An infrastructure failure fails the run BEFORE any issue is touched: a partial scan must never close issues.
package weekly

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/streamingfast/actions/image-scan/internal/gha"
	"github.com/streamingfast/actions/image-scan/internal/github"
	"github.com/streamingfast/actions/image-scan/internal/report"
	"github.com/streamingfast/actions/image-scan/internal/scanner"
	"github.com/streamingfast/actions/image-scan/internal/scout"
	"github.com/streamingfast/actions/image-scan/internal/vex"
)

// Exit codes besides those of the scanner: findings that cannot be read from the report.
const ExitUnreadable = 11

// Config is the inputs of the action.
type Config struct {
	ImageRepository string
	Architectures   string // space separated
	VexLocation     string
	Repo            string // owner/name
}

// Scanner is the scanner as the weekly scan uses it.
type Scanner interface {
	Scan(ctx context.Context, req scanner.Request) (scanner.Result, error)
}

// Finding is a CVE of the latest release, across architectures.
type Finding struct {
	ID       string
	Severity string // critical or high
	Images   []string
}

// Weekly holds what a run needs.
type Weekly struct {
	Config  Config
	Log     *gha.Logger
	Files   gha.Files
	Scanner Scanner
	GitHub  github.API
	Now     func() time.Time
}

func (w *Weekly) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}

// Run resolves the latest release, scans it, syncs the issues and sets the slack-message output.
func (w *Weekly) Run(ctx context.Context) int {
	tag, err := w.GitHub.LatestReleaseTag(ctx, w.Config.Repo)
	if err != nil {
		w.Log.Errorf("Cannot resolve the latest release of %s: %v", w.Config.Repo, err)
		return 1
	}
	w.Log.Printf("Latest release: %s", tag)

	findings, code := w.scan(ctx, tag)
	if code != 0 {
		return code
	}

	message, err := w.syncIssues(ctx, tag, findings)
	// Written even when the sync failed halfway, issues already opened must still be announced
	if setErr := w.Files.SetOutput("slack-message", message); setErr != nil {
		w.Log.Warningf("Cannot write the slack-message output: %v", setErr)
	}
	if err != nil {
		w.Log.Errorf("%v", err)
		return 1
	}
	return 0
}

// scan scans <repository>:<tag>-<arch> for every architecture. It returns the exit code of the scanner on an infrastructure
// failure (10), or ExitUnreadable when findings cannot be read from the report, so a partial scan has no findings.
func (w *Weekly) scan(ctx context.Context, tag string) ([]Finding, int) {
	var tracked []Finding
	var suppressed []vex.Suppressed
	var statements []vex.Statement
	if w.Config.VexLocation != "" {
		statements = vex.Statements(w.Config.VexLocation)
	}

	for arch := range strings.FieldsSeq(w.Config.Architectures) {
		image := fmt.Sprintf("%s:%s-%s", w.Config.ImageRepository, tag, arch)

		result, err := w.Scanner.Scan(ctx, scanner.Request{Image: image, Format: scanner.SARIF, VexLocation: w.Config.VexLocation})
		if err != nil {
			w.Log.Errorf("%v", err)
			return nil, 1
		}
		if result.Code != scanner.ExitClean && result.Code != scanner.ExitFindings {
			return nil, result.Code
		}

		// What the VEX documents suppress on this image (best effort, it only completes the summary): the findings without the
		// documents that the scan above, with them, does not report. The scan above alone decides which issues are open.
		if w.Config.VexLocation != "" {
			all, err := w.Scanner.Scan(ctx, scanner.Request{Image: image, Format: scanner.SARIF, FindingsLevel: "debug"})
			if err == nil && (all.Code == scanner.ExitClean || all.Code == scanner.ExitFindings) {
				var active []scout.Finding
				if result.Code == scanner.ExitFindings {
					active = scout.Findings(result.Report)
				}
				for _, s := range vex.SuppressedFindings(scout.Findings(all.Report), active, statements, image) {
					s.Image = image
					suppressed = append(suppressed, s)
				}
			} else {
				w.Log.Warningf("Cannot list the CVEs suppressed by the VEX documents on %s (scanner exit %d)", image, all.Code)
			}
		}

		if result.Code == scanner.ExitFindings {
			if len(result.Report) == 0 {
				w.Log.Errorf("The scanner reported findings for %s but wrote no report", image)
				return nil, ExitUnreadable
			}
			rows := scout.TrackedFindings(result.Report)
			// Findings that cannot be parsed must fail the job: an empty list would close every open issue
			if len(rows) == 0 {
				w.Log.Errorf("The scanner reported findings for %s but none could be read from its SARIF report", image)
				return nil, ExitUnreadable
			}
			for _, row := range rows {
				tracked = append(tracked, Finding{ID: row.ID, Severity: row.Severity, Images: []string{image}})
			}
		}
	}

	findings := mergeFindings(tracked)
	w.Log.Printf("Findings: %d", len(findings))
	w.summary(tag, findings, suppressed)
	return findings, 0
}

// mergeFindings keeps one entry per CVE across architectures, the most severe wins.
func mergeFindings(rows []Finding) []Finding {
	slices.SortStableFunc(rows, func(a, b Finding) int { return strings.Compare(a.ID, b.ID) })
	var merged []Finding
	for _, row := range rows {
		if n := len(merged); n > 0 && merged[n-1].ID == row.ID {
			last := &merged[n-1]
			if row.Severity == "critical" {
				last.Severity = "critical"
			}
			last.Images = append(last.Images, row.Images...)
			continue
		}
		merged = append(merged, Finding{ID: row.ID, Severity: row.Severity, Images: slices.Clone(row.Images)})
	}
	for i := range merged {
		slices.Sort(merged[i].Images)
		merged[i].Images = slices.Compact(merged[i].Images)
		if merged[i].Severity != "critical" {
			merged[i].Severity = "high"
		}
	}
	return merged
}

func (w *Weekly) summary(tag string, findings []Finding, suppressed []vex.Suppressed) {
	var b strings.Builder
	fmt.Fprintf(&b, "## Image scan of %s:%s\n\n", w.Config.ImageRepository, tag)
	if len(findings) == 0 {
		b.WriteString("No critical/high vulnerability.\n")
	}
	for _, f := range findings {
		fmt.Fprintf(&b, "- %s (%s)\n", f.ID, f.Severity)
	}
	if len(suppressed) > 0 {
		fmt.Fprintf(&b, "\nSuppressed by the VEX documents of `%s`, no issue opened:\n\n", w.Config.VexLocation)
		slices.SortStableFunc(suppressed, func(a, b vex.Suppressed) int { return strings.Compare(a.ID, b.ID) })
		for _, group := range groupByID(suppressed) {
			first := group[0]
			line := fmt.Sprintf("- %s (%s) %s %s", first.ID, first.Severity, first.Package, first.Installed)
			if first.Status != "" {
				line += ": " + report.Explanation(first)
			}
			images := make([]string, len(group))
			for i, s := range group {
				images[i] = s.Image
			}
			fmt.Fprintf(&b, "%s [%s]\n", line, strings.Join(images, ", "))
		}
	}
	if err := w.Files.AppendSummary(b.String()); err != nil {
		w.Log.Warningf("Cannot write the job summary: %v", err)
	}
}

func groupByID(rows []vex.Suppressed) [][]vex.Suppressed {
	var groups [][]vex.Suppressed
	for _, row := range rows {
		if n := len(groups); n > 0 && groups[n-1][0].ID == row.ID {
			groups[n-1] = append(groups[n-1], row)
		} else {
			groups = append(groups, []vex.Suppressed{row})
		}
	}
	return groups
}
