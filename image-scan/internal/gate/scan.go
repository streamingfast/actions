package gate

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/streamingfast/actions/image-scan/internal/report"
	"github.com/streamingfast/actions/image-scan/internal/scanner"
	"github.com/streamingfast/actions/image-scan/internal/scout"
	"github.com/streamingfast/actions/image-scan/internal/vex"
)

// ScanResult is the outcome of the scan step.
type ScanResult struct {
	Code     int  // scanner.ExitClean, ExitFindings or ExitInfra
	Enforce  bool // findings fail the build
	Findings bool
	// Report goes to the job summary in full: the CVE table, the CVEs suppressed by the VEX documents with their
	// justification, then the scanner's own markdown report.
	Report string
	// Comment goes to the pull request comment, quieter: on findings the same with the scanner report collapsed, on a clean scan
	// one line (with the CVEs accepted via VEX collapsed), which is only posted to update the comment of an earlier failing run.
	Comment string
}

// Ran tells whether the scanner gave a verdict.
func (r ScanResult) Ran() bool { return r.Code == scanner.ExitClean || r.Code == scanner.ExitFindings }

var sha256Digest = regexp.MustCompile(`sha256:[0-9a-f]{64}`)

// sarifPass runs the scanner for its SARIF report, best effort: an infrastructure failure only drops the tables.
func (g *Gate) sarifPass(ctx context.Context, image, vexLocation string) ([]scout.Finding, bool) {
	result, err := g.Scanner.Scan(ctx, scanner.Request{Image: image, Format: scanner.SARIF, VexLocation: vexLocation, FindingsLevel: "debug"})
	if err != nil || (result.Code != scanner.ExitClean && result.Code != scanner.ExitFindings) {
		code := result.Code
		if err != nil {
			code = -1
		}
		g.Log.Warningf("Cannot list the CVEs of %s: the scanner failed (exit %d), the report has no CVE table", image, code)
		return nil, false
	}
	return scout.Findings(result.Report), true
}

// scan scans the image, names the CVEs, applies the VEX exceptions and builds the reports.
//
// The scanner runs up to 3 times: 1. markdown report, exit code (with the VEX documents), 2. on findings, the SARIF report with
// the same documents to name the CVEs, 3. with vex-location, the SARIF report WITHOUT the documents: what disappeared from the
// second is what the documents suppress. Only the first decides the outcome, the others are best effort (the scanner failing
// there only drops the tables, with a warning).
func (g *Gate) scan(ctx context.Context, image string) (ScanResult, error) {
	var enforce bool
	switch e := strings.ToLower(cmpOr(g.Config.Enforce, "true")); e {
	case "true":
		enforce = true
	case "false":
	default:
		return ScanResult{}, fmt.Errorf("enforce must be true or false, got '%s'", g.Config.Enforce)
	}
	vexLocation := g.Config.VexLocation

	level := "error"
	if !enforce {
		level = "warning"
	}

	// 1. The decision
	decision, err := g.Scanner.Scan(ctx, scanner.Request{Image: image, VexLocation: vexLocation, FindingsLevel: level})
	if err != nil {
		return ScanResult{}, err
	}
	result := ScanResult{Code: decision.Code, Enforce: enforce}
	if !result.Ran() {
		return result, nil
	}
	findings := decision.Code == scanner.ExitFindings
	scoutReport := string(decision.Report)

	// 2. and 3. The CVEs, best effort
	var active []scout.Finding
	if findings {
		active, _ = g.sarifPass(ctx, image, vexLocation)
		if len(active) == 0 {
			g.Log.Warningf("The scanner reported vulnerabilities in %s but none could be read from its SARIF report, see the scanner report", image)
		}
	}

	var suppressed []vex.Suppressed
	if vexLocation != "" {
		statements := vex.Statements(vexLocation)
		if all, ok := g.sarifPass(ctx, image, ""); ok {
			suppressed = vex.SuppressedFindings(all, active, statements, image)
			// A statement that cannot work must be seen, not trusted
			for _, s := range vex.Ineffective(statements) {
				g.Log.Warningf("VEX statement for %s in %s has status %s: only not_affected suppresses a CVE, this one is ignored",
					cmpOr(s.ID, "?"), s.File, cmpOr(s.Status, "none"))
			}
			for _, s := range vex.Stale(all, statements) {
				g.Log.Noticef("VEX statement for %s in %s matches no critical/high finding of %s, remove it if the fix shipped", s.ID, s.File, image)
			}
		}
	}

	// The log: findings and exceptions by name
	if len(active) > 0 {
		g.Log.Printf("Vulnerabilities of %s:", image)
		g.Log.Println(report.FindingsText(active))
	}
	if len(suppressed) > 0 {
		g.Log.Printf("Suppressed by the VEX documents of %s (%d), not counted above:", vexLocation, len(suppressed))
		g.Log.Println(report.SuppressedText(suppressed))
		ids := make([]string, len(suppressed))
		for i, s := range suppressed {
			ids[i] = s.ID
		}
		g.Log.Noticef("%d vulnerabilities of %s are suppressed by the VEX documents of %s: %s", len(suppressed), image, vexLocation, strings.Join(ids, ", "))
	}

	result.Findings = findings
	result.Report = g.buildReport(findings, enforce, active, suppressed, scoutReport)
	result.Comment = g.buildComment(findings, enforce, active, suppressed, scoutReport, image)

	if findings && !enforce {
		g.Log.Warningf("Advisory mode (enforce: false): %s has vulnerabilities, the build is not failed", image)
	}
	return result, nil
}

const advisoryBanner = "> [!WARNING]\n> Advisory mode (`enforce: false`): the vulnerabilities below do not fail the build.\n\n"

func (g *Gate) vulnerabilitiesSection(active []scout.Finding) string {
	return fmt.Sprintf("### Vulnerabilities (%d)\n\n%s\n\n", len(active), report.FindingsMarkdown(active, report.DefaultLimit))
}

func (g *Gate) buildReport(findings, enforce bool, active []scout.Finding, suppressed []vex.Suppressed, scoutReport string) string {
	var b strings.Builder
	if findings && !enforce {
		b.WriteString(advisoryBanner)
	}
	if len(active) > 0 {
		b.WriteString(g.vulnerabilitiesSection(active))
	}
	if len(suppressed) > 0 {
		fmt.Fprintf(&b, "### Suppressed by VEX (%d)\n\nNot counted as findings: the statements of `%s` mark them not affected. Each one must link its `risk-accepted` issue and go away when the fix ships.\n\n%s\n\n",
			len(suppressed), g.Config.VexLocation, report.SuppressedMarkdown(suppressed, report.DefaultLimit))
	}
	// Nothing more to tell when only the scanner's report is left
	if len(active) > 0 || len(suppressed) > 0 || (findings && !enforce) {
		b.WriteString("### Scanner report\n\n")
	}
	b.WriteString(scoutReport)
	return b.String()
}

func (g *Gate) buildComment(findings, enforce bool, active []scout.Finding, suppressed []vex.Suppressed, scoutReport, image string) string {
	var b strings.Builder
	if !findings {
		severities := strings.ReplaceAll(strings.ToLower(strings.ReplaceAll(cmpOr(g.Config.Severities, "critical,high"), " ", "")), ",", "/")
		line := fmt.Sprintf("✅ Image scan: no %s vulnerabilities in %s", severities, image)
		// The scanner's report names the digest, no extra call for it
		if digest := sha256Digest.FindString(scoutReport); digest != "" {
			line += fmt.Sprintf(" (%s)", digest[len("sha256:"):][:12])
		}
		if len(suppressed) > 0 {
			line += fmt.Sprintf(", %d accepted via VEX", len(suppressed))
		}
		b.WriteString(line + "\n")
		if len(suppressed) > 0 {
			fmt.Fprintf(&b, "\n<details><summary>Accepted via VEX (%d)</summary>\n\nThe statements of `%s` mark them not affected. Each one must link its `risk-accepted` issue and go away when the fix ships.\n\n%s\n\n</details>\n",
				len(suppressed), g.Config.VexLocation, report.SuppressedMarkdown(suppressed, report.DefaultLimit))
		}
		return b.String()
	}

	if !enforce {
		b.WriteString(advisoryBanner)
	}
	if len(active) > 0 {
		b.WriteString(g.vulnerabilitiesSection(active))
	}
	if len(suppressed) > 0 {
		fmt.Fprintf(&b, "### Accepted via VEX (%d)\n\n%s\n\n", len(suppressed), report.SuppressedMarkdown(suppressed, report.DefaultLimit))
	}
	fmt.Fprintf(&b, "<details><summary>Scanner report</summary>\n\n%s\n\n</details>\n", scoutReport)
	return b.String()
}
