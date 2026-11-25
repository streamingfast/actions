// Package report renders findings and VEX suppressions as a log table and markdown tables.
package report

import (
	"cmp"
	"fmt"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/streamingfast/actions/image-scan/internal/scout"
	"github.com/streamingfast/actions/image-scan/internal/vex"
)

// DefaultLimit caps the rows of a markdown table to stay below the pull request comment size limit.
const DefaultLimit = 100

var (
	newlines = regexp.MustCompile(`[\r\n]+`)
	pipes    = strings.NewReplacer("|", `\|`)
)

// cell makes a value safe in a markdown table cell, cut to limit characters when limit > 0.
func cell(s string, limit int) string {
	s = newlines.ReplaceAllString(pipes.Replace(s), " ")
	if limit > 0 {
		if runes := []rune(s); len(runes) > limit {
			return string(runes[:limit]) + "…"
		}
	}
	return s
}

// head is the first limit rows.
func head[T any](rows []T, limit int) []T {
	if len(rows) > limit {
		return rows[:limit]
	}
	return rows
}

func fixedText(f string) string {
	return cmp.Or(f, "no fix")
}

// FindingsText is the aligned plain text table of the log.
func FindingsText(rows []scout.Finding) string {
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CVE\tSEVERITY\tPACKAGE\tINSTALLED\tFIXED")
	for _, f := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", f.ID, f.Severity, f.Package, f.Installed, fixedText(f.Fixed))
	}
	w.Flush()
	return strings.TrimRight(b.String(), "\n")
}

// FindingsMarkdown is the markdown table, at most limit rows.
func FindingsMarkdown(rows []scout.Finding, limit int) string {
	lines := []string{"| CVE | Severity | Package | Installed | Fixed |", "|---|---|---|---|---|"}
	for _, f := range head(rows, limit) {
		lines = append(lines, fmt.Sprintf("| %s | %s | `%s` | %s | %s |", cell(f.ID, 0), f.Severity, cell(f.Package, 0), cell(f.Installed, 0), cell(fixedText(f.Fixed), 0)))
	}
	if len(rows) > limit {
		lines = append(lines, "", fmt.Sprintf("… and %d more, see the scanner report below", len(rows)-limit))
	}
	return strings.Join(lines, "\n")
}

func statementText(s vex.StatementOfSuppressed) string {
	text := cmp.Or(s.Justification, "no justification")
	if s.Impact != "" {
		text += " - " + s.Impact
	}
	text += " [" + s.File + "]"
	if !s.Scoped {
		text += " (statement not scoped to this image)"
	}
	return text
}

// Explanation says why a CVE is suppressed, for the log and the weekly summary.
func Explanation(s vex.Suppressed) string {
	if len(s.Statements) == 0 {
		return "suppressed, not by a vex-location statement"
	}
	texts := make([]string, len(s.Statements))
	for i, statement := range s.Statements {
		texts[i] = statementText(statement)
	}
	return strings.Join(texts, " | ")
}

// SuppressedText is one line per CVE for the log.
func SuppressedText(rows []vex.Suppressed) string {
	lines := make([]string, len(rows))
	for i, s := range rows {
		lines[i] = fmt.Sprintf("%s (%s) %s %s: %s", s.ID, s.Severity, s.Package, s.Installed, Explanation(s))
	}
	return strings.Join(lines, "\n")
}

// SuppressedMarkdown is the markdown table of the CVEs accepted via VEX, at most limit rows.
func SuppressedMarkdown(rows []vex.Suppressed, limit int) string {
	perStatement := func(s vex.Suppressed, f func(vex.StatementOfSuppressed) string) string {
		parts := make([]string, len(s.Statements))
		for i, statement := range s.Statements {
			parts[i] = f(statement)
		}
		return strings.Join(parts, "<br>")
	}

	lines := []string{
		"| CVE | Severity | Package | Installed | Justification | Author | Statement date |",
		"|---|---|---|---|---|---|---|",
	}
	for _, s := range head(rows, limit) {
		justification := "_suppressed, not by a statement of vex-location_"
		if s.Status != "" {
			justification = perStatement(s, func(st vex.StatementOfSuppressed) string {
				var parts []string
				if st.Justification != "" {
					parts = append(parts, st.Justification)
				}
				if st.Impact != "" {
					parts = append(parts, cell(st.Impact, 300))
				}
				text := cmp.Or(strings.Join(parts, ": "), "_none_") + fmt.Sprintf(" (`%s`)", cell(st.File, 60))
				if !st.Scoped {
					text += " _(statement not scoped to this image)_"
				}
				return text
			})
		}
		lines = append(lines, fmt.Sprintf("| %s | %s | `%s` | %s | %s | %s | %s |",
			cell(s.ID, 40), s.Severity, cell(s.Package, 80), cell(s.Installed, 40), justification,
			perStatement(s, func(st vex.StatementOfSuppressed) string { return cell(st.Author, 80) }),
			perStatement(s, func(st vex.StatementOfSuppressed) string { return cell(st.Timestamp, 40) })))
	}
	if len(rows) > limit {
		lines = append(lines, "", fmt.Sprintf("… and %d more", len(rows)-limit))
	}
	return strings.Join(lines, "\n")
}
