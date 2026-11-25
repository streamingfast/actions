// Package scout reads the SARIF report of `docker scout cves --format sarif`: one rule per CVE, with `properties` holding
// cvssV3_severity, security-severity, purls, affected_version and fixed_version.
//
// A field Scout does not provide is rendered as "unknown" / no fix, and a report that cannot be read gives no row: a missing
// table must not hide a finding.
package scout

import (
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Finding is one CVE of a report. Severity is critical, high, medium, low or unknown, Fixed is empty when there is no fix.
type Finding struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	Package   string `json:"package"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed"`
}

type sarifDoc struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []sarifRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID string `json:"ruleId"`
		} `json:"results"`
	} `json:"runs"`
}

type text struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Help             text           `json:"help"`
	FullDescription  text           `json:"fullDescription"`
	ShortDescription text           `json:"shortDescription"`
	Properties       map[string]any `json:"properties"`
}

func parse(data []byte) (sarifDoc, bool) {
	var doc sarifDoc
	if len(data) == 0 || json.Unmarshal(data, &doc) != nil {
		return sarifDoc{}, false
	}
	return doc, true
}

// ruleText is the first non-empty description of the rule, where Scout writes "Package:" style fields.
func (r sarifRule) ruleText() string {
	return cmpOr(r.Help.Text, r.FullDescription.Text, r.ShortDescription.Text)
}

func cmpOr(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func (r sarifRule) prop(name string) (string, bool) {
	v, ok := r.Properties[name]
	if !ok || v == nil {
		return "", false
	}
	if s, ok := v.(string); ok {
		return s, true
	}
	return "", false
}

// field reads a "Name: value" line of the rule text.
func (r sarifRule) field(name string) string {
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `:\s*(.+?)\s*$`)
	if m := re.FindStringSubmatch(r.ruleText()); m != nil {
		return m[1]
	}
	return ""
}

func (r sarifRule) purl() string {
	purls, _ := r.Properties["purls"].([]any)
	if len(purls) == 0 {
		return ""
	}
	s, _ := purls[0].(string)
	return s
}

// score is the numeric value of a property that may be a JSON number or a string, like jq's `tonumber?`.
func (r sarifRule) score(name string) (float64, bool) {
	switch v := r.Properties[name].(type) {
	case float64:
		return v, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f, err == nil
	}
	return 0, false
}

func (r sarifRule) severity() string {
	level, _ := r.prop("cvssV3_severity")
	level = strings.ToLower(level)
	if slices.Contains([]string{"critical", "high", "medium", "low"}, level) {
		return level
	}
	if score, ok := r.score("security-severity"); ok {
		switch {
		case score >= 9:
			return "critical"
		case score >= 7:
			return "high"
		case score >= 4:
			return "medium"
		default:
			return "low"
		}
	}
	return "unknown"
}

var osPackage = regexp.MustCompile(`^(deb|apk|rpm)/`)

// purlName is the package name of a purl: the namespace of an OS package is the distribution (debian/openssl), the one of a
// golang package is its module path. Anything that is not a purl is returned as is.
func purlName(s string) string {
	if !strings.HasPrefix(s, "pkg:") {
		return s
	}
	path := strings.TrimPrefix(s, "pkg:")
	if i := strings.IndexAny(path, "@?#"); i >= 0 {
		path = path[:i]
	}
	if osPackage.MatchString(path) {
		return path[strings.LastIndex(path, "/")+1:]
	}
	if _, after, found := strings.Cut(path, "/"); found {
		return after
	}
	return path
}

func purlVersion(s string) string {
	if !strings.HasPrefix(s, "pkg:") || !strings.Contains(s, "@") {
		return s
	}
	_, after, _ := strings.Cut(s, "@")
	if i := strings.IndexAny(after, "?#"); i >= 0 {
		after = after[:i]
	}
	return after
}

func (r sarifRule) pkg() string {
	name := r.purl()
	if name == "" {
		name = r.field("Package")
	}
	if name == "" {
		return "unknown"
	}
	return purlName(name)
}

func (r sarifRule) installed() string {
	installed, ok := r.prop("affected_version")
	if !ok {
		if purl := r.purl(); strings.Contains(purl, "@") {
			installed = purlVersion(purl)
		}
	}
	if installed != "" {
		return installed
	}
	if v := purlVersion(r.field("Affected version")); v != "" {
		return v
	}
	return "unknown"
}

var noFix = regexp.MustCompile(`(?i)^(|not fixed|none|n/a)$`)

func (r sarifRule) fixed() string {
	fixed, ok := r.prop("fixed_version")
	if !ok {
		fixed = r.field("Fixed version")
	}
	if noFix.MatchString(fixed) {
		return ""
	}
	return fixed
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

func rank(severity string) int {
	if r, ok := severityRank[severity]; ok {
		return r
	}
	return 4
}

// Findings returns one row per CVE of the report (the rules, plus the rule ids only seen in results), the most severe first
// then by id. It returns no row for a report that is empty or not SARIF.
func Findings(data []byte) []Finding {
	doc, ok := parse(data)
	if !ok {
		return nil
	}

	var rows []Finding
	for _, run := range doc.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			rows = append(rows, Finding{ID: rule.ID, Severity: rule.severity(), Package: rule.pkg(), Installed: rule.installed(), Fixed: rule.fixed()})
		}
	}
	for _, id := range resultIDs(doc) {
		rows = append(rows, Finding{ID: id, Severity: "unknown", Package: "unknown", Installed: "unknown"})
	}

	rows = firstPerID(rows)
	slices.SortStableFunc(rows, func(a, b Finding) int {
		if c := rank(a.Severity) - rank(b.Severity); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return rows
}

func resultIDs(doc sarifDoc) []string {
	var ids []string
	for _, run := range doc.Runs {
		for _, result := range run.Results {
			ids = append(ids, result.RuleID)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// firstPerID keeps the first row of every id, sorted by id like jq's group_by.
func firstPerID(rows []Finding) []Finding {
	slices.SortStableFunc(rows, func(a, b Finding) int { return strings.Compare(a.ID, b.ID) })
	return slices.CompactFunc(rows, func(a, b Finding) bool { return a.ID == b.ID })
}

// TrackedFinding is a CVE of the weekly scan, which only tracks critical and high.
type TrackedFinding struct {
	ID       string
	Severity string // critical or high
}

// TrackedFindings reads the CVEs the weekly scan tracks: the severity comes from cvssV3_severity, else the numeric
// security-severity (>= 9.0 is critical), else high, since the scan is already limited to critical,high. Rules missing from
// the driver fall back to the ruleId of the results.
func TrackedFindings(data []byte) []TrackedFinding {
	doc, ok := parse(data)
	if !ok {
		return nil
	}

	var rows []TrackedFinding
	for _, run := range doc.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			level, _ := rule.prop("cvssV3_severity")
			level = strings.ToLower(level)
			score, hasScore := rule.score("security-severity")
			severity := "high"
			if level == "critical" || (level == "" && hasScore && score >= 9) {
				severity = "critical"
			}
			rows = append(rows, TrackedFinding{ID: rule.ID, Severity: severity})
		}
	}
	for _, id := range resultIDs(doc) {
		rows = append(rows, TrackedFinding{ID: id, Severity: "high"})
	}

	slices.SortStableFunc(rows, func(a, b TrackedFinding) int { return strings.Compare(a.ID, b.ID) })
	return slices.CompactFunc(rows, func(a, b TrackedFinding) bool { return a.ID == b.ID })
}
