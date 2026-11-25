// Package vex reads OpenVEX documents and decides which CVEs of an image they suppress.
//
// Only a statement with status not_affected suppresses a CVE (Scout ignores the other statuses). A statement is scoped to an
// image through its products, compared the way Scout names images: pkg:oci/<repo>?repository_url=<registry> (with or without
// a @sha256: digest and tag qualifier), pkg:docker/[<registry>/]<repo>, or a plain [<registry>/]<repo>[:tag][@digest]. A
// product without registry matches any registry, one without digest any digest, tags never count.
package vex

import (
	"cmp"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/streamingfast/actions/image-scan/internal/scout"
)

const NotAffected = "not_affected"

// Statement is one statement of an OpenVEX document.
type Statement struct {
	ID            string // the vulnerability, a CVE id
	Status        string
	Justification string
	Impact        string // impact_statement, else status_notes
	Timestamp     string // the one of the statement, else the one of the document
	Author        string // the one of the statement, else the one of the document
	File          string // the document, as found under the location
	Products      []string
}

type document struct {
	Author     string `json:"author"`
	Timestamp  string `json:"timestamp"`
	Statements []struct {
		// a plain string before OpenVEX 0.2.0, an object ({name}) since
		Vulnerability json.RawMessage   `json:"vulnerability"`
		Status        string            `json:"status"`
		Justification string            `json:"justification"`
		Impact        *string           `json:"impact_statement"`
		StatusNotes   string            `json:"status_notes"`
		Timestamp     *string           `json:"timestamp"`
		Author        *string           `json:"author"`
		Products      []json.RawMessage `json:"products"`
	} `json:"statements"`
}

// Files lists the OpenVEX documents (*.json, *.jsonld) of a location: the file itself, or the files below a directory in
// path order. A missing location lists nothing.
func Files(location string) []string {
	info, err := os.Stat(location)
	if err != nil {
		return nil
	}
	if !info.IsDir() {
		return []string{location}
	}
	var files []string
	_ = filepath.WalkDir(location, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		if ext := filepath.Ext(path); ext == ".json" || ext == ".jsonld" {
			files = append(files, path)
		}
		return nil
	})
	slices.Sort(files)
	return files
}

// Statements reads the statements of the documents of a location. A document that cannot be read gives none.
func Statements(location string) []Statement {
	var all []Statement
	for _, file := range Files(location) {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		all = append(all, parseDocument(data, file)...)
	}
	return all
}

func parseDocument(data []byte, file string) []Statement {
	var doc document
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var statements []Statement
	for _, s := range doc.Statements {
		statement := Statement{
			ID:            vulnerabilityID(s.Vulnerability),
			Status:        s.Status,
			Justification: s.Justification,
			Timestamp:     doc.Timestamp,
			Author:        doc.Author,
			File:          file,
		}
		switch {
		case s.Impact != nil:
			statement.Impact = *s.Impact
		default:
			statement.Impact = s.StatusNotes
		}
		if s.Timestamp != nil {
			statement.Timestamp = *s.Timestamp
		}
		if s.Author != nil {
			statement.Author = *s.Author
		}
		for _, product := range s.Products {
			if id := productID(product); id != "" {
				statement.Products = append(statement.Products, id)
			}
		}
		statements = append(statements, statement)
	}
	return statements
}

func vulnerabilityID(raw json.RawMessage) string {
	var name string
	if json.Unmarshal(raw, &name) == nil {
		return name
	}
	var object struct {
		Name string `json:"name"`
		ID   string `json:"@id"`
	}
	if json.Unmarshal(raw, &object) == nil {
		return cmp.Or(object.Name, object.ID)
	}
	return ""
}

func productID(raw json.RawMessage) string {
	var name string
	if json.Unmarshal(raw, &name) == nil {
		return name
	}
	var object struct {
		ID          string `json:"@id"`
		Identifiers struct {
			Purl string `json:"purl"`
		} `json:"identifiers"`
	}
	if json.Unmarshal(raw, &object) == nil {
		return cmp.Or(object.ID, object.Identifiers.Purl)
	}
	return ""
}

// StatementOfSuppressed is a statement as shown for a suppressed CVE.
type StatementOfSuppressed struct {
	Justification string
	Impact        string
	Timestamp     string
	Author        string
	File          string // base name of the document
	Scoped        bool   // its products match the scanned image
}

// Suppressed is a CVE reported without the VEX documents and no longer with them. Status is "not_affected" when a statement
// explains it, empty otherwise (it is suppressed, but not by a statement of the location).
type Suppressed struct {
	scout.Finding
	Status     string
	Statements []StatementOfSuppressed
	Image      string // the weekly scan sets the image the CVE was found in
}

// SuppressedFindings returns the CVEs of all that are missing from active, each with the not_affected statements that explain
// it. With an image these are the statements whose products match it (all of them, several documents may speak about the
// CVE); when none does, the most recent statement of the CVE id, marked not scoped to the image. Without image, the most
// recent statement of the CVE id.
func SuppressedFindings(all, active []scout.Finding, statements []Statement, image string) []Suppressed {
	activeIDs := map[string]bool{}
	for _, f := range active {
		activeIDs[f.ID] = true
	}
	var img *ImageRef
	if image != "" {
		ref := ParseImage(image)
		img = &ref
	}

	suppressed := []Suppressed{}
	for _, f := range all {
		if activeIDs[f.ID] {
			continue
		}
		var byID []Statement
		for _, s := range statements {
			if s.ID == f.ID && s.Status == NotAffected {
				byID = append(byID, s)
			}
		}

		var chosen []StatementOfSuppressed
		if img != nil {
			scoped := slices.DeleteFunc(slices.Clone(byID), func(s Statement) bool {
				return !slices.ContainsFunc(s.Products, func(p string) bool { return ProductMatches(p, *img) })
			})
			slices.SortStableFunc(scoped, func(a, b Statement) int {
				return cmp.Or(strings.Compare(a.File, b.File), strings.Compare(a.Timestamp, b.Timestamp))
			})
			for _, s := range scoped {
				chosen = append(chosen, shown(s, true))
			}
		}
		if len(chosen) == 0 && len(byID) > 0 {
			slices.SortStableFunc(byID, func(a, b Statement) int { return strings.Compare(a.Timestamp, b.Timestamp) })
			chosen = []StatementOfSuppressed{shown(byID[len(byID)-1], img == nil)}
		}

		row := Suppressed{Finding: f, Statements: chosen}
		if len(chosen) > 0 {
			row.Status = NotAffected
		}
		suppressed = append(suppressed, row)
	}
	return suppressed
}

func shown(s Statement, scoped bool) StatementOfSuppressed {
	return StatementOfSuppressed{
		Justification: s.Justification,
		Impact:        s.Impact,
		Timestamp:     s.Timestamp,
		Author:        s.Author,
		File:          filepath.Base(s.File),
		Scoped:        scoped,
	}
}

// Stale returns the not_affected statements matching no finding of the image, the fix may have shipped.
func Stale(all []scout.Finding, statements []Statement) []Statement {
	ids := map[string]bool{}
	for _, f := range all {
		ids[f.ID] = true
	}
	return slices.DeleteFunc(slices.Clone(statements), func(s Statement) bool {
		return s.Status != NotAffected || s.ID == "" || ids[s.ID]
	})
}

// Ineffective returns the statements Scout ignores: only not_affected suppresses a CVE.
func Ineffective(statements []Statement) []Statement {
	return slices.DeleteFunc(slices.Clone(statements), func(s Statement) bool { return s.Status == NotAffected })
}
