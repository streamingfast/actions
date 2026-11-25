package gate

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// scope decides whether the scan runs.
//
// It always scans, except on a pull_request with scan-paths set: then it scans only when the files changed by the pull request
// match one of the scan-paths lines (one extended regular expression per line, anchor with ^). The caller must check out with
// fetch-depth: 2 so HEAD^1 exists.
func (g *Gate) scope(ctx context.Context) (bool, error) {
	if g.Config.EventName != "pull_request" || strings.TrimSpace(g.Config.ScanPaths) == "" {
		return true, nil
	}

	var patterns []*regexp.Regexp
	for line := range strings.SplitSeq(g.Config.ScanPaths, "\n") {
		// Blank lines would match every file
		if strings.TrimSpace(line) == "" {
			continue
		}
		re, err := regexp.Compile(strings.TrimRight(line, "\r"))
		if err != nil {
			// an invalid expression must fail closed, not read as "no match"
			return false, errors.New("scan-paths holds an invalid regular expression")
		}
		patterns = append(patterns, re)
	}

	diff := g.ChangedFiles
	if diff == nil {
		diff = GitChangedFiles(".")
	}
	changed, err := diff(ctx)
	if err != nil {
		return false, fmt.Errorf("Cannot diff HEAD^1 HEAD, check that the checkout uses fetch-depth: 2")
	}

	for _, file := range changed {
		for _, re := range patterns {
			if re.MatchString(file) {
				g.Log.Println("Image-affecting files changed, scanning")
				return true, nil
			}
		}
	}
	g.Log.Println("No image-affecting file changed, skipping scan")
	return false, nil
}
