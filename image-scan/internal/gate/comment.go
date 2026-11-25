package gate

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// maxCommentBytes keeps the comment below the 65536 characters GitHub accepts.
const maxCommentBytes = 60000

// publish writes the scan report to the job summary and, on a pull_request, to a comment created or updated in place.
// A clean scan is quiet: no comment is created, and the existing one (an earlier failing run) is updated.
func (g *Gate) publish(ctx context.Context, image string, result ScanResult) error {
	// No report when the scanner could not run (infra failure)
	if !result.Ran() || result.Report == "" {
		return nil
	}
	if err := g.Files.AppendSummary(fmt.Sprintf("## Image scan (%s)\n\n%s", image, result.Report)); err != nil {
		return err
	}
	if g.Config.EventName != "pull_request" {
		return nil
	}

	number, err := strconv.Atoi(g.Config.PRNumber)
	if err != nil {
		return fmt.Errorf("the pull request number is missing")
	}
	// The image is in the marker so a matrix (one image per architecture) does not overwrite itself
	marker := fmt.Sprintf("<!-- image-scan:%s -->", htmlSafe(image))

	comments, err := g.GitHub.ListComments(ctx, g.Config.Repo, number)
	if err != nil {
		return err
	}
	var existing int64
	for _, c := range comments {
		if strings.HasPrefix(c.Body, marker) {
			existing = c.ID
			break
		}
	}

	// Nothing to tell on a clean scan, unless an earlier run of the pull request reported a problem that is now gone
	if !result.Findings && existing == 0 {
		return nil
	}

	content := result.Comment
	if len(content) > maxCommentBytes {
		content = content[:maxCommentBytes]
	}
	// a multibyte character cut in half is dropped
	content = strings.ToValidUTF8(content, "")
	body := fmt.Sprintf("%s\n## Image scan (%s)\n\n%s", marker, image, content)
	body = strings.TrimRight(body, "\n")
	// A cut report must not leave its collapsed block open
	if strings.Count(body, "<details>") > strings.Count(body, "</details>") {
		body += "\n\n</details>"
	}

	if existing != 0 {
		return g.GitHub.UpdateComment(ctx, g.Config.Repo, existing, body)
	}
	return g.GitHub.CreateComment(ctx, g.Config.Repo, number, body)
}
