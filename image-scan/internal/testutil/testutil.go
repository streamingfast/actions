// Package testutil holds the fakes and helpers shared by the tests: the fixtures, a fake scanner binary, a fake GitHub API
// and a fake registry.
package testutil

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/streamingfast/actions/image-scan/internal/github"
	"github.com/streamingfast/actions/image-scan/internal/scanner"
)

// Fixture is the path of a file of the testdata directory, the fixtures of the tests.
func Fixture(parts ...string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(append([]string{filepath.Dir(file), "..", "..", "testdata"}, parts...)...)
}

// ReadFixture reads a file of the testdata directory.
func ReadFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(Fixture(parts...))
	require.NoError(t, err)
	return data
}

// Digest is a sha256 digest made of one repeated hex digit.
func Digest(c string) string { return "sha256:" + strings.Repeat(c, 64) }

// Outputs parses the file $GITHUB_OUTPUT points to (name=value lines and name<<DELIMITER heredocs), the last value wins.
func Outputs(t *testing.T, path string) map[string]string {
	t.Helper()
	outputs := map[string]string{}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return outputs
	}
	require.NoError(t, err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if name, delimiter, ok := strings.Cut(line, "<<"); ok && !strings.Contains(name, "=") {
			var values []string
			for scanner.Scan() && scanner.Text() != delimiter {
				values = append(values, scanner.Text())
			}
			outputs[name] = strings.Join(values, "\n")
			continue
		}
		if name, value, ok := strings.Cut(line, "="); ok {
			outputs[name] = value
		}
	}
	return outputs
}

// ----------------------------------------------------------------------------------------------------------------- scanner

// FakeImage is what the fake scanner answers for an image.
type FakeImage struct {
	// RC is the exit code (default 0) and VexRC the one when the scan has --vex-location (RC when nil): the documents suppress CVEs
	RC, VexRC *int
	// SARIF and VexSARIF are printed on findings in the sarif format (VexSARIF when the scan has --vex-location, else SARIF)
	SARIF, VexSARIF string
	// Markdown and VexMarkdown are printed on findings in the markdown format (a one line title by default)
	Markdown, VexMarkdown string
	// CleanMarkdown is printed on a clean scan instead of "no findings"
	CleanMarkdown string
	// BadSARIF makes the sarif scan without --vex-location fail with this exit code (an infrastructure failure)
	BadSARIF int
}

// Code returns a pointer to an exit code, for FakeImage.
func Code(c int) *int { return &c }

// FakeScout is a fake docker-scout: Exec answers the scans by image. Failures is the number of initial runs that fail with exit
// code 1 (an infrastructure failure).
type FakeScout struct {
	mu       sync.Mutex
	Images   map[string]*FakeImage
	Failures int
	Calls    []scanner.Command
}

func NewFakeScout() *FakeScout { return &FakeScout{Images: map[string]*FakeImage{}} }

// Image returns what the fake answers for an image, created on first use.
func (f *FakeScout) Image(image string) *FakeImage {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Images[image] == nil {
		f.Images[image] = &FakeImage{}
	}
	return f.Images[image]
}

// Lines returns one line per call, the arguments of the scanner.
func (f *FakeScout) Lines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	lines := make([]string, len(f.Calls))
	for i, c := range f.Calls {
		lines[i] = strings.Join(c.Args, " ")
	}
	return lines
}

// Count returns the number of calls whose arguments contain the text.
func (f *FakeScout) Count(contains string) int {
	n := 0
	for _, l := range f.Lines() {
		if strings.Contains(l, contains) {
			n++
		}
	}
	return n
}

func (f *FakeScout) Exec(_ context.Context, c scanner.Command) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, c)
	if f.Failures > 0 {
		f.Failures--
		return 1, nil
	}

	args := c.Args
	image := args[len(args)-1]
	format, vex := "", false
	for i, a := range args {
		switch a {
		case "--format":
			format = args[i+1]
		case "--vex-location":
			vex = true
		case "--output":
			return 64, fmt.Errorf("fake scanner: --output must not be used")
		}
	}

	fake := f.Images[image]
	if fake == nil {
		fake = &FakeImage{}
	}
	rc := 0
	switch {
	case vex && fake.VexRC != nil:
		rc = *fake.VexRC
	case fake.RC != nil:
		rc = *fake.RC
	}
	if !vex && format == "sarif" && fake.BadSARIF != 0 {
		rc = fake.BadSARIF
	}

	switch rc {
	case 2:
		pick := func(plain, withVex string) string {
			if vex && withVex != "" {
				return withVex
			}
			return plain
		}
		if format == "sarif" {
			_, _ = c.Stdout.Write([]byte(pick(fake.SARIF, fake.VexSARIF)))
		} else if md := pick(fake.Markdown, fake.VexMarkdown); md != "" {
			_, _ = c.Stdout.Write([]byte(md))
		} else {
			_, _ = fmt.Fprintf(c.Stdout, "# findings in %s\n", image)
		}
	case 0:
		if fake.CleanMarkdown != "" {
			_, _ = c.Stdout.Write([]byte(fake.CleanMarkdown))
		} else {
			_, _ = c.Stdout.Write([]byte("no findings\n"))
		}
	}
	_, _ = c.Stderr.Write([]byte("pulling progress on stderr\n"))
	return rc, nil
}

// ---------------------------------------------------------------------------------------------------------------- GitHub

// FakeGitHub is an in-memory github.API recording what is done to it.
type FakeGitHub struct {
	Comments []github.Comment
	Issues   []github.Issue
	Tag      string // latest release, v1.2.3 by default
	Date     string // publication date of the release, 2026-01-02 by default
	// Fail makes a call fail: "issue create", "issue list", "issue close", ...
	Fail map[string]bool
	// Log has one line per mutating call
	Log []string
}

func NewFakeGitHub() *FakeGitHub { return &FakeGitHub{Fail: map[string]bool{}} }

func (g *FakeGitHub) call(op, line string) error {
	g.Log = append(g.Log, op+" "+line)
	if g.Fail[op] {
		return fmt.Errorf("fake github: %s failed", op)
	}
	return nil
}

// Logged returns the lines of the log of an operation (like "issue edit").
func (g *FakeGitHub) Logged(op string) []string {
	var lines []string
	for _, l := range g.Log {
		if rest, ok := strings.CutPrefix(l, op+" "); ok {
			lines = append(lines, rest)
		}
	}
	return lines
}

// Contains tells whether a line of the log contains the text.
func (g *FakeGitHub) Contains(text string) bool {
	return slices.ContainsFunc(g.Log, func(l string) bool { return strings.Contains(l, text) })
}

func (g *FakeGitHub) ListComments(_ context.Context, _ string, _ int) ([]github.Comment, error) {
	return g.Comments, g.call("comments list", "")
}

func (g *FakeGitHub) CreateComment(_ context.Context, repo string, n int, body string) error {
	return g.call("comment create", fmt.Sprintf("%s#%d %s", repo, n, body))
}

func (g *FakeGitHub) UpdateComment(_ context.Context, repo string, id int64, body string) error {
	return g.call("comment update", fmt.Sprintf("%s/%d %s", repo, id, body))
}

func (g *FakeGitHub) ListIssues(_ context.Context, _, label, state string, _ int) ([]github.Issue, error) {
	if err := g.call("issue list", fmt.Sprintf("--label %s --state %s", label, state)); err != nil {
		return nil, err
	}
	var issues []github.Issue
	for _, i := range g.Issues {
		if state == "all" || strings.EqualFold(state, i.State) {
			issues = append(issues, i)
		}
	}
	return issues, nil
}

func (g *FakeGitHub) CreateIssue(_ context.Context, _, title, body string, labels []string) (string, error) {
	err := g.call("issue create", fmt.Sprintf("--title %s --label %s --body %s", title, strings.Join(labels, " --label "), body))
	return "https://github.com/o/r/issues/99", err
}

func (g *FakeGitHub) EditIssue(_ context.Context, _ string, n int, title, body string) error {
	return g.call("issue edit", fmt.Sprintf("%d --title %s --body %s", n, title, body))
}

func (g *FakeGitHub) AddLabel(_ context.Context, _ string, n int, label string) error {
	return g.call("issue label add", fmt.Sprintf("%d %s", n, label))
}

func (g *FakeGitHub) RemoveLabel(_ context.Context, _ string, n int, label string) error {
	return g.call("issue label remove", fmt.Sprintf("%d %s", n, label))
}

func (g *FakeGitHub) CloseIssue(_ context.Context, _ string, n int, comment string) error {
	return g.call("issue close", fmt.Sprintf("%d %s", n, comment))
}

func (g *FakeGitHub) CommentIssue(_ context.Context, _ string, n int, body string) error {
	return g.call("issue comment", fmt.Sprintf("%d %s", n, body))
}

func (g *FakeGitHub) CreateLabel(_ context.Context, _, name, _ string) error {
	return g.call("label create", name)
}

func (g *FakeGitHub) LatestReleaseTag(context.Context, string) (string, error) {
	if g.Tag == "" {
		return "v1.2.3", g.call("release latest", "")
	}
	return g.Tag, g.call("release latest", "")
}

func (g *FakeGitHub) ReleasePublishedAt(context.Context, string, string) (string, error) {
	if g.Date == "" {
		return "2026-01-02", g.call("release view", "")
	}
	return g.Date, g.call("release view", "")
}

// -------------------------------------------------------------------------------------------------------------- registry

// FakeRegistry is a registry.Registry: Digests are returned by successive Digest calls (the last one repeats, digest a... by
// default), DigestFailures and CopyFailures count the calls still failing.
type FakeRegistry struct {
	Digests        []string
	DigestFailures int
	CopyFailures   int
	DigestCalls    []string
	Copies         [][2]string // source, destination
	CopyCalls      int
}

func (r *FakeRegistry) Digest(_ context.Context, ref string) (string, error) {
	r.DigestCalls = append(r.DigestCalls, ref)
	if r.DigestFailures > 0 {
		r.DigestFailures--
		return "", fmt.Errorf("fake registry: cannot inspect %s", ref)
	}
	if len(r.Digests) == 0 {
		return Digest("a"), nil
	}
	d := r.Digests[0]
	if len(r.Digests) > 1 {
		r.Digests = r.Digests[1:]
	}
	return d, nil
}

func (r *FakeRegistry) Copy(_ context.Context, source, destination string) error {
	r.CopyCalls++
	if r.CopyFailures > 0 {
		r.CopyFailures--
		return fmt.Errorf("fake registry: cannot copy to %s", destination)
	}
	r.Copies = append(r.Copies, [2]string{source, destination})
	return nil
}

// Buffer is a log buffer.
type Buffer = bytes.Buffer
