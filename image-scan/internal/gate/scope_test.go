package gate_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/streamingfast/actions/image-scan/internal/gate"
)

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir, "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

// repository has a base commit and a commit changing README.md, like the merge commit of a pull request.
func repository(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	git(t, dir, "commit", "-q", "--allow-empty", "-m", "base")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("x"), 0o644))
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "change")
	return dir
}

func scope(t *testing.T, dir, event, paths string) (exit int, scanned string) {
	t.Helper()
	h := newHarness(t, config(func(c *gate.Config) { c.EventName, c.ScanPaths = event, paths }))
	h.g.ChangedFiles = gate.GitChangedFiles(dir)
	exit = h.g.Run(t.Context())
	return exit, h.out()["scanned"]
}

func TestScope(t *testing.T) {
	dir := repository(t)

	tests := []struct {
		name, event, paths string
		exit               int
		scanned            string
	}{
		{"empty scan-paths scans", "pull_request", "", 0, "true"},
		{"push always scans", "push", "^Dockerfile", 0, "true"},
		{"pull_request without a matching file skips", "pull_request", "^Dockerfile\n\n^go\\.mod", 0, "false"},
		{"pull_request with a matching file scans", "pull_request", "^Dockerfile\n^README", 0, "true"},
		{"blank lines never match every file", "pull_request", "  \n^Dockerfile", 0, "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exit, scanned := scope(t, dir, tt.event, tt.paths)
			assert.Equal(t, tt.exit, exit)
			assert.Equal(t, tt.scanned, scanned)
		})
	}

	t.Run("a missing HEAD^1 fails", func(t *testing.T) {
		shallow := t.TempDir()
		git(t, shallow, "init", "-q", "-b", "main")
		git(t, shallow, "commit", "-q", "--allow-empty", "-m", "only")
		exit, scanned := scope(t, shallow, "pull_request", "^x")
		assert.Equal(t, 1, exit)
		assert.NotEqual(t, "true", scanned, "no scan")
	})

	t.Run("an invalid regular expression fails closed", func(t *testing.T) {
		exit, scanned := scope(t, dir, "pull_request", "^(")
		assert.Equal(t, 1, exit)
		assert.Empty(t, scanned)
	})
}

func TestScopeMessages(t *testing.T) {
	dir := repository(t)
	h := newHarness(t, config(func(c *gate.Config) { c.EventName, c.ScanPaths = "pull_request", "^Dockerfile" }))
	h.g.ChangedFiles = gate.GitChangedFiles(dir)
	require.Equal(t, 0, h.g.Run(t.Context()))
	assert.True(t, h.logHas("No image-affecting file changed, skipping scan"))
	assert.Empty(t, h.scout.Calls, "the image build is the caller's, the scan does not run")

	h = newHarness(t, config(func(c *gate.Config) { c.EventName, c.ScanPaths = "pull_request", "^(" }))
	h.g.ChangedFiles = gate.GitChangedFiles(dir)
	require.Equal(t, 1, h.g.Run(t.Context()))
	assert.True(t, h.logHas("::error::scan-paths holds an invalid regular expression"))
}
