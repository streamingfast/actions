package gha_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/streamingfast/actions/image-scan/internal/gha"
	"github.com/streamingfast/actions/image-scan/internal/testutil"
)

func TestOutputs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output")
	files := gha.Files{Output: path}
	require.NoError(t, files.SetOutput("scanned", "true"))
	require.NoError(t, files.SetOutput("promoted", "a\nb"))
	require.NoError(t, files.SetOutput("empty", ""))
	assert.Equal(t, map[string]string{"scanned": "true", "promoted": "a\nb", "empty": ""}, testutil.Outputs(t, path))

	assert.Error(t, gha.Files{}.SetOutput("x", "y"), "GITHUB_OUTPUT is required")
}

func TestSummaryAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary")
	files := gha.Files{Summary: path}
	require.NoError(t, files.AppendSummary("a\n"))
	require.NoError(t, files.AppendSummary("b\n"))
	data, _ := os.ReadFile(path)
	assert.Equal(t, "a\nb\n", string(data))
}

func TestWorkflowCommands(t *testing.T) {
	var b bytes.Buffer
	log := gha.NewLogger(&b)
	log.Errorf("e %d", 1)
	log.Warningf("w")
	log.Noticef("n")
	log.Debugf("d")
	log.Group("g")
	log.EndGroup()
	assert.Equal(t, "::error::e 1\n::warning::w\n::notice::n\n::debug::d\n::group::g\n::endgroup::\n", b.String())
}

func TestOneLine(t *testing.T) {
	assert.Equal(t, "a b%0D 100%25", gha.OneLine("a\nb\r 100%"))
}
