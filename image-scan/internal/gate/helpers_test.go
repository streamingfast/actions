package gate_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/streamingfast/actions/image-scan/internal/gate"
	"github.com/streamingfast/actions/image-scan/internal/gha"
	"github.com/streamingfast/actions/image-scan/internal/retry"
	"github.com/streamingfast/actions/image-scan/internal/scanner"
	"github.com/streamingfast/actions/image-scan/internal/testutil"
)

const (
	img = "ghcr.io/o/r:abc-amd64"
	// the key of the fake scanner is the image itself
)

// harness is a gate wired to the fakes: scanner, GitHub, registry, and the files of the runner.
type harness struct {
	t       *testing.T
	g       *gate.Gate
	scout   *testutil.FakeScout
	gh      *testutil.FakeGitHub
	reg     *testutil.FakeRegistry
	log     *bytes.Buffer
	outputs string
	summary string
	sc      *scanner.Scanner
}

type option func(*harness, *gate.Config, *scanner.Config, *retry.Policy)

func retries(n int) option {
	return func(_ *harness, _ *gate.Config, _ *scanner.Config, p *retry.Policy) { p.Attempts = n }
}

func config(modify func(*gate.Config)) option {
	return func(_ *harness, c *gate.Config, _ *scanner.Config, _ *retry.Policy) { modify(c) }
}

func scannerConfig(modify func(*scanner.Config)) option {
	return func(_ *harness, _ *gate.Config, c *scanner.Config, _ *retry.Policy) { modify(c) }
}

func newHarness(t *testing.T, options ...option) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{
		t:       t,
		scout:   testutil.NewFakeScout(),
		gh:      testutil.NewFakeGitHub(),
		reg:     &testutil.FakeRegistry{},
		log:     &bytes.Buffer{},
		outputs: filepath.Join(dir, "output"),
		summary: filepath.Join(dir, "summary"),
	}
	policy := retry.Policy{Attempts: 3, Sleep: func(time.Duration) {}}
	cfg := gate.Config{Repo: "o/r", Image: img, Severities: "critical,high", EventName: "push"}
	scfg := scanner.Config{DockerHubUser: "u", DockerHubPassword: "p"}
	for _, o := range options {
		o(h, &cfg, &scfg, &policy)
	}
	scfg.Retry = policy
	scfg.Severities = cfg.Severities

	log := gha.NewLogger(h.log)
	sc, err := scanner.New(scfg, log, h.scout.Exec, &bytes.Buffer{})
	require.NoError(t, err)
	t.Cleanup(sc.Close)
	h.sc = sc

	h.g = &gate.Gate{
		Config:   cfg,
		Log:      log,
		Files:    gha.Files{Output: h.outputs, Summary: h.summary},
		Scanner:  sc,
		GitHub:   h.gh,
		Registry: h.reg,
		Retry:    policy,
		Now:      func() time.Time { return time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC) },
	}
	return h
}

func (h *harness) logLines() []string { return strings.Split(h.log.String(), "\n") }

// logHas tells whether a line of the log is exactly the text.
func (h *harness) logHas(line string) bool {
	for _, l := range h.logLines() {
		if l == line {
			return true
		}
	}
	return false
}

func (h *harness) readSummary() string {
	data, err := os.ReadFile(h.summary)
	if os.IsNotExist(err) {
		return ""
	}
	require.NoError(h.t, err)
	return string(data)
}

func (h *harness) out() map[string]string { return testutil.Outputs(h.t, h.outputs) }

// fakeImage is the fake scanner entry of the image under test.
func (h *harness) fakeImage() *testutil.FakeImage { return h.scout.Image(img) }

func findingsOf(h *harness, sarif string) {
	h.fakeImage().RC = testutil.Code(2)
	h.fakeImage().SARIF = sarif
}
