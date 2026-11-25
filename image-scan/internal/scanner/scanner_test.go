package scanner_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/streamingfast/actions/image-scan/internal/gha"
	"github.com/streamingfast/actions/image-scan/internal/retry"
	"github.com/streamingfast/actions/image-scan/internal/scanner"
	"github.com/streamingfast/actions/image-scan/internal/testutil"
)

type harness struct {
	scout *testutil.FakeScout
	sc    *scanner.Scanner
	log   *bytes.Buffer
}

func newHarness(t *testing.T, modify ...func(*scanner.Config)) *harness {
	t.Helper()
	cfg := scanner.Config{
		DockerHubUser:     "u",
		DockerHubPassword: "p",
		Retry:             retry.Policy{Attempts: 3, Sleep: func(time.Duration) {}},
	}
	for _, m := range modify {
		m(&cfg)
	}
	h := &harness{scout: testutil.NewFakeScout(), log: &bytes.Buffer{}}
	sc, err := scanner.New(cfg, gha.NewLogger(h.log), h.scout.Exec, &bytes.Buffer{})
	require.NoError(t, err)
	t.Cleanup(sc.Close)
	h.sc = sc
	return h
}

func (h *harness) scan(t *testing.T, req scanner.Request) scanner.Result {
	t.Helper()
	result, err := h.sc.Scan(t.Context(), req)
	require.NoError(t, err)
	return result
}

func TestCleanImage(t *testing.T) {
	h := newHarness(t)
	result := h.scan(t, scanner.Request{Image: "img:1"})

	assert.Equal(t, scanner.ExitClean, result.Code, "clean image exits 0")
	assert.Contains(t, h.scout.Lines()[0], "--only-severity critical,high", "passes severities")
	assert.NotContains(t, h.scout.Lines()[0], "--output", "no --output")
	assert.Equal(t, "no findings\n", string(result.Report), "stdout is the report, stderr stays out of it")

	env := strings.Join(h.scout.Calls[0].Env, "\n")
	assert.Contains(t, env, "DOCKER_SCOUT_HUB_USER=u", "passes the hub auth env by name")
	assert.Contains(t, env, "DOCKER_SCOUT_HUB_PASSWORD=p")
	assert.NotContains(t, strings.Join(h.scout.Lines(), " "), "=p")
	assert.Contains(t, env, "DOCKER_CONFIG=/", "scans use a private docker config")
	assert.NotContains(t, env, "GITHUB", "the scanner sees nothing of the action")
}

func TestPrivateDockerConfigIsRemoved(t *testing.T) {
	h := newHarness(t)
	h.scan(t, scanner.Request{Image: "img:1"})
	var dir string
	for _, e := range h.scout.Calls[0].Env {
		if v, ok := strings.CutPrefix(e, "DOCKER_CONFIG="); ok {
			dir = v
		}
	}
	require.NotEmpty(t, dir)
	h.sc.Close()
	assert.NoDirExists(t, dir)
}

func TestRegistryCredentials(t *testing.T) {
	tests := []struct {
		name       string
		user, pass string
		passed     bool
	}{
		{"both are passed by name", "ru", "rp", true},
		{"empty values are not passed at all", "", "", false},
		{"a user without password is not passed", "ru", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, func(c *scanner.Config) { c.RegistryUser, c.RegistryPassword = tt.user, tt.pass })
			result := h.scan(t, scanner.Request{Image: "img:1"})
			assert.Equal(t, scanner.ExitClean, result.Code, "works without registry credentials")

			env := strings.Join(h.scout.Calls[0].Env, "\n")
			assert.Equal(t, tt.passed, strings.Contains(env, "DOCKER_SCOUT_REGISTRY_USER=ru"), "registry user reaches the env")
			assert.Equal(t, tt.passed, strings.Contains(env, "DOCKER_SCOUT_REGISTRY"))
			assert.NotContains(t, strings.Join(h.scout.Lines(), " "), "rp", "registry password is not on the command line")
		})
	}
}

func TestInvalidRetriesAreRejected(t *testing.T) {
	for _, bad := range []string{"0", "abc", "-1", ""} {
		_, err := retry.ParseAttempts(bad)
		assert.Error(t, err, "retries '%s' is rejected", bad)
	}
	_, err := scanner.New(scanner.Config{DockerHubUser: "u", DockerHubPassword: "p"}, gha.NewLogger(&bytes.Buffer{}), nil, nil)
	assert.Error(t, err, "no attempt is rejected")
}

func TestCredentialsRequired(t *testing.T) {
	log := gha.NewLogger(&bytes.Buffer{})
	retries := retry.Policy{Attempts: 1}
	_, err := scanner.New(scanner.Config{DockerHubPassword: "p", Retry: retries}, log, nil, nil)
	assert.ErrorContains(t, err, "dockerhub-user required")
	_, err = scanner.New(scanner.Config{DockerHubUser: "u", Retry: retries}, log, nil, nil)
	assert.ErrorContains(t, err, "dockerhub-password required")
}

func TestFindingsAreNeverRetried(t *testing.T) {
	h := newHarness(t)
	h.scout.Image("img:1").RC = testutil.Code(2)
	result := h.scan(t, scanner.Request{Image: "img:1"})

	assert.Equal(t, scanner.ExitFindings, result.Code, "findings exit 2")
	assert.Len(t, h.scout.Calls, 1, "findings are not retried")
	assert.NotEmpty(t, result.Report, "findings report written")
}

func TestInfrastructureFailures(t *testing.T) {
	t.Run("then success exits 0", func(t *testing.T) {
		h := newHarness(t)
		h.scout.Failures = 2
		assert.Equal(t, scanner.ExitClean, h.scan(t, scanner.Request{Image: "img:1"}).Code)
		assert.Len(t, h.scout.Calls, 3, "retried")
	})

	t.Run("after the retries exits 10", func(t *testing.T) {
		h := newHarness(t, func(c *scanner.Config) { c.Retry.Attempts = 2 })
		h.scout.Failures = 9
		assert.Equal(t, scanner.ExitInfra, h.scan(t, scanner.Request{Image: "img:1"}).Code)
		assert.Len(t, h.scout.Calls, 2, "stops after the retries")
		assert.Contains(t, h.log.String(), "::error::The image scan could not run on img:1 after 2 attempts")
	})

	t.Run("an unknown exit code is an infrastructure failure", func(t *testing.T) {
		h := newHarness(t, func(c *scanner.Config) { c.Retry.Attempts = 2 })
		h.scout.Image("img:1").RC = testutil.Code(1)
		assert.Equal(t, scanner.ExitInfra, h.scan(t, scanner.Request{Image: "img:1"}).Code)
	})

	t.Run("the backoff grows with the attempt", func(t *testing.T) {
		var slept []time.Duration
		h := newHarness(t, func(c *scanner.Config) {
			c.Retry = retry.Policy{Attempts: 3, Backoff: 15 * time.Second, Sleep: func(d time.Duration) { slept = append(slept, d) }}
		})
		h.scout.Failures = 9
		h.scan(t, scanner.Request{Image: "img:1"})
		assert.Equal(t, []time.Duration{15 * time.Second, 30 * time.Second}, slept)
	})
}

func TestVexDocuments(t *testing.T) {
	fx := testutil.Fixture()

	t.Run("a directory", func(t *testing.T) {
		h := newHarness(t)
		result := h.scan(t, scanner.Request{Image: "img:1", VexLocation: testutil.Fixture("vex")})
		assert.Equal(t, scanner.ExitClean, result.Code)
		line := h.scout.Lines()[0]
		assert.Contains(t, line, "--vex-location "+testutil.Fixture("vex")+" ", "--vex-location points at the documents")
		assert.Contains(t, line, "--vex-author .* ", "authors default to any (Scout only accepts docker.com ones by default)")
		assert.Contains(t, line, "--only-severity critical,high --vex-location", "severities still passed")
	})

	t.Run("a file with an author", func(t *testing.T) {
		h := newHarness(t, func(c *scanner.Config) { c.VexAuthor = "<.*@streamingfast.io>" })
		h.scan(t, scanner.Request{Image: "img:1", VexLocation: testutil.Fixture("vex", "openvex.json")})
		line := h.scout.Lines()[0]
		assert.Contains(t, line, "--vex-location "+testutil.Fixture("vex", "openvex.json")+" ")
		assert.Contains(t, line, "--vex-author <.*@streamingfast.io> ", "vex-author is passed")
	})

	t.Run("a relative location is passed by its absolute path", func(t *testing.T) {
		t.Chdir(fx)
		h := newHarness(t)
		h.scan(t, scanner.Request{Image: "img:1", VexLocation: "vex"})
		assert.Contains(t, h.scout.Lines()[0], "--vex-location "+testutil.Fixture("vex")+" ")
	})

	t.Run("a missing location fails before any scan", func(t *testing.T) {
		h := newHarness(t)
		missing := t.TempDir() + "/nope"
		_, err := h.sc.Scan(t.Context(), scanner.Request{Image: "img:1", VexLocation: missing})
		var cfgErr *scanner.ConfigError
		require.ErrorAs(t, err, &cfgErr)
		assert.Equal(t, "vex-location '"+missing+"' does not exist", cfgErr.Message)
		assert.Empty(t, h.scout.Calls, "before any scan")
	})

	t.Run("a document that is not JSON fails before any scan", func(t *testing.T) {
		h := newHarness(t)
		_, err := h.sc.Scan(t.Context(), scanner.Request{Image: "img:1", VexLocation: testutil.Fixture("vex-invalid")})
		require.Error(t, err)
		assert.ErrorContains(t, err, "bad.json is not valid JSON")
		assert.Empty(t, h.scout.Calls)
	})

	t.Run("no documents, no vex flag", func(t *testing.T) {
		h := newHarness(t)
		h.scan(t, scanner.Request{Image: "img:1"})
		assert.NotContains(t, h.scout.Lines()[0], "vex")
	})
}

func TestFindingsLevel(t *testing.T) {
	tests := []struct {
		level, annotation string
	}{
		{"", "::error::critical,high vulnerabilities found in img:1"},
		{"warning", "::warning::critical,high vulnerabilities found in img:1"},
		{"notice", "::notice::critical,high vulnerabilities found in img:1"},
		{"debug", "::debug::critical,high vulnerabilities found in img:1"},
	}
	for _, tt := range tests {
		t.Run("level "+tt.level, func(t *testing.T) {
			h := newHarness(t)
			h.scout.Image("img:1").RC = testutil.Code(2)
			result := h.scan(t, scanner.Request{Image: "img:1", FindingsLevel: tt.level})
			assert.Equal(t, scanner.ExitFindings, result.Code, "a lower level keeps exit 2")
			assert.Contains(t, strings.Split(h.log.String(), "\n"), tt.annotation)
		})
	}

	h := newHarness(t)
	_, err := h.sc.Scan(t.Context(), scanner.Request{Image: "img:1", FindingsLevel: "loud"})
	assert.Error(t, err, "an unknown level is rejected")
}

func TestSeveritiesAreConfigurable(t *testing.T) {
	h := newHarness(t, func(c *scanner.Config) { c.Severities = "critical" })
	h.scan(t, scanner.Request{Image: "img:1", Format: scanner.SARIF})
	assert.Contains(t, h.scout.Lines()[0], "--only-severity critical --exit-code --format sarif img:1")
}
