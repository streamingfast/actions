// Package scanner is the only package that knows which scanner runs: the Docker Scout CLI (`docker-scout`) shipped in the
// image next to this program. Switching to Trivy/Grype means changing this package and internal/scout, not the action
// inputs.
//
// Exit codes of `docker-scout cves --exit-code`: 0 clean, 2 vulnerabilities, anything else an error. Findings are never
// retried, an infrastructure failure is, and ends as ExitInfra.
package scanner

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/streamingfast/actions/image-scan/internal/gha"
	"github.com/streamingfast/actions/image-scan/internal/retry"
	"github.com/streamingfast/actions/image-scan/internal/vex"
)

// Exit codes of a scan.
const (
	ExitClean    = 0
	ExitFindings = 2
	ExitInfra    = 10
)

// Format of the report.
const (
	Markdown = "markdown"
	SARIF    = "sarif"
)

// ConfigError is a misconfiguration: retrying cannot fix it, the action fails with exit code 1.
type ConfigError struct{ Message string }

func (e *ConfigError) Error() string { return e.Message }

// Command is one invocation of the scanner binary. Stdout is the report, stderr the progress and logs.
type Command struct {
	Args   []string
	Env    []string
	Stdout io.Writer
	Stderr io.Writer
}

// Exec runs the scanner and returns its exit code. An error means it could not run at all.
type Exec func(ctx context.Context, c Command) (int, error)

// BinaryExec runs the docker-scout binary found on the PATH.
func BinaryExec(ctx context.Context, c Command) (int, error) {
	cmd := exec.CommandContext(ctx, "docker-scout", c.Args...)
	cmd.Env = c.Env
	cmd.Stdout = c.Stdout
	cmd.Stderr = c.Stderr
	err := cmd.Run()
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return exitErr.ExitCode(), nil
	}
	return 0, err
}

// Config is what every scan of an action shares.
type Config struct {
	DockerHubUser     string
	DockerHubPassword string
	RegistryUser      string // optional, with RegistryPassword
	RegistryPassword  string
	Severities        string
	VexAuthor         string
	Retry             retry.Policy
}

// Scanner runs scans.
type Scanner struct {
	cfg  Config
	log  *gha.Logger
	exec Exec
	// stderr gets the scanner's own progress, the job log
	stderr io.Writer
	// docker config private to the scans, so no credential ends in ~/.docker/config.json of a non-ephemeral runner
	dockerConfig string
}

// New validates the credentials and the retries, and prepares a private docker config directory. Close removes it.
func New(cfg Config, log *gha.Logger, exec Exec, stderr io.Writer) (*Scanner, error) {
	if cfg.Retry.Attempts < 1 {
		return nil, &ConfigError{"retries must be a positive integer"}
	}
	if cfg.DockerHubUser == "" {
		return nil, &ConfigError{"dockerhub-user required"}
	}
	if cfg.DockerHubPassword == "" {
		return nil, &ConfigError{"dockerhub-password required"}
	}
	dir, err := os.MkdirTemp("", "image-scan-docker-config-")
	if err != nil {
		return nil, err
	}
	if cfg.Severities == "" {
		cfg.Severities = "critical,high"
	}
	if cfg.VexAuthor == "" {
		cfg.VexAuthor = ".*"
	}
	return &Scanner{cfg: cfg, log: log, exec: exec, stderr: stderr, dockerConfig: dir}, nil
}

func (s *Scanner) Close() { _ = os.RemoveAll(s.dockerConfig) }

// Request is one scan.
type Request struct {
	Image  string
	Format string // Markdown (default) or SARIF
	// VexLocation is the file or directory of OpenVEX documents handed to the scanner, empty applies none
	VexLocation string
	// FindingsLevel is the workflow command level of the message printed on findings: error (default), warning, notice or debug
	FindingsLevel string
}

// Result of a scan: Code is ExitClean, ExitFindings or ExitInfra, Report is what the scanner printed on stdout.
type Result struct {
	Code   int
	Report []byte
}

// ValidateVex fails right away on a misconfiguration (a missing path, a document that is not JSON): retrying cannot fix it
// and an exception silently not applied is worse. It returns the absolute location.
func ValidateVex(location string) (string, error) {
	if _, err := os.Stat(location); err != nil {
		return "", &ConfigError{fmt.Sprintf("vex-location '%s' does not exist", location)}
	}
	abs, err := filepath.Abs(location)
	if err != nil {
		return "", err
	}
	for _, document := range vex.Files(abs) {
		data, err := os.ReadFile(document)
		if err != nil {
			return "", &ConfigError{fmt.Sprintf("vex-location: cannot read %s: %v", document, err)}
		}
		if !json.Valid(data) {
			return "", &ConfigError{fmt.Sprintf("vex-location: %s is not valid JSON", document)}
		}
	}
	return abs, nil
}

// Scan runs the scanner up to Retry.Attempts times. The error is a *ConfigError, never an infrastructure failure: those are
// Code ExitInfra.
func (s *Scanner) Scan(ctx context.Context, req Request) (Result, error) {
	level := cmp.Or(req.FindingsLevel, "error")
	switch level {
	case "error", "warning", "notice", "debug":
	default:
		return Result{}, &ConfigError{fmt.Sprintf("IMAGE_SCAN_FINDINGS_LEVEL must be error, warning, notice or debug, got '%s'", level)}
	}
	format := cmp.Or(req.Format, Markdown)

	args := []string{"cves", "--only-severity", s.cfg.Severities}
	if req.VexLocation != "" {
		abs, err := ValidateVex(req.VexLocation)
		if err != nil {
			return Result{}, err
		}
		args = append(args, "--vex-location", abs, "--vex-author", s.cfg.VexAuthor)
	}
	args = append(args, "--exit-code", "--format", format, req.Image)

	attempts := s.cfg.Retry.Attempts
	for i := 1; i <= attempts; i++ {
		s.log.Group(fmt.Sprintf("Image scan of %s (attempt %d/%d)", req.Image, i, attempts))
		var stdout bytes.Buffer
		code, err := s.exec(ctx, Command{Args: args, Env: s.env(), Stdout: &stdout, Stderr: s.stderr})
		s.log.EndGroup()
		if err != nil {
			code = -1
			s.log.Printf("Cannot run the scanner: %v", err)
		}

		switch code {
		case ExitClean:
			s.log.Printf("No %s vulnerability found in %s", s.cfg.Severities, req.Image)
			return Result{Code: ExitClean, Report: stdout.Bytes()}, nil
		case ExitFindings:
			s.log.Command(level, "%s vulnerabilities found in %s", s.cfg.Severities, req.Image)
			return Result{Code: ExitFindings, Report: stdout.Bytes()}, nil
		}

		s.log.Warningf("Scanner setup/infra failure (exit %d) on attempt %d/%d", code, i, attempts)
		if i < attempts {
			sleep := s.cfg.Retry.Sleep
			if sleep == nil {
				sleep = time.Sleep
			}
			sleep(s.cfg.Retry.Backoff * time.Duration(i))
		}
	}

	s.log.Errorf("The image scan could not run on %s after %d attempts", req.Image, attempts)
	return Result{Code: ExitInfra}, nil
}

// env is what the scanner sees: the credentials by name, never on the command line, and nothing else of the action (the
// GitHub token stays out).
func (s *Scanner) env() []string {
	env := []string{
		"DOCKER_SCOUT_HUB_USER=" + s.cfg.DockerHubUser,
		"DOCKER_SCOUT_HUB_PASSWORD=" + s.cfg.DockerHubPassword,
		"DOCKER_CONFIG=" + s.dockerConfig,
	}
	if s.cfg.RegistryUser != "" && s.cfg.RegistryPassword != "" {
		env = append(env, "DOCKER_SCOUT_REGISTRY_USER="+s.cfg.RegistryUser, "DOCKER_SCOUT_REGISTRY_PASSWORD="+s.cfg.RegistryPassword)
	}
	for _, name := range []string{"PATH", "HOME", "TMPDIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	return env
}
