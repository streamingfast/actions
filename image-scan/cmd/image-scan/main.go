// Command image-scan is the image-scan gate and weekly scan of streamingfast/actions, shipped as the
// ghcr.io/streamingfast/image-scan container image next to the Docker Scout CLI.
//
// Usage: image-scan gate | weekly | version. Inputs come from the environment (IMAGE_SCAN_*, and the GITHUB_* variables of the
// runner), see run.sh and the action.yml files.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/streamingfast/actions/image-scan/internal/gate"
	"github.com/streamingfast/actions/image-scan/internal/gha"
	"github.com/streamingfast/actions/image-scan/internal/github"
	"github.com/streamingfast/actions/image-scan/internal/registry"
	"github.com/streamingfast/actions/image-scan/internal/retry"
	"github.com/streamingfast/actions/image-scan/internal/scanner"
	"github.com/streamingfast/actions/image-scan/internal/weekly"
)

// version is set at build time.
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: image-scan gate|weekly|version")
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	log := gha.NewLogger(os.Stdout)

	var (
		code int
		err  error
	)
	switch args[0] {
	case "gate":
		code, err = runGate(ctx, log)
	case "weekly":
		code, err = runWeekly(ctx, log)
	case "version":
		fmt.Println(version)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q, usage: image-scan gate|weekly|version\n", args[0])
		return 1
	}
	if err != nil {
		log.Errorf("%v", err)
		return 1
	}
	return code
}

func env(name string) string { return os.Getenv(name) }

func policy() (retry.Policy, error) {
	retries := env("IMAGE_SCAN_RETRIES")
	if retries == "" {
		retries = "3"
	}
	attempts, err := retry.ParseAttempts(retries)
	if err != nil {
		return retry.Policy{}, err
	}
	backoff := 15
	if s := env("IMAGE_SCAN_BACKOFF"); s != "" {
		if backoff, err = strconv.Atoi(s); err != nil || backoff < 0 {
			return retry.Policy{}, fmt.Errorf("IMAGE_SCAN_BACKOFF must be a number of seconds, got '%s'", s)
		}
	}
	return retry.Policy{Attempts: attempts, Backoff: time.Duration(backoff) * time.Second}, nil
}

func scannerConfig(p retry.Policy, severities string) scanner.Config {
	return scanner.Config{
		DockerHubUser:     env("IMAGE_SCAN_DOCKERHUB_USER"),
		DockerHubPassword: env("IMAGE_SCAN_DOCKERHUB_PASSWORD"),
		RegistryUser:      env("IMAGE_SCAN_REGISTRY_USER"),
		RegistryPassword:  env("IMAGE_SCAN_REGISTRY_PASSWORD"),
		Severities:        severities,
		VexAuthor:         env("IMAGE_SCAN_VEX_AUTHOR"),
		Retry:             p,
	}
}

func runGate(ctx context.Context, log *gha.Logger) (int, error) {
	p, err := policy()
	if err != nil {
		return 0, err
	}
	cfg := gate.Config{
		Image:           env("IMAGE_SCAN_IMAGE"),
		ImageRepository: env("IMAGE_SCAN_IMAGE_REPOSITORY"),
		Severities:      env("IMAGE_SCAN_SEVERITIES"),
		ScanPaths:       env("IMAGE_SCAN_SCAN_PATHS"),
		PromoteTags:     env("IMAGE_SCAN_PROMOTE_TAGS"),
		SkipReason:      env("IMAGE_SCAN_SKIP_REASON"),
		VexLocation:     env("IMAGE_SCAN_VEX_LOCATION"),
		Enforce:         env("IMAGE_SCAN_ENFORCE"),
		PRNumber:        env("IMAGE_SCAN_PR_NUMBER"),
		EventName:       env("GITHUB_EVENT_NAME"),
		Actor:           env("GITHUB_ACTOR"),
		Repo:            env("GITHUB_REPOSITORY"),
		SHA:             env("GITHUB_SHA"),
		Ref:             env("GITHUB_REF"),
		ServerURL:       env("GITHUB_SERVER_URL"),
		RunID:           env("GITHUB_RUN_ID"),
		Arch:            env("RUNNER_ARCH"),
	}

	sc := &lazyScanner{cfg: scannerConfig(p, cfg.Severities), log: log}
	defer sc.close()

	g := &gate.Gate{
		Config:       cfg,
		Log:          log,
		Files:        gha.Files{Output: env("GITHUB_OUTPUT"), Summary: env("GITHUB_STEP_SUMMARY")},
		Scanner:      sc,
		GitHub:       github.NewClient(env("GITHUB_API_URL"), env("IMAGE_SCAN_GITHUB_TOKEN")),
		Registry:     registry.NewCrane(env("IMAGE_SCAN_REGISTRY_USER"), env("IMAGE_SCAN_REGISTRY_PASSWORD")),
		Retry:        p,
		ChangedFiles: gate.GitChangedFiles(env("GITHUB_WORKSPACE")),
	}
	return g.Run(ctx), nil
}

func runWeekly(ctx context.Context, log *gha.Logger) (int, error) {
	p, err := policy()
	if err != nil {
		return 0, err
	}
	architectures := env("IMAGE_SCAN_ARCHITECTURES")
	if architectures == "" {
		architectures = "amd64 arm64"
	}
	// The weekly scan always tracks critical and high only: severity labels and due dates do not exist below
	sc := &lazyScanner{cfg: scannerConfig(p, "critical,high"), log: log}
	defer sc.close()

	w := &weekly.Weekly{
		Config: weekly.Config{
			ImageRepository: env("IMAGE_SCAN_IMAGE_REPOSITORY"),
			Architectures:   architectures,
			VexLocation:     env("IMAGE_SCAN_VEX_LOCATION"),
			Repo:            env("GITHUB_REPOSITORY"),
		},
		Log:     log,
		Files:   gha.Files{Output: env("GITHUB_OUTPUT"), Summary: env("GITHUB_STEP_SUMMARY")},
		Scanner: sc,
		GitHub:  github.NewClient(env("GITHUB_API_URL"), env("IMAGE_SCAN_GITHUB_TOKEN")),
	}
	return w.Run(ctx), nil
}

// lazyScanner creates the scanner when the first scan runs: a gate that does not scan (scan-paths, skip-reason) needs no
// Docker Hub credentials.
type lazyScanner struct {
	cfg scanner.Config
	log *gha.Logger
	sc  *scanner.Scanner
}

func (l *lazyScanner) Scan(ctx context.Context, req scanner.Request) (scanner.Result, error) {
	if l.sc == nil {
		sc, err := scanner.New(l.cfg, l.log, scanner.BinaryExec, os.Stderr)
		if err != nil {
			return scanner.Result{}, err
		}
		l.sc = sc
	}
	return l.sc.Scan(ctx, req)
}

func (l *lazyScanner) close() {
	if l.sc != nil {
		l.sc.Close()
	}
}
