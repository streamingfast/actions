// Package gate is the image-scan gate: decide whether the scan runs, resolve the image, scan it, report to the job summary and
// the pull request, audit a skipped scan and promote the tags of a clean image.
//
// Exit codes: 0 clean (or advisory), 2 findings (never retried), 10 the scanner could not run (retried), 1 anything else
// (a misconfiguration, a failed promotion).
package gate

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/streamingfast/actions/image-scan/internal/gha"
	"github.com/streamingfast/actions/image-scan/internal/github"
	"github.com/streamingfast/actions/image-scan/internal/registry"
	"github.com/streamingfast/actions/image-scan/internal/retry"
	"github.com/streamingfast/actions/image-scan/internal/scanner"
)

// Config is the inputs of the action and the GitHub context of the run.
type Config struct {
	Image           string
	ImageRepository string
	Severities      string
	ScanPaths       string
	PromoteTags     string
	SkipReason      string
	VexLocation     string
	Enforce         string
	PRNumber        string

	EventName string
	Actor     string
	Repo      string // owner/name
	SHA       string
	Ref       string
	ServerURL string
	RunID     string
	Arch      string // runner architecture: X64 or ARM64
}

// Scanner is the scanner as the gate uses it.
type Scanner interface {
	Scan(ctx context.Context, req scanner.Request) (scanner.Result, error)
}

// Gate holds what a run needs.
type Gate struct {
	Config   Config
	Log      *gha.Logger
	Files    gha.Files
	Scanner  Scanner
	GitHub   github.API
	Registry registry.Registry
	Retry    retry.Policy
	// ChangedFiles lists the files changed by the pull request, GitChangedFiles by default
	ChangedFiles func(ctx context.Context) ([]string, error)
	Now          func() time.Time
}

func (g *Gate) now() time.Time {
	if g.Now != nil {
		return g.Now().UTC()
	}
	return time.Now().UTC()
}

// GitChangedFiles lists `git diff --name-only HEAD^1 HEAD` of a checkout: on a pull_request the checkout is the merge commit,
// HEAD^1 is the base branch. The checkout is bind-mounted, owned by another user than the one running here.
func GitChangedFiles(dir string) func(ctx context.Context) ([]string, error) {
	return func(ctx context.Context) ([]string, error) {
		cmd := exec.CommandContext(ctx, "git", "diff", "--name-only", "-z", "HEAD^1", "HEAD")
		cmd.Dir = dir
		cmd.Env = append(cmd.Environ(), "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=safe.directory", "GIT_CONFIG_VALUE_0=*")
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		var files []string
		for name := range strings.SplitSeq(string(out), "\x00") {
			if name != "" {
				files = append(files, name)
			}
		}
		return files, nil
	}
}

// Run executes the steps of the action and returns the exit code.
func (g *Gate) Run(ctx context.Context) int {
	out := outputs{files: g.Files, log: g.Log}

	scan, err := g.scope(ctx)
	if err != nil {
		g.Log.Errorf("%v", err)
		return 1
	}
	// A failed scope writes no output, like a failed step
	defer out.write()
	skip := g.decideSkip()
	out.skipped, out.scanned = skip, scan && !skip

	image, err := g.resolveImage()
	if err != nil {
		g.Log.Errorf("%v", err)
		return 1
	}

	// Without promote-tags the digest only completes the audit of a skipped scan, it must not block the emergency release
	digest := ""
	if g.Config.PromoteTags != "" || skip {
		digest, err = g.resolveDigest(ctx, image)
		switch {
		case err == nil:
		case g.Config.PromoteTags == "":
			g.Log.Warningf("%v", err)
		default:
			g.Log.Errorf("%v", err)
			return 1
		}
	}

	if skip {
		g.recordSkip(ctx, image, digest)
	}

	if scan && !skip {
		result, err := g.scan(ctx, image)
		if err != nil {
			g.Log.Errorf("%v", err)
			return 1
		}
		if result.Ran() {
			out.findings = &result.Findings
		}
		if err := g.publish(ctx, image, result); err != nil {
			g.Log.Warningf("Cannot publish the scan report: %v", err)
		}
		if result.Code != scanner.ExitClean && !(result.Code == scanner.ExitFindings && !result.Enforce) {
			return result.Code
		}
	}

	// A clean scan (or no scan: scan-paths or skip-reason skipped it) is the only way to get here
	if g.Config.PromoteTags != "" {
		promoted, err := g.promote(ctx, image, digest)
		if err != nil {
			g.Log.Errorf("%v", err)
			return 1
		}
		out.promoted = promoted
	}
	return 0
}

type outputs struct {
	files    gha.Files
	log      *gha.Logger
	scanned  bool
	skipped  bool
	findings *bool
	promoted []string
}

func (o *outputs) write() {
	set := func(name, value string) {
		if err := o.files.SetOutput(name, value); err != nil {
			o.log.Warningf("Cannot write the %s output: %v", name, err)
		}
	}
	set("scanned", fmt.Sprint(o.scanned))
	set("skipped", fmt.Sprint(o.skipped))
	if o.findings != nil {
		set("findings", fmt.Sprint(*o.findings))
	}
	set("promoted", strings.Join(o.promoted, "\n"))
}
