// Package retry runs a flaky infrastructure call a few times with a linear backoff.
package retry

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/streamingfast/actions/image-scan/internal/gha"
)

var positiveInt = regexp.MustCompile(`^[1-9][0-9]*$`)

// ParseAttempts validates the `retries` input: a positive integer.
func ParseAttempts(s string) (int, error) {
	if !positiveInt.MatchString(s) {
		return 0, fmt.Errorf("retries must be a positive integer, got '%s'", s)
	}
	return strconv.Atoi(s)
}

// Policy is the number of attempts and the base backoff, multiplied by the attempt number.
type Policy struct {
	Attempts int
	Backoff  time.Duration
	Sleep    func(time.Duration) // time.Sleep when nil
}

// Do calls fn until it succeeds or the attempts are used, warning on each failure. It returns the last error.
func (p Policy) Do(ctx context.Context, log *gha.Logger, what string, fn func() error) error {
	sleep := p.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	var err error
	for i := 1; i <= p.Attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		log.Warningf("%s failed on attempt %d/%d", what, i, p.Attempts)
		if i < p.Attempts {
			sleep(p.Backoff * time.Duration(i))
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return err
}
