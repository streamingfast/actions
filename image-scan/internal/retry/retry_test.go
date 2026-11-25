package retry_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/streamingfast/actions/image-scan/internal/gha"
	"github.com/streamingfast/actions/image-scan/internal/retry"
)

func TestParseAttempts(t *testing.T) {
	for in, want := range map[string]int{"1": 1, "3": 3, "12": 12} {
		got, err := retry.ParseAttempts(in)
		assert.NoError(t, err)
		assert.Equal(t, want, got)
	}
	for _, bad := range []string{"0", "abc", "-1", "", "01", "1.5"} {
		_, err := retry.ParseAttempts(bad)
		assert.EqualError(t, err, "retries must be a positive integer, got '"+bad+"'")
	}
}

func TestDo(t *testing.T) {
	var slept []time.Duration
	p := retry.Policy{Attempts: 3, Backoff: 15 * time.Second, Sleep: func(d time.Duration) { slept = append(slept, d) }}
	var log bytes.Buffer

	calls := 0
	err := p.Do(t.Context(), gha.NewLogger(&log), "thing", func() error {
		calls++
		if calls < 3 {
			return errors.New("flaky")
		}
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, []time.Duration{15 * time.Second, 30 * time.Second}, slept, "linear backoff")
	assert.Contains(t, log.String(), "::warning::thing failed on attempt 1/3")

	slept = nil
	err = p.Do(t.Context(), gha.NewLogger(&log), "thing", func() error { return errors.New("down") })
	assert.EqualError(t, err, "down", "the last error")
	assert.Len(t, slept, 2, "no sleep after the last attempt")
}
