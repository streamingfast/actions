package gate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/streamingfast/actions/image-scan/internal/gate"
	"github.com/streamingfast/actions/image-scan/internal/retry"
	"github.com/streamingfast/actions/image-scan/internal/testutil"
)

const scanned = "ghcr.io/o/r:0123456"

func promoteHarness(t *testing.T, tags string, options ...option) *harness {
	return newHarness(t, append([]option{config(func(c *gate.Config) { c.Image, c.PromoteTags = scanned, tags })}, options...)...)
}

func TestResolveDigest(t *testing.T) {
	h := promoteHarness(t, "")
	digest, err := h.g.ResolveDigest(t.Context(), scanned)
	require.NoError(t, err)
	assert.Equal(t, testutil.Digest("a"), digest, "resolve writes the digest")
	assert.Equal(t, []string{scanned}, h.reg.DigestCalls, "resolve inspects the image")

	h = promoteHarness(t, "", retries(2))
	h.reg.DigestFailures = 9
	_, err = h.g.ResolveDigest(t.Context(), scanned)
	require.Error(t, err, "resolve fails when the image cannot be inspected")
	assert.Len(t, h.reg.DigestCalls, 2, "resolve retries")
	assert.Contains(t, err.Error(), "Cannot resolve the digest of "+scanned+" after 2 attempts")
}

func TestPromote(t *testing.T) {
	a := testutil.Digest("a")
	source := "ghcr.io/o/r@" + a

	tests := []struct {
		name   string
		image  string
		tags   string
		copies []string // destinations
	}{
		{"every tag, by digest", scanned, "ghcr.io/o/r:v1.2.3\nghcr.io/o/r:latest\n", []string{"ghcr.io/o/r:v1.2.3", "ghcr.io/o/r:latest"}},
		{"comma separated, trimmed and deduplicated", scanned, "ghcr.io/o/r:v1.2.3, ghcr.io/o/r:latest ,,ghcr.io/o/r:v1.2.3", []string{"ghcr.io/o/r:v1.2.3", "ghcr.io/o/r:latest"}},
		{"the scanned image tag is skipped", scanned, "ghcr.io/o/r:0123456\nghcr.io/o/r:develop", []string{"ghcr.io/o/r:develop"}},
		{"only the scanned tag means nothing to do", scanned, "ghcr.io/o/r:0123456", nil},
		{"the source by digest is skipped", scanned, source + "\nghcr.io/o/r:x", []string{"ghcr.io/o/r:x"}},
		{"another repository of the same registry", scanned, "ghcr.io/o/other:v1", []string{"ghcr.io/o/other:v1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := promoteHarness(t, tt.tags)
			promoted, err := h.g.Promote(t.Context(), tt.image, a)
			require.NoError(t, err)

			assert.Equal(t, tt.copies, promoted, "promoted output lists the tags")
			var destinations []string
			for _, c := range h.reg.Copies {
				assert.Equal(t, source, c[0], "copied by digest")
				destinations = append(destinations, c[1])
			}
			assert.Equal(t, tt.copies, destinations)
		})
	}

	t.Run("a registry port is not taken for a tag", func(t *testing.T) {
		h := promoteHarness(t, "localhost:5000/o/r:latest")
		_, err := h.g.Promote(t.Context(), "localhost:5000/o/r:0123456", a)
		require.NoError(t, err)
		assert.Equal(t, "localhost:5000/o/r@"+a, h.reg.Copies[0][0])
	})

	t.Run("an image already by digest is promoted as is", func(t *testing.T) {
		h := promoteHarness(t, "ghcr.io/o/r:latest")
		_, err := h.g.Promote(t.Context(), "ghcr.io/o/r@"+a, a)
		require.NoError(t, err)
		assert.Equal(t, "ghcr.io/o/r@"+a, h.reg.Copies[0][0])
	})

	t.Run("a tag that moved since the scan started fails", func(t *testing.T) {
		h := promoteHarness(t, "ghcr.io/o/r:latest")
		h.reg.Digests = []string{testutil.Digest("b")}
		_, err := h.g.Promote(t.Context(), scanned, a)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nothing promoted, the scan does not cover that image")
		assert.Empty(t, h.reg.Copies, "and promotes nothing")
	})

	t.Run("a failed copy is retried", func(t *testing.T) {
		h := promoteHarness(t, "ghcr.io/o/r:latest")
		h.reg.CopyFailures = 1
		promoted, err := h.g.Promote(t.Context(), scanned, a)
		require.NoError(t, err)
		assert.Equal(t, []string{"ghcr.io/o/r:latest"}, promoted)
		assert.Equal(t, 2, h.reg.CopyCalls, "twice")
	})

	t.Run("a copy failing after the retries fails", func(t *testing.T) {
		h := promoteHarness(t, "ghcr.io/o/r:latest", retries(2))
		h.reg.CopyFailures = 9
		promoted, err := h.g.Promote(t.Context(), scanned, a)
		require.Error(t, err)
		assert.Empty(t, promoted, "nothing reported promoted")
		assert.Equal(t, 2, h.reg.CopyCalls, "stops after the retries")
	})
}

func TestInvalidRetriesAreRejected(t *testing.T) {
	_, err := retry.ParseAttempts("abc")
	assert.Error(t, err)
}
