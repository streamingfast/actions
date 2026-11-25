package gate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/streamingfast/actions/image-scan/internal/gate"
)

func TestResolveImage(t *testing.T) {
	const sha = "0123456789abcdef"
	tests := []struct {
		name  string
		cfg   gate.Config
		want  string
		fails bool
	}{
		{"explicit image is used as is", gate.Config{Image: "x/y:z", Arch: "X64", SHA: sha}, "x/y:z", false},
		{"commit and amd64 by default", gate.Config{ImageRepository: "ghcr.io/o/r", Arch: "X64", SHA: sha, Ref: "refs/heads/main"}, "ghcr.io/o/r:0123456-amd64", false},
		{"tag name and arm64 on a tag build", gate.Config{ImageRepository: "ghcr.io/o/r", Arch: "ARM64", SHA: sha, Ref: "refs/tags/v1.2.3"}, "ghcr.io/o/r:v1.2.3-arm64", false},
		{"unknown runner architecture fails", gate.Config{ImageRepository: "r", Arch: "X86", SHA: sha}, "", true},
		{"no repository fails", gate.Config{Arch: "X64", SHA: sha}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, config(func(c *gate.Config) { *c = tt.cfg }))
			image, err := h.g.ResolveImage()
			if tt.fails {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, image)
		})
	}
}
