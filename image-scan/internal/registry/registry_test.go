package registry_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/streamingfast/actions/image-scan/internal/registry"
	"github.com/streamingfast/actions/image-scan/internal/testutil"
)

func TestIsDigest(t *testing.T) {
	assert.True(t, registry.IsDigest(testutil.Digest("a")))
	for _, bad := range []string{"", "sha256:abc", "sha512:" + testutil.Digest("a")[7:], testutil.Digest("a") + "0", "sha256:" + "G" + testutil.Digest("a")[8:]} {
		assert.False(t, registry.IsDigest(bad), bad)
	}
}
