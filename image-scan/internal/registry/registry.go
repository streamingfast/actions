// Package registry resolves digests and retags images registry-side, with go-containerregistry: no Docker daemon, no rebuild,
// the multi-arch index and its attestations are copied as they are, so the digest is the one that was scanned.
//
// Credentials come from the Docker config of the runner (DOCKER_CONFIG, written by docker/login-action, mounted read-only
// into the container), which also covers the GCP access-token logins of gcr.io. When it has none for a registry, the
// registry credentials given to the action are used for the registry of the scanned image.
package registry

import (
	"context"
	"fmt"
	"regexp"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
)

// Registry is what promotion needs from a registry, an interface so the logic is tested without the network.
type Registry interface {
	// Digest is the digest of the manifest (or index) a reference points to.
	Digest(ctx context.Context, ref string) (string, error)
	// Copy copies source (by digest) to the destination reference, a registry-side retag.
	Copy(ctx context.Context, source, destination string) error
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// IsDigest tells whether s is a sha256 digest.
func IsDigest(s string) bool { return digestPattern.MatchString(s) }

// Crane is the Registry backed by go-containerregistry.
type Crane struct {
	user, password string
}

// NewCrane uses the Docker config first, then the given credentials, only for the registry of the scanned image: the
// source of every call. They are never sent to the registry of another tag.
func NewCrane(user, password string) *Crane { return &Crane{user: user, password: password} }

type basicFor struct {
	registry string
	auth     authn.Authenticator
}

func (b basicFor) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	if resource.RegistryStr() == b.registry {
		return b.auth, nil
	}
	return authn.Anonymous, nil
}

func (c *Crane) options(ctx context.Context, source string) []crane.Option {
	keychains := []authn.Keychain{authn.DefaultKeychain}
	if c.user != "" && c.password != "" {
		if ref, err := name.ParseReference(source); err == nil {
			keychains = append(keychains, basicFor{registry: ref.Context().RegistryStr(), auth: &authn.Basic{Username: c.user, Password: c.password}})
		}
	}
	return []crane.Option{crane.WithContext(ctx), crane.WithAuthFromKeychain(authn.NewMultiKeychain(keychains...))}
}

func (c *Crane) Digest(ctx context.Context, ref string) (string, error) {
	digest, err := crane.Digest(ref, c.options(ctx, ref)...)
	if err != nil {
		return "", err
	}
	if !IsDigest(digest) {
		return "", fmt.Errorf("%s resolved to %q, not a sha256 digest", ref, digest)
	}
	return digest, nil
}

func (c *Crane) Copy(ctx context.Context, source, destination string) error {
	return crane.Copy(source, destination, c.options(ctx, source)...)
}
