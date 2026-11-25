package vex

import (
	"regexp"
	"strings"
)

// ImageRef is an image reduced to what a product is compared on.
type ImageRef struct {
	Registry string // empty when the reference names none
	Repo     string
	Digest   string // empty or sha256:...
}

var (
	tagSuffix   = regexp.MustCompile(`:[^/:]*$`)
	urlDecoder  = strings.NewReplacer("%2F", "/", "%2f", "/", "%3A", ":", "%3a", ":", "%40", "@")
	httpsPrefix = regexp.MustCompile(`^https?://`)
)

func normRegistry(r string) string {
	if r == "index.docker.io" || r == "registry-1.docker.io" {
		return "docker.io"
	}
	return r
}

func digestOf(s string) string {
	if strings.HasPrefix(s, "sha256:") {
		return s
	}
	return ""
}

// splitRef reads [<registry>/]<repo>[:tag][@digest] without its digest and tag. The first path element is a registry when it
// looks like a host (a dot, a port or localhost).
func splitRef(s string) (registry, repo string) {
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[:i]
	}
	s = tagSuffix.ReplaceAllString(s, "")

	repo = s
	if i := strings.Index(s, "/"); i >= 0 {
		first := s[:i]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			registry, repo = normRegistry(first), s[i+1:]
		}
	}
	if registry == "docker.io" {
		repo = strings.TrimPrefix(repo, "library/")
	}
	return registry, repo
}

// ParseImage reads the image to scan: a reference without registry is on Docker Hub.
func ParseImage(image string) ImageRef {
	name, digest, _ := strings.Cut(image, "@")
	registry, repo := splitRef(name)
	if registry == "" {
		registry = "docker.io"
		repo = strings.TrimPrefix(repo, "library/")
	}
	return ImageRef{Registry: registry, Repo: repo, Digest: digestOf(digest)}
}

func qualifier(s, key string) string {
	parts := strings.Split(s, "?")
	if len(parts) < 2 {
		return ""
	}
	query, _, _ := strings.Cut(parts[1], "#")
	for param := range strings.SplitSeq(query, "&") {
		if value, ok := strings.CutPrefix(param, key+"="); ok {
			return value
		}
	}
	return ""
}

// productRef reads a product of a statement in any of its forms.
func productRef(product string) ImageRef {
	decoded := urlDecoder.Replace(product)

	if body, ok := strings.CutPrefix(decoded, "pkg:oci/"); ok {
		path := body
		if i := strings.IndexAny(path, "?#"); i >= 0 {
			path = path[:i]
		}
		name, version, hasDigest := strings.Cut(path, "@")
		digest := ""
		if hasDigest {
			digest = digestOf(version)
		}
		registry := httpsPrefix.ReplaceAllString(qualifier(body, "repository_url"), "")
		registry = strings.TrimSuffix(registry, "/")
		if registry == "" {
			return ImageRef{Repo: name, Digest: digest}
		}
		ref := registry + "/" + name
		if registry == name || strings.HasSuffix(registry, "/"+name) {
			ref = registry
		}
		r, repo := splitRef(ref)
		return ImageRef{Registry: r, Repo: repo, Digest: digest}
	}

	path := strings.TrimPrefix(decoded, "pkg:docker/")
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	registry, repo := splitRef(path)
	digest := ""
	if _, version, ok := strings.Cut(path, "@"); ok {
		digest = digestOf(version)
	}
	return ImageRef{Registry: registry, Repo: repo, Digest: digest}
}

// ProductMatches tells whether a product of a statement designates the image.
func ProductMatches(product string, image ImageRef) bool {
	p := productRef(product)
	return p.Repo == image.Repo &&
		(p.Registry == "" || p.Registry == image.Registry) &&
		(p.Digest == "" || image.Digest == "" || p.Digest == image.Digest)
}
