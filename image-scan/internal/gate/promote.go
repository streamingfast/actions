package gate

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
)

func cmpOr(a, b string) string { return cmp.Or(a, b) }

// resolveDigest resolves the image to its manifest digest, before the scan.
func (g *Gate) resolveDigest(ctx context.Context, image string) (string, error) {
	var digest string
	err := g.Retry.Do(ctx, g.Log, "Resolving the digest of "+image, func() error {
		d, err := g.Registry.Digest(ctx, image)
		digest = d
		return err
	})
	if err != nil {
		return "", fmt.Errorf("Cannot resolve the digest of %s after %d attempts, is the image pushed and the runner logged in to its registry? (%v)", image, g.Retry.Attempts, err)
	}
	g.Log.Printf("Digest of %s: %s", image, digest)
	return digest, nil
}

// sourceOf is <repository>@<digest>, the repository being the image without its tag or digest.
func sourceOf(image, digest string) string {
	repository, _, _ := strings.Cut(image, "@")
	last := repository[strings.LastIndex(repository, "/")+1:]
	if strings.Contains(last, ":") {
		repository = repository[:strings.LastIndex(repository, ":")]
	}
	return repository + "@" + digest
}

// promoteTags are the tags to add: full image refs separated by newlines or commas, trimmed and deduplicated, without the
// scanned image itself.
func promoteTags(list, image, source string) []string {
	var tags []string
	for tag := range strings.FieldsFuncSeq(list, func(r rune) bool { return r == ',' || r == '\n' }) {
		tag = strings.Join(strings.Fields(tag), "")
		if tag == "" || tag == image || tag == source || slices.Contains(tags, tag) {
			continue
		}
		tags = append(tags, tag)
	}
	return tags
}

// promote adds every promote-tags tag to the scanned image, a registry-side retag of the digest (no rebuild). It re-resolves
// the image first and fails when its digest is not the one of the scan anymore: the tag moved during the scan, what was
// scanned is not what would be promoted.
func (g *Gate) promote(ctx context.Context, image, expected string) ([]string, error) {
	digest, err := g.resolveDigest(ctx, image)
	if err != nil {
		return nil, err
	}
	if digest != expected {
		return nil, fmt.Errorf("%s points to %s now, it was %s when the scan started: nothing promoted, the scan does not cover that image", image, digest, expected)
	}

	source := sourceOf(image, digest)
	tags := promoteTags(g.Config.PromoteTags, image, source)
	if len(tags) == 0 {
		g.Log.Printf("No tag to add to %s", source)
		return nil, nil
	}

	g.Log.Printf("Adding %s to %s", strings.Join(tags, " "), source)
	err = g.Retry.Do(ctx, g.Log, "Adding the tags", func() error {
		for _, tag := range tags {
			if err := g.Registry.Copy(ctx, source, tag); err != nil {
				return fmt.Errorf("%s: %w", tag, err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("Cannot add %s to %s after %d attempts, the image is clean but not promoted. Is the runner logged in to the registry of these tags with push access? (%v)", strings.Join(tags, " "), source, g.Retry.Attempts, err)
	}
	return tags, nil
}
