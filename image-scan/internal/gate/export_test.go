package gate

import "context"

// The steps of the gate, for the tests.

func (g *Gate) ResolveImage() (string, error) { return g.resolveImage() }
func (g *Gate) DecideSkip() bool              { return g.decideSkip() }
func (g *Gate) RecordSkip(ctx context.Context, image, digest string) {
	g.recordSkip(ctx, image, digest)
}
func (g *Gate) ResolveDigest(ctx context.Context, image string) (string, error) {
	return g.resolveDigest(ctx, image)
}
func (g *Gate) Promote(ctx context.Context, image, expected string) ([]string, error) {
	return g.promote(ctx, image, expected)
}
func (g *Gate) Scan(ctx context.Context, image string) (ScanResult, error) { return g.scan(ctx, image) }
func (g *Gate) Publish(ctx context.Context, image string, r ScanResult) error {
	return g.publish(ctx, image, r)
}
