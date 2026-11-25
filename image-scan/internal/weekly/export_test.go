package weekly

import "context"

func (w *Weekly) Scan(ctx context.Context, tag string) ([]Finding, int) { return w.scan(ctx, tag) }
func (w *Weekly) SyncIssues(ctx context.Context, tag string, findings []Finding) (string, error) {
	return w.syncIssues(ctx, tag, findings)
}
