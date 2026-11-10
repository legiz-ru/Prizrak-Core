package constant

import "context"

type healthCheckKey struct{}

// WithHealthCheck marks ctx as the context of a health check of a proxy: a
// connection made only to measure the proxy, not for traffic.
func WithHealthCheck(ctx context.Context) context.Context {
	return context.WithValue(ctx, healthCheckKey{}, true)
}

// IsHealthCheck says whether ctx is the context of a health check.
func IsHealthCheck(ctx context.Context) bool {
	marked, _ := ctx.Value(healthCheckKey{}).(bool)
	return marked
}
