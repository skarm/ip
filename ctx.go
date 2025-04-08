package ip

import (
	"context"
	"net/netip"
)

// The context keys.
type ctxIPKey struct{}

// Ctx retrieves the IP address from the request context.
func Ctx(ctx context.Context) (netip.Addr, bool) {
	ip, ok := ctx.Value(ctxIPKey{}).(netip.Addr)
	return ip, ok
}

// WithContext adds an IP address to the context.
func WithContext(ctx context.Context, v netip.Addr) context.Context {
	return context.WithValue(ctx, ctxIPKey{}, v)
}
