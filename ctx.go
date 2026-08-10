package ip

import (
	"context"
	"net/netip"
)

type ctxIPKey struct{}

// Ctx returns the client IP address stored in ctx.
//
// The second result is false when ctx does not contain an address stored by
// [WithContext].
func Ctx(ctx context.Context) (netip.Addr, bool) {
	ip, ok := ctx.Value(ctxIPKey{}).(netip.Addr)
	return ip, ok
}

// WithContext returns a child context that stores v as the client IP address.
// IPv4-mapped IPv6 addresses are converted to IPv4, and IPv6 zones are removed.
func WithContext(ctx context.Context, v netip.Addr) context.Context {
	return context.WithValue(ctx, ctxIPKey{}, normalizeAddr(v))
}
