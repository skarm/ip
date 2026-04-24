package ip_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/skarm/ip"
)

func TestCtxAndWithContext(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8::1")
	ctx := ip.WithContext(context.Background(), addr)

	got, ok := ip.Ctx(ctx)
	if !ok {
		t.Fatal("expected IP in context")
	}
	if got != addr {
		t.Fatalf("expected %s, got %s", addr, got)
	}
}
