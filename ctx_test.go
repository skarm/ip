package ip_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/skarm/ip"
)

func TestCtxWithoutAddress(t *testing.T) {
	got, ok := ip.Ctx(context.Background())
	if ok {
		t.Fatalf("Ctx() = (%v, true), want (_, false)", got)
	}
}

func TestWithContext(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "IPv6", input: "2001:db8::1", want: "2001:db8::1"},
		{name: "IPv4-mapped IPv6", input: "::ffff:198.51.100.10", want: "198.51.100.10"},
		{name: "IPv6 zone", input: "fe80::1%eth0", want: "fe80::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := ip.WithContext(context.Background(), netip.MustParseAddr(tt.input))

			got, ok := ip.Ctx(ctx)
			if !ok {
				t.Fatal("Ctx() did not find the address stored by WithContext()")
			}

			want := netip.MustParseAddr(tt.want)
			if got != want {
				t.Fatalf("Ctx() = %v, want %v", got, want)
			}
		})
	}
}
