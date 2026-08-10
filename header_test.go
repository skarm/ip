package ip_test

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/skarm/ip"
)

func TestStrictUntrustedPeerDetectsConfiguredHeaderCasing(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		wantErr error
	}{
		{
			name:    "canonical casing",
			headers: map[string][]string{"X-Forwarded-For": {"198.51.100.10"}},
			wantErr: ip.ErrUntrustedProxy,
		},
		{
			name:    "mixed casing",
			headers: map[string][]string{"x-FoRwArDeD-fOr": {"198.51.100.10"}},
			wantErr: ip.ErrUntrustedProxy,
		},
		{
			name:    "empty configured value is ignored",
			headers: map[string][]string{"x-FoRwArDeD-fOr": nil},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := mustExtractor(t, ip.WithStrict(), ip.WithTrustedProxies("10.0.0.0/8"))
			got, err := ex.ExtractFrom(tt.headers, "203.0.113.20:443")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ExtractFrom() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && got != netip.MustParseAddr("203.0.113.20") {
				t.Fatalf("ExtractFrom() = %v, want 203.0.113.20", got)
			}
		})
	}
}

func TestUnknownLargeHeaderNameDoesNotAllocatePerExtraction(t *testing.T) {
	ex := ip.Must(ip.New(ip.WithUnsafeTrustAllProxies()))
	want := netip.MustParseAddr("192.0.2.1")
	headers := map[string][]string{
		strings.Repeat("x", 1<<20): {"ignored"},
	}

	allocs := testing.AllocsPerRun(100, func() {
		result, err := ex.ExtractResultFrom(headers, "192.0.2.1:443")
		if err != nil {
			panic(err)
		}
		if result.Addr != want {
			panic("unexpected result")
		}
	})
	if allocs != 0 {
		t.Fatalf("allocations per extraction = %.2f, want 0", allocs)
	}
}
