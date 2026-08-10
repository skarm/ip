package ip_test

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/skarm/ip"
)

func TestExtractResultReportsProvenance(t *testing.T) {
	tests := []struct {
		name        string
		opts        []ip.Option
		headers     map[string][]string
		remote      string
		wantAddr    string
		wantSource  ip.Source
		wantHeader  string
		wantReason  ip.Reason
		trustedHops int
	}{
		{
			name:       "headers denied",
			remote:     "203.0.113.1:443",
			wantAddr:   "203.0.113.1",
			wantSource: ip.SourceRemoteAddr,
			wantReason: ip.ReasonProxyHeadersDenied,
		},
		{
			name:        "selected single-IP header",
			opts:        []ip.Option{ip.WithTrustedProxies("10.0.0.2"), ip.WithHeaders(ip.XRealIP)},
			headers:     map[string][]string{ip.XRealIP: {"198.51.100.10"}},
			remote:      "10.0.0.2:443",
			wantAddr:    "198.51.100.10",
			wantSource:  ip.SourceProxyHeader,
			wantHeader:  ip.XRealIP,
			wantReason:  ip.ReasonSelectedHeader,
			trustedHops: 1,
		},
		{
			name:        "selected untrusted client hop",
			opts:        []ip.Option{ip.WithTrustedProxies("10.0.0.1", "10.0.0.2")},
			headers:     map[string][]string{ip.XForwardedFor: {"198.51.100.10, 10.0.0.1"}},
			remote:      "10.0.0.2:443",
			wantAddr:    "198.51.100.10",
			wantSource:  ip.SourceProxyHeader,
			wantHeader:  ip.XForwardedFor,
			wantReason:  ip.ReasonSelectedHeader,
			trustedHops: 2,
		},
		{
			name:        "unverifiable boundary fallback",
			opts:        []ip.Option{ip.WithTrustedProxies("10.0.0.1", "10.0.0.2")},
			headers:     map[string][]string{ip.XForwardedFor: {"198.51.100.10, unknown, 10.0.0.1"}},
			remote:      "10.0.0.2:443",
			wantAddr:    "10.0.0.2",
			wantSource:  ip.SourceRemoteAddr,
			wantHeader:  ip.XForwardedFor,
			wantReason:  ip.ReasonUnverifiableChain,
			trustedHops: 2,
		},
		{
			name:        "all hops trusted fallback",
			opts:        []ip.Option{ip.WithTrustedProxies("10.0.0.1", "10.0.0.2")},
			headers:     map[string][]string{ip.XForwardedFor: {"10.0.0.1"}},
			remote:      "10.0.0.2:443",
			wantAddr:    "10.0.0.2",
			wantSource:  ip.SourceRemoteAddr,
			wantHeader:  ip.XForwardedFor,
			wantReason:  ip.ReasonNoUntrustedHop,
			trustedHops: 2,
		},
		{
			name:       "allow all without proxy headers",
			opts:       []ip.Option{ip.WithUnsafeTrustAllProxies()},
			remote:     "203.0.113.1:443",
			wantAddr:   "203.0.113.1",
			wantSource: ip.SourceRemoteAddr,
			wantReason: ip.ReasonNoProxyHeaders,
		},
		{
			name:       "allow all ignores unverifiable single-IP value",
			opts:       []ip.Option{ip.WithUnsafeTrustAllProxies(), ip.WithHeaders(ip.XRealIP)},
			headers:    map[string][]string{ip.XRealIP: {"unknown"}},
			remote:     "203.0.113.1:443",
			wantAddr:   "203.0.113.1",
			wantSource: ip.SourceRemoteAddr,
			wantReason: ip.ReasonNoProxyHeaders,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := mustExtractor(t, tt.opts...)
			got, err := ex.ExtractResultFrom(tt.headers, tt.remote)
			if err != nil {
				t.Fatalf("ExtractResultFrom() error = %v", err)
			}
			if got.Addr.String() != tt.wantAddr || got.Source != tt.wantSource || got.Header != tt.wantHeader || got.Reason != tt.wantReason || got.TrustedHops != tt.trustedHops {
				t.Fatalf("ExtractResultFrom() = %+v", got)
			}
		})
	}
}

func TestExtractResultFromRejectsInvalidRemoteAddress(t *testing.T) {
	tests := []struct {
		name string
		opts []ip.Option
	}{
		{name: "headers denied"},
		{name: "allow list", opts: []ip.Option{ip.WithTrustedProxies("10.0.0.2")}},
		{name: "allow all", opts: []ip.Option{ip.WithUnsafeTrustAllProxies()}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := mustExtractor(t, tt.opts...)
			_, err := ex.ExtractResultFrom(nil, "not-a-remote-address")
			if !errors.Is(err, ip.ErrInvalidRemoteAddr) {
				t.Fatalf("ExtractResultFrom() error = %v, want ErrInvalidRemoteAddr", err)
			}
		})
	}
}

func TestExtractResultFromSupportsMoreThanInlineHeaderCount(t *testing.T) {
	const headerCount = 17

	specs := make([]ip.HeaderSpec, headerCount)
	for i := range specs {
		specs[i] = ip.HeaderSpec{
			Name: fmt.Sprintf("x-client-ip-%d", i),
			Kind: ip.HeaderSingleIP,
		}
	}

	ex := mustExtractor(t, ip.WithHeaderSpecs(specs...), ip.WithUnsafeTrustAllProxies())
	got, err := ex.ExtractResultFrom(
		map[string][]string{specs[headerCount-1].Name: {"198.51.100.10"}},
		"not-a-remote-address",
	)
	if err != nil {
		t.Fatalf("ExtractResultFrom() error = %v", err)
	}
	if got.Addr != netip.MustParseAddr("198.51.100.10") || got.Header != specs[headerCount-1].Name {
		t.Fatalf("ExtractResultFrom() = %+v", got)
	}
}

func TestProvenanceString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  fmt.Stringer
		want string
	}{
		{name: "remote source", got: ip.SourceRemoteAddr, want: "SourceRemoteAddr"},
		{name: "header source", got: ip.SourceProxyHeader, want: "SourceProxyHeader"},
		{name: "unknown source", got: ip.Source(255), want: "Source(255)"},
		{name: "selected header", got: ip.ReasonSelectedHeader, want: "ReasonSelectedHeader"},
		{name: "headers denied", got: ip.ReasonProxyHeadersDenied, want: "ReasonProxyHeadersDenied"},
		{name: "untrusted peer", got: ip.ReasonUntrustedImmediatePeer, want: "ReasonUntrustedImmediatePeer"},
		{name: "no proxy headers", got: ip.ReasonNoProxyHeaders, want: "ReasonNoProxyHeaders"},
		{name: "unverifiable chain", got: ip.ReasonUnverifiableChain, want: "ReasonUnverifiableChain"},
		{name: "no untrusted hop", got: ip.ReasonNoUntrustedHop, want: "ReasonNoUntrustedHop"},
		{name: "unknown reason", got: ip.Reason(255), want: "Reason(255)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.got.String(); got != tt.want {
				t.Fatalf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
