package ip_test

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/ip"
)

func TestExtractUsesHTTPRequestMetadata(t *testing.T) {
	ex := mustExtractor(t, ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"))
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set(ip.XForwardedFor, "198.51.100.10, 10.0.0.1")

	got, err := ex.Extract(req)
	assertExtractResult(t, got, err, "198.51.100.10", nil, "")
}

func TestExtractResultUsesHTTPRequestMetadata(t *testing.T) {
	ex := mustExtractor(t, ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"))
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set(ip.XForwardedFor, "198.51.100.10, 10.0.0.1")

	got, err := ex.ExtractResult(req)
	if err != nil {
		t.Fatalf("ExtractResult() error = %v", err)
	}
	want := ip.Result{
		Addr:        netip.MustParseAddr("198.51.100.10"),
		Header:      ip.XForwardedFor,
		TrustedHops: 2,
		Source:      ip.SourceProxyHeader,
		Reason:      ip.ReasonSelectedHeader,
	}
	if got != want {
		t.Fatalf("ExtractResult() = %+v, want %+v", got, want)
	}
}

func TestExtractFrom(t *testing.T) {
	for _, tt := range extractTestCases() {
		t.Run(tt.name, func(t *testing.T) {
			ex := mustExtractor(t, tt.opts...)
			got, err := ex.ExtractFrom(cloneHeaders(tt.headers), tt.remoteAddr)
			assertExtractResult(t, got, err, tt.wantIP, tt.wantErr, tt.errText)
		})
	}
}

func TestExtractFromNormalizesBracketedIPv6RemoteAddress(t *testing.T) {
	ex := mustExtractor(t)

	got, err := ex.ExtractFrom(nil, "[fe80::1%eth0]:443")
	if err != nil {
		t.Fatalf("ExtractFrom() error = %v", err)
	}
	if got != netip.MustParseAddr("fe80::1") {
		t.Fatalf("ExtractFrom() = %v, want fe80::1", got)
	}
}

func TestExtractFromDoesNotMutateInputHeaders(t *testing.T) {
	ex := mustExtractor(t, ip.WithTrustedProxies("10.0.0.2"))

	headers := map[string][]string{
		"X-Forwarded-For": {"198.51.100.10"},
		"x-forwarded-for": {"203.0.113.5"},
		"X-Real-IP":       {"198.51.100.20"},
	}
	before := cloneHeaders(headers)

	got, err := ex.ExtractFrom(headers, "10.0.0.2:443")
	if err != nil {
		t.Fatalf("ExtractFrom() error = %v", err)
	}
	if !got.IsValid() {
		t.Fatal("expected valid IP")
	}

	assertHeadersEqual(t, headers, before)
}

type extractTestCase struct {
	name       string
	opts       []ip.Option
	headers    map[string][]string
	remoteAddr string
	wantIP     string
	wantErr    error
	errText    string
}

func extractTestCases() []extractTestCase {
	return []extractTestCase{
		{
			name:       "default ignores proxy headers",
			remoteAddr: "203.0.113.10:1234",
			headers: map[string][]string{
				ip.XForwardedFor: {"198.51.100.10"},
			},
			wantIP: "203.0.113.10",
		},
		{
			name:       "allow list uses trusted X-Forwarded-For chain",
			opts:       []ip.Option{ip.WithTrustedProxies("10.0.0.2", "10.0.0.1")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"198.51.100.10, 10.0.0.1"},
			},
			wantIP: "198.51.100.10",
		},
		{
			name:       "mapped trusted proxy matches native remote address",
			opts:       []ip.Option{ip.WithTrustedProxies("::ffff:10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"198.51.100.10"},
			},
			wantIP: "198.51.100.10",
		},
		{
			name:       "mapped trusted prefix matches native remote address",
			opts:       []ip.Option{ip.WithTrustedProxies("::ffff:10.0.0.0/104")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"198.51.100.10"},
			},
			wantIP: "198.51.100.10",
		},
		{
			name:       "allow list ignores untrusted proxy headers",
			opts:       []ip.Option{ip.WithTrustedProxies("10.0.0.0/8")},
			remoteAddr: "203.0.113.20:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"198.51.100.10"},
			},
			wantIP: "203.0.113.20",
		},
		{
			name:       "allow all trusts left-most X-Forwarded-For",
			opts:       []ip.Option{ip.WithUnsafeTrustAllProxies()},
			remoteAddr: "203.0.113.20:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"198.51.100.10, 10.0.0.1"},
			},
			wantIP: "198.51.100.10",
		},
		{
			name: "supports lowercase metadata keys",
			opts: []ip.Option{ip.WithTrustedProxies("10.0.0.2")},
			headers: map[string][]string{
				"x-forwarded-for": {"198.51.100.10"},
			},
			remoteAddr: "10.0.0.2:443",
			wantIP:     "198.51.100.10",
		},
		{
			name: "matches arbitrary ASCII header casing",
			opts: []ip.Option{ip.WithTrustedProxies("10.0.0.2")},
			headers: map[string][]string{
				"x-FoRwArDeD-fOr": {"198.51.100.10"},
			},
			remoteAddr: "10.0.0.2:443",
			wantIP:     "198.51.100.10",
		},
		{
			name:       "permissive duplicate logical header prefers lowercase key",
			opts:       []ip.Option{ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				"X-Forwarded-For": {"198.51.100.10"},
				"x-forwarded-for": {"203.0.113.5"},
			},
			wantIP: "203.0.113.5",
		},
		{
			name:       "strict duplicate logical header is ambiguous",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				"X-Forwarded-For": {"198.51.100.10"},
				"x-forwarded-for": {"203.0.113.5"},
			},
			wantErr: ip.ErrAmbiguousHeader,
		},
		{
			name:       "spoofing chain returns first untrusted hop from right",
			opts:       []ip.Option{ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"198.51.100.10, 203.0.113.55"},
			},
			wantIP: "203.0.113.55",
		},
		{
			name:       "all trusted hops fall back to remote",
			opts:       []ip.Option{ip.WithTrustedProxies("10.0.0.2", "10.0.0.1")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"10.0.0.1"},
			},
			wantIP: "10.0.0.2",
		},
		{
			name:       "forwarded supports multiple header values",
			opts:       []ip.Option{ip.WithTrustedProxies("10.0.0.2", "10.0.0.1")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.Forwarded: {`for=198.51.100.10;proto=https`, `for="[2001:db8::1]:1234";by=10.0.0.1`},
			},
			wantIP: "2001:db8::1",
		},
		{
			name:       "Forwarded wins over de-facto headers",
			opts:       []ip.Option{ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.Forwarded:     {`for=198.51.100.10`},
				ip.XForwardedFor: {"198.51.100.20"},
			},
			wantIP: "198.51.100.10",
		},
		{
			name:       "strict mapped and native headers resolve equally",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.Forwarded:     {`for="[::ffff:198.51.100.10]"`},
				ip.XForwardedFor: {"198.51.100.10"},
			},
			wantIP: "198.51.100.10",
		},
		{
			name:       "strict conflicting headers",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.Forwarded:     {`for=198.51.100.10`},
				ip.XForwardedFor: {"198.51.100.20"},
			},
			wantErr: ip.ErrConflictingHeaders,
		},
		{
			name:       "strict duplicate Forwarded parameter",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.Forwarded: {`for=198.51.100.10;by=10.0.0.1;by=10.0.0.2`},
			},
			wantErr: ip.ErrInvalidForwarded,
		},
		{
			name:       "strict invalid Forwarded parameter name",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.Forwarded: {`bad key=value;for=198.51.100.10`},
			},
			wantErr: ip.ErrInvalidForwarded,
		},
		{
			name:       "strict malformed Forwarded",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.Forwarded: {`for="[2001:db8::1"`},
			},
			wantErr: ip.ErrInvalidForwarded,
		},
		{
			name:       "permissive malformed Forwarded falls back to remote",
			opts:       []ip.Option{ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.Forwarded:     {`for="[2001:db8::1"`},
				ip.XForwardedFor: {"198.51.100.10"},
			},
			wantIP: "10.0.0.2",
		},
		{
			name:       "strict whitespace separated X-Forwarded-For is invalid",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"198.51.100.10 10.0.0.1"},
			},
			wantErr: ip.ErrInvalidIP,
		},
		{
			name:       "strict empty X-Forwarded-For element is invalid",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"198.51.100.10,,10.0.0.1"},
			},
			wantErr: ip.ErrInvalidIP,
		},
		{
			name:       "strict malformed X-Forwarded-For",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"bad-token"},
			},
			wantErr: ip.ErrInvalidIP,
		},
		{
			name:       "permissive malformed X-Forwarded-For falls back to remote",
			opts:       []ip.Option{ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"bad-token"},
			},
			wantIP: "10.0.0.2",
		},
		{
			name:       "strict untrusted proxy header rejected",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.0/8")},
			remoteAddr: "203.0.113.20:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"198.51.100.10"},
			},
			wantErr: ip.ErrUntrustedProxy,
		},
		{
			name:       "strict ambiguous single value header",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.XRealIP: {"198.51.100.10", "198.51.100.20"},
			},
			wantErr: ip.ErrAmbiguousHeader,
		},
		{
			name:       "strict malformed single ip header",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.XRealIP: {"bad-ip"},
			},
			wantErr: ip.ErrInvalidIP,
		},
		{
			name:       "permissive malformed single ip header falls back to remote",
			opts:       []ip.Option{ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.XRealIP: {"bad-ip"},
			},
			wantIP: "10.0.0.2",
		},
		{
			name:       "unknown single ip header falls back to remote",
			opts:       []ip.Option{ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.XRealIP: {"unknown"},
			},
			wantIP: "10.0.0.2",
		},
		{
			name:       "unknown Forwarded node falls back to remote",
			opts:       []ip.Option{ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.Forwarded: {`for=unknown`},
			},
			wantIP: "10.0.0.2",
		},
		{
			name:       "strict unknown proxy chain is unverifiable",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2", "10.0.0.1")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"unknown, 10.0.0.1"},
			},
			wantErr: ip.ErrUnverifiableChain,
		},
		{
			name:       "strict without proxy headers returns remote",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.0/8")},
			remoteAddr: "203.0.113.10:443",
			wantIP:     "203.0.113.10",
		},
		{
			name:       "strict allows matching trusted headers",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.Forwarded: {`for=198.51.100.10`},
				ip.XRealIP:   {"198.51.100.10"},
			},
			wantIP: "198.51.100.10",
		},
		{
			name:       "invalid remote addr includes context",
			remoteAddr: "bad remote",
			wantErr:    ip.ErrInvalidRemoteAddr,
			errText:    "RemoteAddr",
		},
		{
			name:       "allow all falls back to remote when no headers",
			opts:       []ip.Option{ip.WithUnsafeTrustAllProxies()},
			remoteAddr: "203.0.113.10:443",
			wantIP:     "203.0.113.10",
		},
		{
			name:       "allow all uses header when remote addr is invalid",
			opts:       []ip.Option{ip.WithUnsafeTrustAllProxies()},
			remoteAddr: "bad remote",
			headers: map[string][]string{
				ip.XForwardedFor: {"198.51.100.10"},
			},
			wantIP: "198.51.100.10",
		},
		{
			name:       "strict allow all returns malformed header error",
			opts:       []ip.Option{ip.WithStrict(), ip.WithUnsafeTrustAllProxies()},
			remoteAddr: "203.0.113.10:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"bad-token"},
			},
			wantErr: ip.ErrInvalidIP,
		},
		{
			name:       "strict allow all rejects unknown hop before valid address",
			opts:       []ip.Option{ip.WithStrict(), ip.WithUnsafeTrustAllProxies()},
			remoteAddr: "203.0.113.10:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"unknown, 198.51.100.10"},
			},
			wantErr: ip.ErrUnverifiableChain,
		},
		{
			name:       "strict allow all rejects unknown hop after valid address",
			opts:       []ip.Option{ip.WithStrict(), ip.WithUnsafeTrustAllProxies()},
			remoteAddr: "203.0.113.10:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"198.51.100.10, unknown"},
			},
			wantErr: ip.ErrUnverifiableChain,
		},
		{
			name:       "strict allow all rejects obfuscated Forwarded node",
			opts:       []ip.Option{ip.WithStrict(), ip.WithUnsafeTrustAllProxies()},
			remoteAddr: "203.0.113.10:443",
			headers: map[string][]string{
				ip.Forwarded: {"for=_hidden, for=198.51.100.10"},
			},
			wantErr: ip.ErrUnverifiableChain,
		},
		{
			name:       "strict allow all rejects Forwarded element without for",
			opts:       []ip.Option{ip.WithStrict(), ip.WithUnsafeTrustAllProxies()},
			remoteAddr: "203.0.113.10:443",
			headers: map[string][]string{
				ip.Forwarded: {"for=198.51.100.10, by=203.0.113.9"},
			},
			wantErr: ip.ErrUnverifiableChain,
		},
		{
			name:       "allow all invalid remote without usable headers returns remote error",
			opts:       []ip.Option{ip.WithUnsafeTrustAllProxies()},
			remoteAddr: "bad remote",
			headers: map[string][]string{
				ip.XForwardedFor: {"bad-token"},
			},
			wantErr: ip.ErrInvalidRemoteAddr,
			errText: "RemoteAddr",
		},
		{
			name:       "bare remote address is accepted",
			remoteAddr: "203.0.113.10",
			wantIP:     "203.0.113.10",
		},
	}
}

func mustExtractor(t *testing.T, opts ...ip.Option) *ip.Extractor {
	t.Helper()

	ex, err := ip.New(opts...)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return ex
}

func assertExtractResult(t *testing.T, got netip.Addr, err error, wantIP string, wantErr error, errText string) {
	t.Helper()

	if !errors.Is(err, wantErr) {
		t.Fatalf("expected error %v, got %v", wantErr, err)
	}
	if errText != "" && (err == nil || !strings.Contains(err.Error(), errText)) {
		t.Fatalf("expected error text %q, got %v", errText, err)
	}
	if wantErr != nil {
		return
	}
	if got.String() != wantIP {
		t.Fatalf("expected %q, got %q", wantIP, got.String())
	}
}

func cloneHeaders(headers map[string][]string) map[string][]string {
	if headers == nil {
		return nil
	}

	cloned := make(map[string][]string, len(headers))
	for k, values := range headers {
		cloned[k] = append([]string(nil), values...)
	}

	return cloned
}

func assertHeadersEqual(t *testing.T, got, want map[string][]string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("expected %d header keys, got %d", len(want), len(got))
	}

	for key, wantValues := range want {
		gotValues, ok := got[key]
		if !ok {
			t.Fatalf("missing header key %q", key)
		}
		if !slices.Equal(gotValues, wantValues) {
			t.Fatalf("header %q: expected %s, got %s", key, fmt.Sprint(wantValues), fmt.Sprint(gotValues))
		}
	}
}

func TestExtractorResourceLimits(t *testing.T) {
	tests := []struct {
		name    string
		opts    []ip.Option
		headers map[string][]string
		wantErr error
	}{
		{
			name:    "aggregate header bytes",
			opts:    []ip.Option{ip.WithMaxHeaderBytes(8)},
			headers: map[string][]string{ip.XForwardedFor: {"198.51.100.10"}},
			wantErr: ip.ErrHeaderTooLarge,
		},
		{
			name:    "physical header values",
			opts:    []ip.Option{ip.WithMaxHeaderValues(1)},
			headers: map[string][]string{ip.XForwardedFor: {"198.51.100.10", "10.0.0.1"}},
			wantErr: ip.ErrTooManyHeaderValues,
		},
		{
			name:    "proxy hops",
			opts:    []ip.Option{ip.WithMaxHops(2)},
			headers: map[string][]string{ip.XForwardedFor: {"198.51.100.10, 10.0.0.1, 10.0.0.2"}},
			wantErr: ip.ErrTooManyHops,
		},
		{
			name:    "proxy token bytes",
			opts:    []ip.Option{ip.WithMaxTokenBytes(8)},
			headers: map[string][]string{ip.XForwardedFor: {"198.51.100.10"}},
			wantErr: ip.ErrTokenTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := append([]ip.Option{ip.WithTrustedProxies("10.0.0.2")}, tt.opts...)
			ex := mustExtractor(t, opts...)
			_, err := ex.ExtractFrom(tt.headers, "10.0.0.2:443")
			if !errors.Is(err, ip.ErrLimitExceeded) || !errors.Is(err, tt.wantErr) {
				t.Fatalf("ExtractFrom() error = %v, want ErrLimitExceeded and %v", err, tt.wantErr)
			}
		})
	}
}

func TestProxiesDeniedDoesNotProcessProxyHeaderLimits(t *testing.T) {
	ex := mustExtractor(t, ip.WithMaxHeaderBytes(1))
	got, err := ex.ExtractFrom(map[string][]string{ip.XForwardedFor: {strings.Repeat("x", 1024)}}, "203.0.113.1:443")
	if err != nil {
		t.Fatalf("ExtractFrom() error = %v", err)
	}
	if got.String() != "203.0.113.1" {
		t.Fatalf("ExtractFrom() = %v, want 203.0.113.1", got)
	}
}

func TestSingleIPHeaderEnforcesTokenLimit(t *testing.T) {
	ex := mustExtractor(t,
		ip.WithTrustedProxies("10.0.0.2"),
		ip.WithHeaders(ip.XRealIP),
		ip.WithMaxTokenBytes(8),
	)

	_, err := ex.ExtractFrom(
		map[string][]string{ip.XRealIP: {"198.51.100.10"}},
		"10.0.0.2:443",
	)
	if !errors.Is(err, ip.ErrLimitExceeded) || !errors.Is(err, ip.ErrTokenTooLarge) {
		t.Fatalf("ExtractFrom() error = %v, want token limit errors", err)
	}
}
