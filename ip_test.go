package ip_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/ip"
)

func TestExtract(t *testing.T) {
	runExtractCases(t, func(t *testing.T, ex *ip.Extractor, tt extractTestCase) (netip.Addr, error) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = tt.remoteAddr
		req.Header = make(http.Header)
		for k, values := range tt.headers {
			req.Header[k] = append([]string(nil), values...)
		}

		return ex.Extract(req)
	})
}

func TestExtractFrom(t *testing.T) {
	runExtractCases(t, func(t *testing.T, ex *ip.Extractor, tt extractTestCase) (netip.Addr, error) {
		return ex.ExtractFrom(cloneHeaders(tt.headers), tt.remoteAddr)
	})
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

func TestParseRemoteAddr(t *testing.T) {
	runParseAddrCases(t, ip.ParseRemoteAddr, func(tt parseAddrCase) string {
		return tt.remoteWantIP
	}, func(tt parseAddrCase) bool {
		return tt.remoteWantErr
	})
}

func TestParseAddrPort(t *testing.T) {
	runParseAddrCases(t, ip.ParseAddrPort, func(tt parseAddrCase) string {
		return tt.addrPortWantIP
	}, func(tt parseAddrCase) bool {
		return tt.addrPortWantErr
	})
}

func TestParseAddr(t *testing.T) {
	runParseAddrCases(t, ip.ParseAddr, func(tt parseAddrCase) string {
		return tt.addrWantIP
	}, func(tt parseAddrCase) bool {
		return tt.addrWantErr
	})
}

func TestParseForwarded(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    []string
		wantErr error
	}{
		{name: "single ipv4", header: `for=192.0.2.43`, want: []string{"192.0.2.43"}},
		{name: "quoted ipv6 with port", header: `for="[2001:db8::1]:1234"`, want: []string{"2001:db8::1"}},
		{name: "multiple forwarded elements", header: `for=192.0.2.43, for=198.51.100.17`, want: []string{"192.0.2.43", "198.51.100.17"}},
		{name: "obfuscated and unknown are skipped", header: `for=_hidden, for=unknown, for=198.51.100.17`, want: []string{"198.51.100.17"}},
		{name: "escaped quoted string with comma", header: `for="198.51.100.17";by="proxy\,1", for=192.0.2.1`, want: []string{"198.51.100.17", "192.0.2.1"}},
		{name: "obfuscated port is accepted", header: `for="[2001:db8::1]:_https"`, want: []string{"2001:db8::1"}},
		{name: "malformed elements return partial result", header: `for="[2001:db8::1", for=198.51.100.17`, want: []string{"198.51.100.17"}, wantErr: ip.ErrInvalidForwarded},
		{name: "invalid obfuscated identifier returns partial result", header: `for=_bad!, for=198.51.100.2`, want: []string{"198.51.100.2"}, wantErr: ip.ErrInvalidForwarded},
		{name: "quoted value with trailing junk returns partial result", header: `for="192.0.2.1"x, for=198.51.100.2`, want: []string{"198.51.100.2"}, wantErr: ip.ErrInvalidForwarded},
		{name: "duplicate for parameter returns partial result", header: `for=192.0.2.1;for=198.51.100.2, for=203.0.113.1`, want: []string{"203.0.113.1"}, wantErr: ip.ErrInvalidForwarded},
		{name: "invalid bracketed ipv4 returns partial result", header: `for="[192.0.2.1]", for=198.51.100.2`, want: []string{"198.51.100.2"}, wantErr: ip.ErrInvalidForwarded},
		{name: "invalid port returns partial result", header: `for=192.0.2.1:http, for=198.51.100.2`, want: []string{"198.51.100.2"}, wantErr: ip.ErrInvalidForwarded},
		{name: "invalid parameter syntax returns partial result", header: `proto, for=198.51.100.2`, want: []string{"198.51.100.2"}, wantErr: ip.ErrInvalidForwarded},
		{name: "empty for value returns partial result", header: `for=, for=198.51.100.2`, want: []string{"198.51.100.2"}, wantErr: ip.ErrInvalidForwarded},
		{name: "header without for parameter is ignored", header: `proto=https;by=10.0.0.1`, want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ip.ParseForwarded(tt.header)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
			assertAddrs(t, got, tt.want)
		})
	}
}

func TestParseXForwardedFor(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    []string
		wantErr error
	}{
		{name: "single ip", header: "192.0.2.1", want: []string{"192.0.2.1"}},
		{name: "multiple ips", header: "198.51.100.10, 192.0.2.1", want: []string{"198.51.100.10", "192.0.2.1"}},
		{name: "unknown then ip", header: "unknown, 192.0.2.1", want: []string{"192.0.2.1"}},
		{name: "only unknown", header: "unknown", want: nil},
		{name: "ipv6 with port", header: "[2001:db8::1]:443", want: []string{"2001:db8::1"}},
		{name: "bracketed ipv6 without port is invalid", header: "[2001:db8::1]", want: nil, wantErr: ip.ErrInvalidIP},
		{name: "malformed token returns partial result", header: "bad-token, 192.0.2.1", want: []string{"192.0.2.1"}, wantErr: ip.ErrInvalidIP},
		{name: "host port and empty tokens", header: " , 192.0.2.1:80 ,, 198.51.100.2 ", want: []string{"192.0.2.1", "198.51.100.2"}},
		{name: "keeps parsing after first malformed token", header: "bad-token, 192.0.2.1, still-bad, 198.51.100.2", want: []string{"192.0.2.1", "198.51.100.2"}, wantErr: ip.ErrInvalidIP},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ip.ParseXForwardedFor(tt.header)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
			assertAddrs(t, got, tt.want)
		})
	}
}

func TestErrorFormatting(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "header error bare", got: (&ip.HeaderError{Err: ip.ErrInvalidIP}).Error(), want: ip.ErrInvalidIP.Error()},
		{name: "header error with header", got: (&ip.HeaderError{Header: "X-Real-IP", Err: ip.ErrInvalidIP}).Error(), want: "X-Real-IP: " + ip.ErrInvalidIP.Error()},
		{name: "header error with value", got: (&ip.HeaderError{Header: "X-Real-IP", Value: "bad value", Err: ip.ErrInvalidIP}).Error(), want: `X-Real-IP "bad value": ` + ip.ErrInvalidIP.Error()},
		{name: "config error bare", got: (&ip.ConfigError{Err: ip.ErrInvalidConfig}).Error(), want: ip.ErrInvalidConfig.Error()},
		{name: "config error with option", got: (&ip.ConfigError{Option: "proxy mode", Err: ip.ErrInvalidConfig}).Error(), want: "proxy mode: " + ip.ErrInvalidConfig.Error()},
		{name: "config error with value", got: (&ip.ConfigError{Option: "proxy mode", Value: "bad", Err: ip.ErrInvalidConfig}).Error(), want: `proxy mode "bad": ` + ip.ErrInvalidConfig.Error()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, tt.got)
			}
		})
	}
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
			name:       "strict malformed Forwarded",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.Forwarded: {`for="[2001:db8::1"`},
			},
			wantErr: ip.ErrInvalidForwarded,
		},
		{
			name:       "permissive malformed Forwarded falls back",
			opts:       []ip.Option{ip.WithTrustedProxies("10.0.0.2")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.Forwarded:     {`for="[2001:db8::1"`},
				ip.XForwardedFor: {"198.51.100.10"},
			},
			wantIP: "198.51.100.10",
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
			name:       "strict unknown proxy chain rejected",
			opts:       []ip.Option{ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2", "10.0.0.1")},
			remoteAddr: "10.0.0.2:443",
			headers: map[string][]string{
				ip.XForwardedFor: {"unknown, 10.0.0.1"},
			},
			wantErr: ip.ErrUntrustedProxy,
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

type parseAddrCase struct {
	name            string
	input           string
	remoteWantIP    string
	remoteWantErr   bool
	addrPortWantIP  string
	addrPortWantErr bool
	addrWantIP      string
	addrWantErr     bool
}

func parseAddrCases() []parseAddrCase {
	return []parseAddrCase{
		{
			name:            "ipv4 hostport",
			input:           "192.0.2.1:80",
			remoteWantIP:    "192.0.2.1",
			addrPortWantIP:  "192.0.2.1",
			addrWantErr:     true,
			remoteWantErr:   false,
			addrPortWantErr: false,
		},
		{
			name:            "ipv6 hostport",
			input:           "[2001:db8::1]:443",
			remoteWantIP:    "2001:db8::1",
			addrPortWantIP:  "2001:db8::1",
			addrWantErr:     true,
			remoteWantErr:   false,
			addrPortWantErr: false,
		},
		{
			name:            "bare ipv4",
			input:           "198.51.100.4",
			remoteWantIP:    "198.51.100.4",
			addrPortWantErr: true,
			addrWantIP:      "198.51.100.4",
		},
		{
			name:            "bare ipv6 with zone",
			input:           "fe80::1%eth0",
			remoteWantIP:    "fe80::1",
			addrPortWantErr: true,
			addrWantIP:      "fe80::1",
		},
		{
			name:            "ipv6 hostport with zone",
			input:           "[fe80::1%eth0]:443",
			remoteWantIP:    "fe80::1",
			addrPortWantIP:  "fe80::1",
			addrWantErr:     true,
			remoteWantErr:   false,
			addrPortWantErr: false,
		},
		{
			name:            "garbage",
			input:           "bad",
			remoteWantErr:   true,
			addrPortWantErr: true,
			addrWantErr:     true,
		},
		{
			name:            "empty string",
			input:           "",
			remoteWantErr:   true,
			addrPortWantErr: true,
			addrWantErr:     true,
		},
		{
			name:            "bracketed ipv6 without port",
			input:           "[2001:db8::1]",
			remoteWantErr:   true,
			addrPortWantErr: true,
			addrWantErr:     true,
		},
	}
}

func runExtractCases(t *testing.T, run func(*testing.T, *ip.Extractor, extractTestCase) (netip.Addr, error)) {
	t.Helper()

	for _, tt := range extractTestCases() {
		t.Run(tt.name, func(t *testing.T) {
			ex := mustExtractor(t, tt.opts...)
			got, err := run(t, ex, tt)
			assertExtractResult(t, got, err, tt.wantIP, tt.wantErr, tt.errText)
		})
	}
}

func runParseAddrCases(t *testing.T, run func(string) (netip.Addr, error), wantIP func(parseAddrCase) string, wantErr func(parseAddrCase) bool) {
	t.Helper()

	for _, tt := range parseAddrCases() {
		t.Run(tt.name, func(t *testing.T) {
			got, err := run(tt.input)
			assertParseResult(t, got, err, wantIP(tt), wantErr(tt))
		})
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

func assertAddrs(t *testing.T, got []netip.Addr, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("expected %d IPs, got %d", len(want), len(got))
	}
	for i := range got {
		if got[i].String() != want[i] {
			t.Fatalf("expected IP[%d]=%q, got %q", i, want[i], got[i].String())
		}
	}
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

func assertParseResult(t *testing.T, got netip.Addr, err error, wantIP string, wantErr bool) {
	t.Helper()

	if (err != nil) != wantErr {
		t.Fatalf("expected err=%v, got %v", wantErr, err)
	}
	if !wantErr && got.String() != wantIP {
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
