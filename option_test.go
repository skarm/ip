package ip_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/skarm/ip"
)

func TestNewRejectsInvalidTrustedProxy(t *testing.T) {
	_, err := ip.New(ip.WithTrustedProxies("not-a-cidr"))
	if !errors.Is(err, ip.ErrInvalidTrustedProxy) {
		t.Fatalf("expected ErrInvalidTrustedProxy, got %v", err)
	}
}

func TestNewRejectsAllowListWithoutTrustedProxies(t *testing.T) {
	_, err := ip.New(ip.WithProxyMode(ip.ProxiesAllowedList))
	if !errors.Is(err, ip.ErrMissingTrustedProxies) {
		t.Fatalf("expected ErrMissingTrustedProxies, got %v", err)
	}
}

func TestProxyModeString(t *testing.T) {
	tests := []struct {
		mode ip.ProxyMode
		want string
	}{
		{mode: ip.ProxiesDenied, want: "ProxiesDenied"},
		{mode: ip.ProxiesAllowedList, want: "ProxiesAllowedList"},
		{mode: ip.ProxiesAllowedAll, want: "ProxiesAllowedAll"},
		{mode: ip.ProxyMode(99), want: "ProxyMode(99)"},
	}

	for _, tt := range tests {
		if got := tt.mode.String(); got != tt.want {
			t.Fatalf("mode %d: expected %q, got %q", tt.mode, tt.want, got)
		}
	}
}

func TestWithHeadersRejectsEmptyHeader(t *testing.T) {
	_, err := ip.New(ip.WithHeaders("X-Real-IP", ""))
	if !errors.Is(err, ip.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestWithProxyModeRejectsInvalidMode(t *testing.T) {
	_, err := ip.New(ip.WithProxyMode(ip.ProxyMode(99)))
	if !errors.Is(err, ip.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "ProxyMode(99)") {
		t.Fatalf("expected invalid mode value in error, got %v", err)
	}
}

func TestWithProxyModeAllowAll(t *testing.T) {
	ex, err := ip.New(ip.WithProxyMode(ip.ProxiesAllowedAll))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.RemoteAddr = "203.0.113.1:443"
	req.Header.Set(ip.XForwardedFor, "198.51.100.10")

	got, err := ex.Extract(req)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if got.String() != "198.51.100.10" {
		t.Fatalf("expected IP %q, got %q", "198.51.100.10", got.String())
	}
}

func TestWithHeadersClonesInputAndTreatsCustomHeaderAsSingleIP(t *testing.T) {
	headers := []string{"X-Custom-Ip"}
	ex, err := ip.New(
		ip.WithHeaders(headers...),
		ip.WithTrustedProxies("10.0.0.2"),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	headers[0] = "X-Other-Ip"

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set("X-Custom-Ip", "198.51.100.10")

	got, err := ex.Extract(req)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if got.String() != "198.51.100.10" {
		t.Fatalf("expected IP %q, got %q", "198.51.100.10", got.String())
	}
}

func TestWithHeadersDedupesLogicalHeaderNames(t *testing.T) {
	ex, err := ip.New(
		ip.WithStrict(),
		ip.WithHeaders(ip.XRealIP, "x-real-ip"),
		ip.WithTrustedProxies("10.0.0.2"),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header["X-Real-IP"] = []string{"198.51.100.10", "198.51.100.20"}

	_, err = ex.Extract(req)
	if !errors.Is(err, ip.ErrAmbiguousHeader) {
		t.Fatalf("expected ErrAmbiguousHeader, got %v", err)
	}
}

func TestMust(t *testing.T) {
	ex := ip.Must(ip.New(ip.WithProxyMode(ip.ProxiesDenied)))
	if ex == nil {
		t.Fatal("expected non-nil extractor")
	}
}

func TestMustPanicsOnInvalidConfig(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()

	_ = ip.Must(ip.New(ip.WithTrustedProxies("not-a-cidr")))
}

func TestProxyModeOptionsAreOrderIndependent(t *testing.T) {
	tests := []struct {
		name string
		opts []ip.Option
		want string
	}{
		{
			name: "allow all before trusted proxies",
			opts: []ip.Option{ip.WithProxyMode(ip.ProxiesAllowedAll), ip.WithTrustedProxies("10.0.0.2")},
			want: "198.51.100.10",
		},
		{
			name: "allow all after trusted proxies",
			opts: []ip.Option{ip.WithTrustedProxies("10.0.0.2"), ip.WithProxyMode(ip.ProxiesAllowedAll)},
			want: "198.51.100.10",
		},
		{
			name: "denied before trusted proxies",
			opts: []ip.Option{ip.WithProxyMode(ip.ProxiesDenied), ip.WithTrustedProxies("10.0.0.2")},
			want: "203.0.113.1",
		},
		{
			name: "denied after trusted proxies",
			opts: []ip.Option{ip.WithTrustedProxies("10.0.0.2"), ip.WithProxyMode(ip.ProxiesDenied)},
			want: "203.0.113.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex, err := ip.New(tt.opts...)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
			req.RemoteAddr = "203.0.113.1:443"
			req.Header.Set(ip.XForwardedFor, "198.51.100.10")

			got, err := ex.Extract(req)
			if err != nil {
				t.Fatalf("Extract() error = %v", err)
			}
			if got.String() != tt.want {
				t.Fatalf("Extract() = %v, want %s", got, tt.want)
			}
		})
	}
}

func TestWithHeadersRejectsInvalidFieldName(t *testing.T) {
	tests := []string{"X Bad", "X-Bad\nInjected", ":authority"}
	for _, header := range tests {
		t.Run(header, func(t *testing.T) {
			_, err := ip.New(ip.WithHeaders(header))
			if !errors.Is(err, ip.ErrInvalidConfig) {
				t.Fatalf("New() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestWithHeaderSpecsSupportsCustomProxyChain(t *testing.T) {
	ex, err := ip.New(
		ip.WithHeaderSpecs(ip.HeaderSpec{Name: "X-Proxy-Chain", Kind: ip.HeaderXForwardedFor}),
		ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set("X-Proxy-Chain", "198.51.100.10, 10.0.0.1")

	got, err := ex.Extract(req)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if got.String() != "198.51.100.10" {
		t.Fatalf("Extract() = %v, want 198.51.100.10", got)
	}
}

func TestWithHeaderSpecsRejectsInvalidKind(t *testing.T) {
	_, err := ip.New(ip.WithHeaderSpecs(ip.HeaderSpec{Name: "X-Client-IP", Kind: ip.HeaderKind(99)}))
	if !errors.Is(err, ip.ErrInvalidConfig) {
		t.Fatalf("New() error = %v, want ErrInvalidConfig", err)
	}
}

func TestLimitOptionsRejectNonPositiveValues(t *testing.T) {
	tests := []ip.Option{
		ip.WithMaxHeaderBytes(0),
		ip.WithMaxHeaderValues(0),
		ip.WithMaxHops(0),
		ip.WithMaxTokenBytes(0),
	}
	for i, option := range tests {
		if _, err := ip.New(option); !errors.Is(err, ip.ErrInvalidConfig) {
			t.Fatalf("option %d: New() error = %v, want ErrInvalidConfig", i, err)
		}
	}
}

func TestWithTrustedProxiesRejectsUnrepresentableMappedPrefix(t *testing.T) {
	t.Parallel()

	_, err := ip.New(ip.WithTrustedProxies("::ffff:0:0/80"))
	if !errors.Is(err, ip.ErrInvalidTrustedProxy) {
		t.Fatalf("New() error = %v, want ErrInvalidTrustedProxy", err)
	}
	var configErr *ip.ConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("New() error = %T, want *ConfigError", err)
	}
	if configErr.Value != "::ffff:0:0/80" {
		t.Fatalf("ConfigError.Value = %q", configErr.Value)
	}
}

func TestWithTrustedProxiesAcceptsExactPrefix(t *testing.T) {
	t.Parallel()

	ex, err := ip.New(ip.WithTrustedProxies("10.0.0.2/32"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	got, err := ex.ExtractFrom(
		map[string][]string{ip.XForwardedFor: {"198.51.100.10"}},
		"10.0.0.2:443",
	)
	if err != nil {
		t.Fatalf("ExtractFrom() error = %v", err)
	}
	if got != netip.MustParseAddr("198.51.100.10") {
		t.Fatalf("ExtractFrom() = %v, want 198.51.100.10", got)
	}
}
