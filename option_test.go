package ip_test

import (
	"errors"
	"net/http/httptest"
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

	req := httptest.NewRequest("GET", "/", nil)
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
	headers := []string{"X-Custom-IP"}
	ex, err := ip.New(
		ip.WithHeaders(headers...),
		ip.WithTrustedProxies("10.0.0.2"),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	headers[0] = "X-Other-IP"

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set("X-Custom-IP", "198.51.100.10")

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

	req := httptest.NewRequest("GET", "/", nil)
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

func TestMustWithStrictOption(t *testing.T) {
	ex := ip.Must(ip.New(ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2")))
	if ex == nil {
		t.Fatal("expected non-nil extractor")
	}
}
