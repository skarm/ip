package ip_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/skarm/ip"
)

func TestMiddlewareStoresExtractedIP(t *testing.T) {
	ex := mustExtractor(t, ip.WithTrustedProxies("10.0.0.2"))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set(ip.XForwardedFor, "198.51.100.10")

	var got netip.Addr
	handler := ex.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = ip.Ctx(r.Context())
	}))

	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got.String() != "198.51.100.10" {
		t.Fatalf("expected middleware IP %q, got %q", "198.51.100.10", got.String())
	}
}
