package ip_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/skarm/ip"
)

func TestMiddlewareStoresExtractedIP(t *testing.T) {
	ex := mustExtractor(t, ip.WithTrustedProxies("10.0.0.2"))

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set(ip.XForwardedFor, "198.51.100.10")

	var got netip.Addr
	handler := ex.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = ip.Ctx(r.Context())
	}))

	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got.String() != "198.51.100.10" {
		t.Fatalf("expected middleware IP %q, got %q", "198.51.100.10", got.String())
	}
}

func TestMiddlewareContinuesOnExtractError(t *testing.T) {
	ex := mustExtractor(t, ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2"))
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set(ip.XForwardedFor, "not-an-ip")

	called := false
	handler := ex.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !called {
		t.Fatal("expected best-effort middleware to call next")
	}
}

func TestMiddlewareWithErrorHandlerReceivesExtractError(t *testing.T) {
	ex := mustExtractor(t, ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2"))
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set(ip.XForwardedFor, "not-an-ip")

	var gotErr error
	handler := ex.MiddlewareWithErrorHandler(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("next must not be called")
		}),
		func(w http.ResponseWriter, _ *http.Request, err error) {
			gotErr = err
			w.WriteHeader(http.StatusUnprocessableEntity)
		},
	)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if !errors.Is(gotErr, ip.ErrInvalidIP) {
		t.Fatalf("error = %v, want ErrInvalidIP", gotErr)
	}
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnprocessableEntity)
	}
}

func TestMiddlewareWithErrorHandlerStoresExtractedIP(t *testing.T) {
	ex := mustExtractor(t, ip.WithTrustedProxies("10.0.0.2"))
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set(ip.XForwardedFor, "198.51.100.10")

	var got netip.Addr
	handler := ex.MiddlewareWithErrorHandler(
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got, _ = ip.Ctx(r.Context())
		}),
		func(http.ResponseWriter, *http.Request, error) {
			t.Fatal("error handler must not be called")
		},
	)

	handler.ServeHTTP(httptest.NewRecorder(), req)

	want := netip.MustParseAddr("198.51.100.10")
	if got != want {
		t.Fatalf("context address = %v, want %v", got, want)
	}
}

func TestMiddlewareWithErrorHandlerPanicsOnNil(t *testing.T) {
	ex := mustExtractor(t)

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for nil error handler")
		}
	}()

	ex.MiddlewareWithErrorHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), nil)
}
