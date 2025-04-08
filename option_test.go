package ip_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skarm/ip"
)

func TestWithHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		req     *http.Request
		want    string
		wantOK  bool
	}{
		{
			name:    "custom header present",
			headers: []string{"X-Custom-IP"},
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Set("X-Custom-IP", "192.0.2.100")
				r.RemoteAddr = "203.0.113.1:12345"
				return r
			}(),
			want:   "192.0.2.100",
			wantOK: true,
		},
		{
			name:    "custom header with invalid IP",
			headers: []string{"X-Custom-IP"},
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Set("X-Custom-IP", "not-an-ip")
				r.RemoteAddr = "203.0.113.1:12345"
				return r
			}(),
			want:   "203.0.113.1",
			wantOK: true,
		},
		{
			name:    "header not present",
			headers: []string{"X-Does-Not-Exist"},
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.RemoteAddr = "203.0.113.2:4567"
				return r
			}(),
			want:   "203.0.113.2",
			wantOK: true,
		},
		{
			name:    "empty header list",
			headers: []string{},
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.RemoteAddr = "203.0.113.3:7890"
				return r
			}(),
			want:   "203.0.113.3",
			wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := ip.New(ip.WithHeaders(tt.headers...))
			got, ok := ex.FromRequest(tt.req)
			if ok != tt.wantOK {
				t.Errorf("expected ok: %v, got: %v", tt.wantOK, ok)
			}
			if got.String() != tt.want {
				t.Errorf("expected IP: %q, got: %q", tt.want, got.String())
			}
		})
	}
}

func TestWithTrustedProxies(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		xForwardedFor  string
		want           string
		wantOK         bool
	}{
		{
			name:           "trusted proxy honors X-Forwarded-For",
			trustedProxies: []string{"127.0.0.1"},
			remoteAddr:     "127.0.0.1:1234",
			xForwardedFor:  "198.51.100.5",
			want:           "198.51.100.5",
			wantOK:         true,
		},
		{
			name:           "untrusted proxy ignores X-Forwarded-For",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "192.168.1.1:5678",
			xForwardedFor:  "198.51.100.6",
			want:           "192.168.1.1",
			wantOK:         true,
		},
		{
			name:           "trusted proxy with malformed X-Forwarded-For",
			trustedProxies: []string{"127.0.0.1"},
			remoteAddr:     "127.0.0.1:4321",
			xForwardedFor:  "not-an-ip",
			want:           "127.0.0.1",
			wantOK:         true,
		},
		{
			name:           "empty trusted proxy list (all trusted)",
			trustedProxies: []string{},
			remoteAddr:     "127.0.0.1:8080",
			xForwardedFor:  "203.0.113.9",
			want:           "203.0.113.9",
			wantOK:         true,
		},
		{
			name:           "no X-Forwarded-For present",
			trustedProxies: []string{"127.0.0.1"},
			remoteAddr:     "127.0.0.1:8080",
			xForwardedFor:  "",
			want:           "127.0.0.1",
			wantOK:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := ip.New(ip.WithTrustedProxies(tt.trustedProxies...))
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			got, ok := ex.FromRequest(req)
			if ok != tt.wantOK {
				t.Errorf("expected ok: %v, got: %v", tt.wantOK, ok)
			}
			if got.String() != tt.want {
				t.Errorf("expected IP: %q, got: %q", tt.want, got.String())
			}
		})
	}
}
