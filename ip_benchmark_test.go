package ip

import (
	"net/http"
	"net/netip"
	"testing"
)

var (
	benchDefaultExtractor    = Must(New())
	benchAllowListExtractor  = Must(New(WithTrustedProxies("10.0.0.2", "10.0.0.1")))
	benchAllowAllExtractor   = Must(New(WithUnsafeTrustAllProxies()))
	benchStrictListExtractor = Must(New(WithStrict(), WithTrustedProxies("10.0.0.2", "10.0.0.1")))
	benchWantDefaultIP       = netip.MustParseAddr("203.0.113.20")
	benchWantClientIP        = netip.MustParseAddr("198.51.100.24")
	benchWantForwardedClient = netip.MustParseAddr("2001:db8::10")
)

func BenchmarkExtractorExtract(b *testing.B) {
	b.Run("http/default_no_proxy_headers", func(b *testing.B) {
		req := &http.Request{
			Header: http.Header{
				"User-Agent":      {"benchmark-client/1.0"},
				"Accept":          {"application/json"},
				"Accept-Encoding": {"gzip, br"},
				"Authorization":   {"Bearer test-token"},
				"Cookie":          {"session=abc123; pref=light"},
				"Traceparent":     {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"},
				"X-Request-Id":    {"8dbdfc5c-f0b2-4337-a6b2-58442ba6f2a5"},
			},
			RemoteAddr: "203.0.113.20:443",
		}

		benchmarkExtractRequest(b, benchDefaultExtractor, req, benchWantDefaultIP)
	})

	b.Run("http/allow_list_x_forwarded_for_chain", func(b *testing.B) {
		req := &http.Request{
			Header: http.Header{
				"X-Forwarded-For":   {"198.51.100.24, 10.0.0.1"},
				"X-Forwarded-Proto": {"https"},
				"X-Forwarded-Host":  {"api.example.com"},
				"User-Agent":        {"benchmark-client/1.0"},
				"Accept":            {"application/json"},
				"Accept-Encoding":   {"gzip, br"},
				"Traceparent":       {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"},
				"X-Request-Id":      {"7b4181d2-c9ab-4b60-98d9-8ca2a7a3d85f"},
			},
			RemoteAddr: "10.0.0.2:443",
		}

		benchmarkExtractRequest(b, benchAllowListExtractor, req, benchWantClientIP)
	})

	b.Run("http/allow_all_forwarded_ipv6", func(b *testing.B) {
		req := &http.Request{
			Header: http.Header{
				"Forwarded":             {`for="[2001:db8::10]:1234";proto=https;by=10.0.0.2`},
				"X-Forwarded-Proto":     {"https"},
				"X-Forwarded-Host":      {"api.example.com"},
				"User-Agent":            {"benchmark-client/1.0"},
				"Accept":                {"application/json"},
				"Accept-Language":       {"en-US,en;q=0.9"},
				"Cache-Control":         {"no-cache"},
				"X-Cloud-Trace-Context": {"105445aa7843bc8bf206b120001000/1;o=1"},
			},
			RemoteAddr: "203.0.113.20:443",
		}

		benchmarkExtractRequest(b, benchAllowAllExtractor, req, benchWantForwardedClient)
	})
}

func BenchmarkExtractorExtractFrom(b *testing.B) {
	b.Run("grpc/default_no_proxy_headers", func(b *testing.B) {
		headers := map[string][]string{
			"content-type": {"application/grpc"},
			"user-agent":   {"grpc-go/1.72.0"},
			"grpc-timeout": {"150m"},
			"x-request-id": {"c80e878e-81dd-48b0-80b9-63585cd24f7a"},
			"traceparent":  {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"},
		}

		benchmarkExtractHeaders(b, benchDefaultExtractor, headers, "203.0.113.20:8443", benchWantDefaultIP)
	})

	b.Run("grpc/allow_list_x_forwarded_for_chain", func(b *testing.B) {
		headers := map[string][]string{
			"x-forwarded-for":   {"198.51.100.24, 10.0.0.1"},
			"x-forwarded-proto": {"https"},
			"x-forwarded-host":  {"grpc.example.internal"},
			"content-type":      {"application/grpc"},
			"user-agent":        {"grpc-go/1.72.0"},
			"grpc-timeout":      {"150m"},
			"x-request-id":      {"6ceef326-f8df-4a22-bff2-73dbefc4e4ab"},
			"traceparent":       {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"},
		}

		benchmarkExtractHeaders(b, benchAllowListExtractor, headers, "10.0.0.2:8443", benchWantClientIP)
	})

	b.Run("grpc/allow_all_forwarded_ipv6", func(b *testing.B) {
		headers := map[string][]string{
			"forwarded":         {`for="[2001:db8::10]:1234";proto=https;by=10.0.0.2`},
			"x-forwarded-proto": {"https"},
			"x-forwarded-host":  {"grpc.example.internal"},
			"content-type":      {"application/grpc"},
			"user-agent":        {"grpc-go/1.72.0"},
			"grpc-timeout":      {"150m"},
			"x-request-id":      {"ddb9122c-01af-447d-b77a-9b41d159af5d"},
			"traceparent":       {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"},
		}

		benchmarkExtractHeaders(b, benchAllowAllExtractor, headers, "203.0.113.20:8443", benchWantForwardedClient)
	})

	b.Run("grpc/strict_ambiguous_duplicate_proxy_header", func(b *testing.B) {
		headers := map[string][]string{
			"X-Forwarded-For":   {"198.51.100.24"},
			"x-forwarded-for":   {"203.0.113.55"},
			"x-forwarded-proto": {"https"},
			"content-type":      {"application/grpc"},
			"user-agent":        {"grpc-go/1.72.0"},
			"grpc-timeout":      {"150m"},
		}

		b.ReportAllocs()
		for b.Loop() {
			_, err := benchStrictListExtractor.ExtractFrom(headers, "10.0.0.2:8443")
			if err == nil {
				b.Fatal("expected error")
			}
		}
	})
}

func benchmarkExtractRequest(b *testing.B, ex *Extractor, req *http.Request, want netip.Addr) {
	b.ReportAllocs()
	for b.Loop() {
		got, err := ex.Extract(req)
		if err != nil {
			b.Fatalf("Extract() error = %v", err)
		}
		if got != want {
			b.Fatalf("Extract() = %v, want %v", got, want)
		}
	}
}

func benchmarkExtractHeaders(b *testing.B, ex *Extractor, headers map[string][]string, remoteAddr string, want netip.Addr) {
	b.ReportAllocs()
	for b.Loop() {
		got, err := ex.ExtractFrom(headers, remoteAddr)
		if err != nil {
			b.Fatalf("ExtractFrom() error = %v", err)
		}
		if got != want {
			b.Fatalf("ExtractFrom() = %v, want %v", got, want)
		}
	}
}
