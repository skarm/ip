package ip_test

import (
	"errors"
	"testing"

	"github.com/skarm/ip"
)

func TestPermissiveProxyChainStopsAtUnverifiableBoundary(t *testing.T) {
	tests := []struct {
		name   string
		header string
		value  string
	}{
		{name: "malformed X-Forwarded-For", header: ip.XForwardedFor, value: "198.51.100.7, not-an-ip, 10.0.0.1"},
		{name: "unknown X-Forwarded-For", header: ip.XForwardedFor, value: "198.51.100.7, unknown, 10.0.0.1"},
		{name: "malformed Forwarded", header: ip.Forwarded, value: `for=198.51.100.7, for="[bad", for=10.0.0.1`},
		{name: "obfuscated Forwarded", header: ip.Forwarded, value: `for=198.51.100.7, for=_hidden, for=10.0.0.1`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := mustExtractor(t, ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"))
			got, err := ex.ExtractFrom(map[string][]string{tt.header: {tt.value}}, "10.0.0.2:443")
			if err != nil {
				t.Fatalf("ExtractFrom() error = %v", err)
			}
			if got.String() != "10.0.0.2" {
				t.Fatalf("ExtractFrom() = %v, want immediate remote 10.0.0.2", got)
			}
		})
	}
}

func TestForwardedElementWithoutForIsTrustBoundary(t *testing.T) {
	t.Parallel()

	headers := func(prefix string) map[string][]string {
		return map[string][]string{
			ip.Forwarded: {"for=" + prefix + ", by=203.0.113.9;proto=https, for=10.0.0.1"},
		}
	}

	t.Run("permissive", func(t *testing.T) {
		t.Parallel()

		ex := mustExtractor(t, ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"))
		for _, prefix := range []string{"198.51.100.7", "192.0.2.55"} {
			result, err := ex.ExtractResultFrom(headers(prefix), "10.0.0.2:443")
			if err != nil {
				t.Fatalf("ExtractResultFrom(%q) error = %v", prefix, err)
			}
			if result.Addr.String() != "10.0.0.2" || result.Reason != ip.ReasonUnverifiableChain {
				t.Fatalf("ExtractResultFrom(%q) = %+v, want transport-peer fallback", prefix, result)
			}
		}
	})

	t.Run("strict", func(t *testing.T) {
		t.Parallel()

		ex := mustExtractor(t, ip.WithStrict(), ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"))
		_, err := ex.ExtractResultFrom(headers("198.51.100.7"), "10.0.0.2:443")
		if !errors.Is(err, ip.ErrUnverifiableChain) {
			t.Fatalf("ExtractResultFrom() error = %v, want ErrUnverifiableChain", err)
		}
	})
}

func TestMalformedForwardedHopIsTrustBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hop  string
	}{
		{name: "six digit node port", hop: `for="10.0.0.1:123456"`},
		{name: "invalid by", hop: `for=10.0.0.1;by="not/a"`},
		{name: "invalid host", hop: `for=10.0.0.1;host="example.com:not-a-port"`},
		{name: "invalid proto", hop: `for=10.0.0.1;proto="not/a"`},
		{name: "whitespace around equals", hop: `for = 10.0.0.1`},
		{name: "whitespace before semicolon", hop: `for=10.0.0.1 ;proto=https`},
		{name: "whitespace after semicolon", hop: `for=10.0.0.1; proto=https`},
		{name: "zoned ipv6", hop: `for="[fe80::1%eth0]"`},
		{name: "quoted node whitespace", hop: `for=" 10.0.0.1 "`},
		{name: "non OWS before element", hop: "\rfor=10.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			headers := map[string][]string{
				ip.Forwarded: {"for=198.51.100.7, " + tt.hop},
			}

			t.Run("permissive", func(t *testing.T) {
				t.Parallel()

				ex := mustExtractor(t, ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"))
				result, err := ex.ExtractResultFrom(headers, "10.0.0.2:443")
				if err != nil {
					t.Fatalf("ExtractResultFrom() error = %v", err)
				}
				if result.Addr.String() != "10.0.0.2" || result.Reason != ip.ReasonUnverifiableChain {
					t.Fatalf("ExtractResultFrom() = %+v, want transport-peer fallback", result)
				}
			})

			t.Run("strict", func(t *testing.T) {
				t.Parallel()

				ex := mustExtractor(t, ip.WithStrict(), ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"))
				_, err := ex.ExtractResultFrom(headers, "10.0.0.2:443")
				if !errors.Is(err, ip.ErrInvalidForwarded) {
					t.Fatalf("ExtractResultFrom() error = %v, want ErrInvalidForwarded", err)
				}
			})
		})
	}
}

func TestEmptyForwardedElementIsTrustBoundary(t *testing.T) {
	t.Parallel()

	headers := map[string][]string{
		ip.Forwarded: {"for=198.51.100.7, , for=10.0.0.1"},
	}

	t.Run("permissive", func(t *testing.T) {
		t.Parallel()

		ex := mustExtractor(t, ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"))
		result, err := ex.ExtractResultFrom(headers, "10.0.0.2:443")
		if err != nil {
			t.Fatalf("ExtractResultFrom() error = %v", err)
		}
		if result.Addr.String() != "10.0.0.2" || result.Reason != ip.ReasonUnverifiableChain {
			t.Fatalf("ExtractResultFrom() = %+v, want transport-peer fallback", result)
		}
	})

	t.Run("strict", func(t *testing.T) {
		t.Parallel()

		ex := mustExtractor(t, ip.WithStrict(), ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"))
		_, err := ex.ExtractResultFrom(headers, "10.0.0.2:443")
		if !errors.Is(err, ip.ErrUnverifiableChain) {
			t.Fatalf("ExtractResultFrom() error = %v, want ErrUnverifiableChain", err)
		}
	})
}

func TestNonOWSXForwardedForWhitespaceIsTrustBoundary(t *testing.T) {
	t.Parallel()

	headers := map[string][]string{
		ip.XForwardedFor: {"198.51.100.7, \r10.0.0.1"},
	}

	t.Run("permissive", func(t *testing.T) {
		t.Parallel()

		ex := mustExtractor(t, ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"))
		result, err := ex.ExtractResultFrom(headers, "10.0.0.2:443")
		if err != nil {
			t.Fatalf("ExtractResultFrom() error = %v", err)
		}
		if result.Addr.String() != "10.0.0.2" || result.Reason != ip.ReasonUnverifiableChain {
			t.Fatalf("ExtractResultFrom() = %+v, want transport-peer fallback", result)
		}
	})

	t.Run("strict", func(t *testing.T) {
		t.Parallel()

		ex := mustExtractor(t, ip.WithStrict(), ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"))
		_, err := ex.ExtractResultFrom(headers, "10.0.0.2:443")
		if !errors.Is(err, ip.ErrInvalidIP) {
			t.Fatalf("ExtractResultFrom() error = %v, want ErrInvalidIP", err)
		}
	})
}

func TestEmptyXForwardedForElementIsTrustBoundary(t *testing.T) {
	t.Parallel()

	headers := func(prefix string) map[string][]string {
		return map[string][]string{
			ip.XForwardedFor: {prefix + ", , 10.0.0.1"},
		}
	}

	t.Run("permissive", func(t *testing.T) {
		t.Parallel()

		ex := mustExtractor(t, ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"))
		for _, prefix := range []string{"198.51.100.7", "192.0.2.55"} {
			result, err := ex.ExtractResultFrom(headers(prefix), "10.0.0.2:443")
			if err != nil {
				t.Fatalf("ExtractResultFrom(%q) error = %v", prefix, err)
			}
			if result.Addr.String() != "10.0.0.2" || result.Reason != ip.ReasonUnverifiableChain {
				t.Fatalf("ExtractResultFrom(%q) = %+v, want transport-peer fallback", prefix, result)
			}
		}
	})

	t.Run("strict", func(t *testing.T) {
		t.Parallel()

		ex := mustExtractor(t, ip.WithStrict(), ip.WithTrustedProxies("10.0.0.1", "10.0.0.2"))
		_, err := ex.ExtractResultFrom(headers("198.51.100.7"), "10.0.0.2:443")
		if !errors.Is(err, ip.ErrInvalidIP) {
			t.Fatalf("ExtractResultFrom() error = %v, want ErrInvalidIP", err)
		}
	})
}

func TestUnverifiableSingleIPHeaderStopsFallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
	}{
		{name: "malformed", values: []string{"bad-ip"}},
		{name: "unknown", values: []string{"unknown"}},
		{name: "ambiguous", values: []string{"198.51.100.7", "192.0.2.55"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ex := mustExtractor(t,
				ip.WithTrustedProxies("10.0.0.2"),
				ip.WithHeaders(ip.XRealIP, ip.XClientIP),
			)
			result, err := ex.ExtractResultFrom(map[string][]string{
				ip.XRealIP:   tt.values,
				ip.XClientIP: {"203.0.113.99"},
			}, "10.0.0.2:443")
			if err != nil {
				t.Fatalf("ExtractResultFrom() error = %v", err)
			}
			if result.Addr.String() != "10.0.0.2" || result.Header != ip.XRealIP || result.Reason != ip.ReasonUnverifiableChain {
				t.Fatalf("ExtractResultFrom() = %+v, want X-Real-IP boundary fallback", result)
			}
		})
	}
}

func TestStrictUnknownSingleIPHeaderIsRejected(t *testing.T) {
	t.Parallel()

	ex := mustExtractor(t,
		ip.WithStrict(),
		ip.WithTrustedProxies("10.0.0.2"),
		ip.WithHeaders(ip.XRealIP),
	)
	_, err := ex.ExtractResultFrom(map[string][]string{ip.XRealIP: {"unknown"}}, "10.0.0.2:443")
	if !errors.Is(err, ip.ErrUnverifiableChain) {
		t.Fatalf("ExtractResultFrom() error = %v, want ErrUnverifiableChain", err)
	}
}
