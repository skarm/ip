package ip_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/skarm/ip"
)

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
		{name: "limit error", got: (&ip.LimitError{Limit: 4, Actual: 5, Err: ip.ErrTooManyHops}).Error(), want: ip.ErrTooManyHops.Error() + ": limit 4, actual 5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, tt.got)
			}
		})
	}
}

func TestHeaderErrorTruncatesOversizedValue(t *testing.T) {
	ex := mustExtractor(t, ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2"), ip.WithMaxHeaderBytes(2048), ip.WithMaxTokenBytes(1024))
	value := strings.Repeat("x", 1000)
	_, err := ex.ExtractFrom(map[string][]string{ip.XForwardedFor: {value}}, "10.0.0.2:443")
	if err == nil {
		t.Fatal("expected extraction error")
	}
	if len(err.Error()) > 400 {
		t.Fatalf("error text is not bounded: %d bytes", len(err.Error()))
	}
	if !strings.Contains(err.Error(), "1000 bytes") {
		t.Fatalf("error text %q does not report original length", err.Error())
	}
}

func TestHeaderErrorFormattingHandlesTruncatedSeparator(t *testing.T) {
	ex := mustExtractor(t,
		ip.WithStrict(),
		ip.WithTrustedProxies("10.0.0.2"),
		ip.WithHeaders(ip.XRealIP),
		ip.WithMaxHeaderBytes(1024),
		ip.WithMaxTokenBytes(1024),
	)
	values := []string{strings.Repeat("x", 255), "y"}

	_, err := ex.ExtractFrom(map[string][]string{ip.XRealIP: values}, "10.0.0.2:443")
	if !errors.Is(err, ip.ErrAmbiguousHeader) {
		t.Fatalf("ExtractFrom() error = %v, want ErrAmbiguousHeader", err)
	}
	if len(err.Error()) > 400 {
		t.Fatalf("error text is not bounded: %d bytes", len(err.Error()))
	}
}

func TestUntrustedErrorValuesAreBounded(t *testing.T) {
	t.Parallel()

	longValue := strings.Repeat("x", 1024)
	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "remote address",
			run: func() error {
				_, err := ip.Must(ip.New()).ExtractFrom(nil, longValue)
				return err
			},
		},
		{
			name: "single IP header",
			run: func() error {
				ex := ip.Must(ip.New(
					ip.WithStrict(),
					ip.WithTrustedProxies("10.0.0.2"),
					ip.WithHeaders(ip.XRealIP),
					ip.WithMaxTokenBytes(2048),
				))
				_, err := ex.ExtractFrom(map[string][]string{ip.XRealIP: {longValue}}, "10.0.0.2:443")
				return err
			},
		},
		{
			name: "chain boundary",
			run: func() error {
				ex := ip.Must(ip.New(
					ip.WithStrict(),
					ip.WithTrustedProxies("10.0.0.2"),
					ip.WithMaxTokenBytes(2048),
				))
				_, err := ex.ExtractFrom(map[string][]string{ip.XForwardedFor: {longValue}}, "10.0.0.2:443")
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.run()
			var headerErr *ip.HeaderError
			if !errors.As(err, &headerErr) {
				t.Fatalf("error = %v, want *HeaderError", err)
			}
			if len(headerErr.Value) > 300 {
				t.Fatalf("bounded value length = %d, want <= 300", len(headerErr.Value))
			}
			if !strings.Contains(headerErr.Value, "1024 bytes") {
				t.Fatalf("bounded value = %q, want original byte count", headerErr.Value)
			}
		})
	}
}
