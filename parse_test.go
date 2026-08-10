package ip_test

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/skarm/ip"
)

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
		{name: "escaped quoted string with comma", header: `for="198.51.100.17";extension="proxy\,1", for=192.0.2.1`, want: []string{"198.51.100.17", "192.0.2.1"}},
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
		{name: "duplicate by parameter is invalid", header: `for=192.0.2.1;by=10.0.0.1;BY=10.0.0.2`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "duplicate extension after inline parameter set is invalid", header: `for=192.0.2.1;a=1;b=2;c=3;d=4;e=5;f=6;g=7;h=8;A=9`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "invalid parameter name is rejected", header: `bad key=value;for=192.0.2.1`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "invalid unquoted value is rejected", header: `for=192.0.2.1;proto=https bad`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "quoted pair is unescaped", header: `for="192.0.2.1";extension="a\,b"`, want: []string{"192.0.2.1"}},
		{name: "known parameters use their RFC grammars", header: `for=192.0.2.1;by="[2001:db8::2]:443";host="example.com:8443";proto=https`, want: []string{"192.0.2.1"}},
		{name: "omitted forwarded pairs are accepted", header: `;for=192.0.2.1;;`, want: []string{"192.0.2.1"}},
		{name: "six digit node port is rejected", header: `for="192.0.2.1:123456", for=198.51.100.2`, want: []string{"198.51.100.2"}, wantErr: ip.ErrInvalidForwarded},
		{name: "invalid by value is rejected", header: `for=192.0.2.1;by="not/a"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "invalid host value is rejected", header: `for=192.0.2.1;host="example.com:not-a-port"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "invalid proto value is rejected", header: `for=192.0.2.1;proto="not/a"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "whitespace before equals is rejected", header: `for =192.0.2.1`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "whitespace after equals is rejected", header: `for= 192.0.2.1`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "whitespace before semicolon is rejected", header: `for=192.0.2.1 ;proto=https`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "whitespace after semicolon is rejected", header: `for=192.0.2.1; proto=https`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "zoned ipv6 node is rejected", header: `for="[fe80::1%eth0]"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "quoted node whitespace is significant", header: `for=" 192.0.2.1 "`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "non OWS around an element is rejected", header: "\rfor=192.0.2.1", want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "empty quoted for node is rejected", header: `for=""`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "bracketed node trailing data is rejected", header: `for="[2001:db8::1]x"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "empty node port is rejected", header: `for="192.0.2.1:"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "invalid obfuscated node port is rejected", header: `for="192.0.2.1:_bad!"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "invalid numeric node port is rejected", header: `for="192.0.2.1:12a"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "invalid bracketed node port is rejected", header: `for="[2001:db8::1]:http"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "unbracketed IPv6 node is rejected", header: `for=2001:db8::1`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "quoted unbracketed IPv6 node is rejected", header: `for="2001:db8::1"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "short obfuscated node is rejected", header: `for=_`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "IPv6 host without port is accepted", header: `for=192.0.2.1;host="[2001:db8::2]"`, want: []string{"192.0.2.1"}},
		{name: "IPv6 host with empty port is accepted", header: `for=192.0.2.1;host="[2001:db8::2]:"`, want: []string{"192.0.2.1"}},
		{name: "IPv6 host rejects invalid port", header: `for=192.0.2.1;host="[2001:db8::2]:http"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "host rejects empty bracketed literal", header: `for=192.0.2.1;host="[]"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "host rejects unterminated bracketed literal", header: `for=192.0.2.1;host="[2001:db8::2"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "host rejects non-IP short bracketed literal", header: `for=192.0.2.1;host="[x]"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "IPvFuture host is accepted", header: `for=192.0.2.1;host="[v1.fe80::a]"`, want: []string{"192.0.2.1"}},
		{name: "IPvFuture host requires version digits", header: `for=192.0.2.1;host="[v.fe80]"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "IPvFuture host requires address text", header: `for=192.0.2.1;host="[v12.]"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "IPvFuture host rejects invalid characters", header: `for=192.0.2.1;host="[v1.fe80^]"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "registered host accepts percent encoding and sub-delimiters", header: `for=192.0.2.1;host="example%2Ecom!$&'()*+;="`, want: []string{"192.0.2.1"}},
		{name: "registered host rejects invalid percent encoding", header: `for=192.0.2.1;host="example%ZZ.com"`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "empty proto is rejected", header: `for=192.0.2.1;proto=""`, want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "extended URI scheme is accepted", header: `for=192.0.2.1;proto=git+ssh-1.0`, want: []string{"192.0.2.1"}},
		{name: "dangling quoted escape is rejected", header: "for=192.0.2.1;extension=\"bad\\", want: nil, wantErr: ip.ErrInvalidForwarded},
		{name: "quoted control character is rejected", header: "for=192.0.2.1;extension=\"bad\x01value\"", want: nil, wantErr: ip.ErrInvalidForwarded},
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
		{name: "host port and empty tokens", header: " , 192.0.2.1:80 ,, 198.51.100.2 ", want: []string{"192.0.2.1", "198.51.100.2"}, wantErr: ip.ErrInvalidIP},
		{name: "keeps parsing after first malformed token", header: "bad-token, 192.0.2.1, still-bad, 198.51.100.2", want: []string{"192.0.2.1", "198.51.100.2"}, wantErr: ip.ErrInvalidIP},
		{name: "whitespace does not delimit hops", header: "198.51.100.10 10.0.0.1", want: nil, wantErr: ip.ErrInvalidIP},
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

func TestStandaloneParsersHandleLongLists(t *testing.T) {
	forwarded := make([]string, 9)
	xForwardedFor := make([]string, 9)
	for i := range forwarded {
		addr := fmt.Sprintf("192.0.2.%d", i+1)
		forwarded[i] = "for=" + addr
		xForwardedFor[i] = addr
	}

	tests := []struct {
		name  string
		value string
		parse func(string) ([]netip.Addr, error)
	}{
		{name: "Forwarded", value: strings.Join(forwarded, ", "), parse: ip.ParseForwarded},
		{name: "X-Forwarded-For", value: strings.Join(xForwardedFor, ", "), parse: ip.ParseXForwardedFor},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.parse(tt.value)
			if err != nil {
				t.Fatalf("parse error = %v", err)
			}
			if len(got) != 9 {
				t.Fatalf("address count = %d, want 9", len(got))
			}
		})
	}
}

func TestStandaloneParsersEnforceHopAndTokenLimits(t *testing.T) {
	forwardedHops := strings.Repeat("for=192.0.2.1,", ip.DefaultMaxHops) + "for=192.0.2.1"
	xForwardedForHops := strings.Repeat("192.0.2.1,", ip.DefaultMaxHops) + "192.0.2.1"
	longToken := strings.Repeat("x", ip.DefaultMaxTokenBytes+1)

	tests := []struct {
		name    string
		value   string
		parse   func(string) ([]netip.Addr, error)
		wantErr error
	}{
		{name: "Forwarded hops", value: forwardedHops, parse: ip.ParseForwarded, wantErr: ip.ErrTooManyHops},
		{name: "X-Forwarded-For hops", value: xForwardedForHops, parse: ip.ParseXForwardedFor, wantErr: ip.ErrTooManyHops},
		{name: "Forwarded token", value: "for=" + longToken, parse: ip.ParseForwarded, wantErr: ip.ErrTokenTooLarge},
		{name: "X-Forwarded-For token", value: longToken, parse: ip.ParseXForwardedFor, wantErr: ip.ErrTokenTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.parse(tt.value)
			if len(got) != 0 {
				t.Fatalf("addresses = %v, want none", got)
			}
			if !errors.Is(err, ip.ErrLimitExceeded) || !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want ErrLimitExceeded and %v", err, tt.wantErr)
			}
		})
	}
}

func TestStandaloneParsersEnforceAggregateLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		parse func(string) ([]netip.Addr, error)
	}{
		{name: "Forwarded", parse: ip.ParseForwarded},
		{name: "X-Forwarded-For", parse: ip.ParseXForwardedFor},
	}

	value := strings.Repeat("x", ip.DefaultMaxHeaderBytes+1)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			addrs, err := tt.parse(value)
			if addrs != nil {
				t.Fatalf("addresses = %v, want nil", addrs)
			}
			if !errors.Is(err, ip.ErrLimitExceeded) || !errors.Is(err, ip.ErrHeaderTooLarge) {
				t.Fatalf("error = %v, want aggregate limit errors", err)
			}
			var limitErr *ip.LimitError
			if !errors.As(err, &limitErr) || limitErr.Limit != ip.DefaultMaxHeaderBytes || limitErr.Actual != len(value) {
				t.Fatalf("limit error = %+v", limitErr)
			}
		})
	}
}

type parseAddrCase struct {
	name            string
	input           string
	remoteWantIP    string
	addrPortWantIP  string
	addrWantIP      string
	remoteWantErr   bool
	addrPortWantErr bool
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
			name:            "ipv4 mapped bare address is unmapped",
			input:           "::ffff:198.51.100.4",
			remoteWantIP:    "198.51.100.4",
			addrPortWantErr: true,
			addrWantIP:      "198.51.100.4",
		},
		{
			name:           "ipv4 mapped hostport is unmapped",
			input:          "[::ffff:198.51.100.4]:443",
			remoteWantIP:   "198.51.100.4",
			addrPortWantIP: "198.51.100.4",
			addrWantErr:    true,
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

func runParseAddrCases(t *testing.T, run func(string) (netip.Addr, error), wantIP func(parseAddrCase) string, wantErr func(parseAddrCase) bool) {
	t.Helper()

	for _, tt := range parseAddrCases() {
		t.Run(tt.name, func(t *testing.T) {
			got, err := run(tt.input)
			assertParseResult(t, got, err, wantIP(tt), wantErr(tt))
		})
	}
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

func assertParseResult(t *testing.T, got netip.Addr, err error, wantIP string, wantErr bool) {
	t.Helper()

	if (err != nil) != wantErr {
		t.Fatalf("expected err=%v, got %v", wantErr, err)
	}
	if !wantErr && got.String() != wantIP {
		t.Fatalf("expected %q, got %q", wantIP, got.String())
	}
}
