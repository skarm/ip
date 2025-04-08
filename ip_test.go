package ip_test

import (
	"context"
	"net/http"
	"net/netip"
	"testing"

	"github.com/skarm/ip"
)

func TestExtractor_FromRequest(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddr     string
		headers        map[string]string
		trustedProxies []string
		wantIP         string
		ok             bool
	}{
		{
			name:           "untrusted direct",
			remoteAddr:     "203.0.113.1:12345",
			headers:        nil,
			trustedProxies: []string{"127.0.0.0/8"},
			wantIP:         "203.0.113.1",
			ok:             true,
		},
		{
			name:       "trusted proxy with X-Forwarded-For",
			remoteAddr: "127.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "198.51.100.100, 127.0.0.1",
			},
			trustedProxies: []string{"127.0.0.1"},
			wantIP:         "198.51.100.100",
			ok:             true,
		},
		{
			name:       "trusted proxy with bad X-Forwarded-For",
			remoteAddr: "127.0.0.1:12345",
			headers: map[string]string{
				"X-Forwarded-For": "not_an_ip",
			},
			trustedProxies: []string{"127.0.0.1"},
			wantIP:         "127.0.0.1",
			ok:             true,
		},
		{
			name:       "trusted proxy with Forwarded",
			remoteAddr: "192.0.2.1:12345",
			headers: map[string]string{
				"Forwarded": `for=192.0.2.60:443; proto=http; by=192.0.2.1`,
			},
			trustedProxies: []string{"192.0.2.1"},
			wantIP:         "192.0.2.60",
			ok:             true,
		},
		{
			name:       "trusted proxy with X-Real-IP",
			remoteAddr: "127.0.0.1:12345",
			headers: map[string]string{
				"X-Real-IP": "192.0.2.1",
			},
			trustedProxies: []string{"127.0.0.1"},
			wantIP:         "192.0.2.1",
			ok:             true,
		},
		{
			name:       "trusted proxy with CF-Connecting-IP",
			remoteAddr: "127.0.0.1:12345",
			headers: map[string]string{
				"CF-Connecting-IP": "198.51.100.1",
			},
			trustedProxies: []string{"127.0.0.1"},
			wantIP:         "198.51.100.1",
			ok:             true,
		},
		{
			name:       "untrusted with broken header",
			remoteAddr: "203.0.113.2:23456",
			headers: map[string]string{
				"X-Real-IP": "!!!",
			},
			trustedProxies: nil,
			wantIP:         "203.0.113.2",
			ok:             true,
		},
		{
			name:           "IPv6 with zone",
			remoteAddr:     "[fd7a:115c:a1e0:ab12:4843:cd96:626b:430b%eth0]:80",
			headers:        nil,
			trustedProxies: []string{"fd7a::/16"},
			wantIP:         "fd7a:115c:a1e0:ab12:4843:cd96:626b:430b",
			ok:             true,
		},
		{
			name:           "IPv4 in IPv6 notation",
			remoteAddr:     "[::ffff:192.0.2.1]:443",
			headers:        nil,
			trustedProxies: nil,
			wantIP:         "::ffff:192.0.2.1",
			ok:             true,
		},
		{
			name:       "Forwarded header quoted IPv6",
			remoteAddr: "127.0.0.1:9999",
			headers: map[string]string{
				"Forwarded": `for="[2001:db8::1]:1234"`,
			},
			trustedProxies: []string{"127.0.0.1"},
			wantIP:         "2001:db8::1",
			ok:             true,
		},
		{
			name:       "X-Forwarded-For with unknown",
			remoteAddr: "127.0.0.1:9999",
			headers: map[string]string{
				"X-Forwarded-For": "unknown, 192.0.2.55",
			},
			trustedProxies: nil,
			wantIP:         "192.0.2.55",
			ok:             true,
		},
		{
			name:       "X-Forwarded-For all unknown",
			remoteAddr: "127.0.0.1:9999",
			headers: map[string]string{
				"X-Forwarded-For": "unknown, also_invalid",
			},
			trustedProxies: nil,
			wantIP:         "127.0.0.1",
			ok:             true,
		},
		{
			name:       "Empty remoteAddr",
			remoteAddr: "",
			headers:    nil,
			wantIP:     "",
			ok:         false,
		},
		{
			name:       "Invalid remoteAddr format",
			remoteAddr: "some_junk_string",
			headers:    nil,
			wantIP:     "",
			ok:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := ip.New(ip.WithTrustedProxies(tt.trustedProxies...))
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     http.Header{},
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			got, ok := ex.FromRequest(req)
			if ok != tt.ok {
				t.Fatalf("expected ok: %v, got: %v", tt.ok, ok)
			}
			if got.String() != tt.wantIP && tt.ok {
				t.Errorf("expected IP: %q, got: %q", tt.wantIP, got)
			}
		})
	}
}

func TestParseAddrPort(t *testing.T) {
	tests := []struct {
		name     string
		addrPort string
		wantIP   string
		wantErr  bool
	}{
		{name: "valid IPv4 with port", addrPort: "192.168.0.1:8080", wantIP: "192.168.0.1", wantErr: false},
		{name: "invalid IP:Port format", addrPort: "invalid:port", wantIP: "", wantErr: true},
		{name: "invalid IP format", addrPort: "invalid:80", wantIP: "", wantErr: true},
		{name: "IP without port", addrPort: "203.0.113.1", wantIP: "", wantErr: true},
		{name: "valid IPv6 with port", addrPort: "[2001:db8::1]:443", wantIP: "2001:db8::1", wantErr: false},
		{name: "valid IPv6 with scoped zone", addrPort: "[2001:db8::1%eth0]:80", wantIP: "2001:db8::1", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipAddr, err := ip.ParseAddrPort(tt.addrPort)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error: %v, got: %v", tt.wantErr, err)
			}
			if got := ipAddr.String(); got != tt.wantIP && !tt.wantErr {
				t.Errorf("expected IP: %s, got: %s", tt.wantIP, got)
			}
		})
	}
}

func TestParseAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantIP  string
		wantErr bool
	}{
		{name: "valid IPv4", addr: "127.0.0.1", wantIP: "127.0.0.1", wantErr: false},
		{name: "valid IPv6", addr: "2001:db8::1", wantIP: "2001:db8::1", wantErr: false},
		{name: "invalid address", addr: "abc.def", wantIP: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipAddr, err := ip.ParseAddr(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error: %v, got: %v", tt.wantErr, err)
			}
			if got := ipAddr.String(); got != tt.wantIP && !tt.wantErr {
				t.Errorf("expected IP: %s, got: %s", tt.wantIP, got)
			}
		})
	}
}

func TestExtractFor(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "quoted IPv4", in: `for="192.168.1.1"`, want: "192.168.1.1"},
		{name: "unquoted IPv4:Port", in: `for="192.168.1.1:1234"`, want: "192.168.1.1:1234"},
		{name: "unquoted IPv6", in: `for=[2001:db8::1]`, want: "[2001:db8::1]"},
		{name: "for not present", in: `by=proxy`, want: ""},
		{name: "for without value", in: `for=;by=proxy`, want: ""},
		{name: "multiple segments", in: `by=proxy; for=192.0.2.60; host=example.com`, want: "192.0.2.60"},
		{name: "trailing semicolon", in: `for=192.0.2.60;`, want: "192.0.2.60"},
		{name: "quoted IPv6:Port", in: `fOr="[2001:db8::68]:4711";proto=https`, want: "[2001:db8::68]:4711"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ip.ExtractFor(tt.in); got != tt.want {
				t.Errorf("expected: %q, got: %q", tt.want, got)
			}
		})
	}
}

func TestParseXForwardedFor(t *testing.T) {
	tests := []struct {
		name   string
		header string
		wantIP string
		ok     bool
	}{
		{
			name:   "single IP",
			header: "192.168.0.1",
			wantIP: "192.168.0.1",
			ok:     true,
		},
		{
			name:   "multiple IPs",
			header: "203.0.113.1, 192.168.0.1",
			wantIP: "203.0.113.1",
			ok:     true,
		},
		{
			name:   "with unknown",
			header: "unknown, 192.168.0.1",
			wantIP: "192.168.0.1",
			ok:     true,
		},
		{
			name:   "only unknown",
			header: "unknown",
			wantIP: "",
			ok:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ip.ParseXForwardedFor(tt.header)
			if ok != tt.ok {
				t.Fatalf("expected ok: %v, got: %v", tt.ok, ok)
			}
			if got.String() != tt.wantIP && tt.ok {
				t.Errorf("expected IP: %q, got: %q", tt.wantIP, got)
			}
		})
	}
}

func TestCtxAndWithContext(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{
			name: "store and retrieve",
			ip:   "127.0.0.1",
		},
		{
			name: "store and retrieve IPv6",
			ip:   "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.ip)
			ctx := ip.WithContext(context.Background(), addr)
			got, ok := ip.Ctx(ctx)
			if !ok {
				t.Fatal("expected IP in context")
			}
			if got != addr {
				t.Errorf("expected %s, got %s", addr, got)
			}
		})
	}
}

func TestFieldsSeq(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Simple case with IPv4 and IPv6",
			input:    "192.168.0.1, 10.0.0.1, 2001:0db8:85a3:0000:0000:8a2e:0370:7334, fe80::1",
			expected: []string{"192.168.0.1", "10.0.0.1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "fe80::1"},
		},
		{
			name:     "Spaces around IP addresses",
			input:    " 192.168.0.1 ,   10.0.0.1 ,   2001:0db8:85a3:0000:0000:8a2e:0370:7334  , fe80::1 ",
			expected: []string{"192.168.0.1", "10.0.0.1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "fe80::1"},
		},
		{
			name:     "Spaces and empty entries",
			input:    "   ,192.168.0.1\r, , 10.0.0.1 ,\t,2001:0db8:85a3:0000:0000:8a2e:0370:7334 , ",
			expected: []string{"192.168.0.1", "10.0.0.1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		},
		{
			name:     "Spaces before and after entries",
			input:    "   ,  ,  , 192.168.0.1, fe80::1 , , 2001:0db8:85a3:0000:0000:8a2e:0370:7334, ",
			expected: []string{"192.168.0.1", "fe80::1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		},
		{
			name:     "Only spaces and commas",
			input:    ", , , , , , ,",
			expected: []string{},
		},
		{
			name:     "Only IPv6 and IPv4 addresses",
			input:    "::1, 127.0.0.1, 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expected: []string{"::1", "127.0.0.1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		},
		{
			name:     "Single IP address",
			input:    "192.168.0.1",
			expected: []string{"192.168.0.1"},
		},
		{
			name:     "Only IPv6 addresses",
			input:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334,::1,fe80::1",
			expected: []string{"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "::1", "fe80::1"},
		},
		{
			name:     "Only IPv4 addresses",
			input:    "192.168.1.1,10.0.0.1,172.16.0.1",
			expected: []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"},
		},
		{
			name:     "Spaces and commas between addresses",
			input:    " 192.168.0.1 , , , 10.0.0.1, , 2001:0db8:85a3:0000:0000:8a2e:0370:7334 ",
			expected: []string{"192.168.0.1", "10.0.0.1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		},
		{
			name: "Long input with multiple addresses",
			input: "192.168.1.1,2001:0db8:85a3:0000:0000:8a2e:0370:7334,fe80::1," +
				"10.0.0.1,172.16.0.1,::1,192.168.0.1,10.0.1.1,2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expected: []string{"192.168.1.1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "fe80::1",
				"10.0.0.1", "172.16.0.1", "::1", "192.168.0.1", "10.0.1.1",
				"2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result []string
			seq := ip.FieldsSeqXForwardedFor(tt.input)
			seq(func(s string) bool {
				result = append(result, s)
				return true
			})

			if !equal(result, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParseForwarded(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		wantIP string
		wantOK bool
	}{
		{
			name:   "single header with IPv4",
			values: []string{`for=192.0.2.43`},
			wantIP: "192.0.2.43",
			wantOK: true,
		},
		{
			name:   "single header with quoted IPv6",
			values: []string{`for="fd7a:115c::626b:430b"`},
			wantIP: "fd7a:115c::626b:430b",
			wantOK: true,
		},
		{
			name:   "IPv6 with port",
			values: []string{`for="[fd7a:115c::626b:430b]:8080"`},
			wantIP: "fd7a:115c::626b:430b",
			wantOK: true,
		},
		{
			name: "multiple values in one header",
			values: []string{
				`for=192.0.2.1;by=proxy;host=example.com`,
				`for=192.0.2.2;by=proxy;host=10.0.0.1`,
			},
			wantIP: "192.0.2.1",
			wantOK: true,
		},
		{
			name: "multiple headers, take first valid",
			values: []string{
				`for=garbage;by=proxy`,
				`for=198.51.100.3;by=proxy`,
			},
			wantIP: "198.51.100.3",
			wantOK: true,
		},
		{
			name: "multiple headers with invalid 'for' values",
			values: []string{
				`for=unknown;by=proxy`,
				`for=198.51.100.4;by=proxy`,
			},
			wantIP: "198.51.100.4",
			wantOK: true,
		},
		{
			name:   "only obfuscated identifier",
			values: []string{`for=_hidden`},
			wantIP: "",
			wantOK: false,
		},
		{
			name:   "empty header value",
			values: []string{""},
			wantIP: "",
			wantOK: false,
		},
		{
			name:   "empty slice",
			values: []string{},
			wantIP: "",
			wantOK: false,
		},
		{
			name: "multiple parameters, take first valid",
			values: []string{
				`for=192.0.2.1;by=proxy;host=example.com`,
				`for=garbage;by=proxy;host=example.com`,
			},
			wantIP: "192.0.2.1",
			wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ip.ParseForwarded(tt.values)
			if ok != tt.wantOK {
				t.Errorf("expected ok=%v, got=%v", tt.wantOK, ok)
			}
			if tt.wantOK {
				if !got.IsValid() {
					t.Errorf("expected IP=%q, but got invalid IP", tt.wantIP)
				} else if got.String() != tt.wantIP {
					t.Errorf("expected IP=%q, got %q", tt.wantIP, got.String())
				}
			} else if got.IsValid() {
				t.Errorf("expected invalid IP, got %q", got.String())
			}
		})
	}
}
