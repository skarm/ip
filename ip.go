// Package ip provides tools for extracting client IP addresses from HTTP requests,
// handling proxy headers, and managing trusted networks.
package ip

import (
	"iter"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// Header constants represent common HTTP headers used for client IP detection.
const (
	XForwardedFor    = "X-Forwarded-For"     // Load-balancers (AWS ELB) or proxies.
	Forwarded        = "Forwarded"           // RFC7239.
	XRealIP          = "X-Real-IP"           // Default nginx proxy/fcgi; alternative to x-forwarded-for, used by some proxies.
	XClientIP        = "X-Client-IP"         // Standard headers used by Amazon EC2, Heroku, and others.
	CfConnectingIP   = "CF-Connecting-IP"    // @see https://support.cloudflare.com/hc/en-us/articles/200170986-How-does-Cloudflare-handle-HTTP-Request-headers-.
	FastlyClientIP   = "Fastly-Client-IP"    // Fastly and Firebase hosting header (When forwared to cloud function).
	TrueClientIP     = "True-Client-IP"      // Akamai and Cloudflare: True-Client-IP.
	XClusterClientIP = "X-Cluster-Client-IP" // Rackspace LB and Riverbed's Stingray.
	XForwarded       = "X-Forwarded"
	ForwardedFor     = "Forwarded-For"
)

// Extractor configures IP extraction rules and trusted proxies.
// Use New() to create instances with optional configuration.
type Extractor struct {
	headers        []string
	trustedProxies []netip.Prefix
}

// New creates a new Extractor with optional configuration options.
// By default, it includes commonly used HTTP headers for identifying the client IP.
// Use WithHeaders and WithTrustedProxies to customize behavior.
func New(opts ...Option) *Extractor {
	e := &Extractor{
		headers: []string{
			XForwardedFor,
			Forwarded,
			XRealIP,
			XClientIP,
			CfConnectingIP,
			FastlyClientIP,
			TrueClientIP,
			XClusterClientIP,
			XForwarded,
			ForwardedFor,
		},
	}

	for _, opt := range opts {
		opt.apply(e)
	}

	return e
}

// FromRequest extracts the client's IP address from the given HTTP request.
// It uses the configured headers in priority order and checks whether the remote address
// is a trusted proxy. If so, it attempts to retrieve the original client IP from headers.
// Returns (IP, true) on success, or (zero value, false) if extraction fails.
func (e *Extractor) FromRequest(r *http.Request) (netip.Addr, bool) {
	remoteAddr, err := ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}

	if !e.isTrusted(remoteAddr) {
		return remoteAddr, true
	}

	for _, header := range e.headers {
		if strings.EqualFold(header, Forwarded) {
			if ip, ok := ParseForwarded(r.Header.Values(header)); ok {
				return ip, true
			}
		}

		value := r.Header.Get(header)
		if value == "" {
			continue
		}

		if strings.EqualFold(header, XForwardedFor) {
			if ip, ok := ParseXForwardedFor(value); ok {
				return ip, true
			}
		}

		if ip, err := ParseAddr(value); err == nil {
			return ip, true
		}
	}

	return remoteAddr, remoteAddr.IsValid()
}

// Middleware returns an HTTP middleware that injects the client's IP address
// into the request context, using the Extractor's logic.
func (e *Extractor) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip, ok := e.FromRequest(r); ok {
			r = r.WithContext(WithContext(r.Context(), ip))
		}

		next.ServeHTTP(w, r)
	})
}

// isTrusted checks if the IP address is from a trusted proxy.
func (e *Extractor) isTrusted(addr netip.Addr) bool {
	if len(e.trustedProxies) == 0 {
		return true
	}

	return slices.ContainsFunc(e.trustedProxies, func(proxy netip.Prefix) bool {
		return proxy.Contains(addr)
	})
}

// ParseAddrPort parses s as an [netip.AddrPort].
//
// It doesn't do any name resolution: both the address and the port
// must be numeric.
func ParseAddrPort(addrPort string) (netip.Addr, error) {
	ipp, err := netip.ParseAddrPort(addrPort)
	if err != nil {
		return netip.Addr{}, err
	}

	return ipp.Addr().WithZone(""), nil
}

// ParseAddr parses s as an IP address, returning the result. The string
// s can be in dotted decimal ("192.0.2.1"), IPv6 ("2001:db8::68"),
// or IPv6 with a scoped addressing zone ("fe80::1cc0:3e8c:119f:c2e1%eth0").
func ParseAddr(addr string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Addr{}, err
	}

	return ip.WithZone(""), nil
}

// ParseForwarded parses the "Forwarded" HTTP headers and extracts the first valid IP address from the "for=" parameter.
// Returns the extracted IP and true if parsing succeeds, or zero IP and false otherwise.
func ParseForwarded(addrs []string) (netip.Addr, bool) {
	for _, addr := range addrs {
		v := ExtractFor(addr)
		if v == "" {
			continue
		}

		if ip, err := ParseAddrPort(v); err == nil {
			return ip, true
		}

		if ip, err := ParseAddr(v); err == nil {
			return ip, true
		}
	}

	return netip.Addr{}, false
}

const (
	space     = ' '
	semicolon = ';'
	equally   = '='
	quote     = '"'
)

// ExtractFor parses a single Forwarded header value string and returns the value of the first "for=" parameter.
// Handles optional quotes and IPv6 brackets, e.g. `for="[2001:db8::1]:443"` or `for=192.0.2.43`.
// If the "for" parameter is not found, an empty string is returned.
func ExtractFor(s string) string {
	var (
		i     int
		value string
	)

	for i < len(s) {
		for i < len(s) && (s[i] == space || s[i] == semicolon) {
			i++
		}

		start := i

		for i < len(s) && s[i] != equally {
			i++
		}

		if i >= len(s) {
			break
		}

		key := strings.TrimSpace(s[start:i])
		i++

		for i < len(s) && s[i] == space {
			i++
		}

		if i < len(s) && s[i] == quote {
			i++
			start = i

			for i < len(s) && s[i] != quote {
				i++
			}

			value = s[start:i]
			i++
		} else {
			start = i

			for i < len(s) && s[i] != semicolon {
				i++
			}

			value = strings.TrimSpace(s[start:i])
		}

		if strings.EqualFold(key, "for") {
			return value
		}
	}

	return ""
}

// ParseXForwardedFor parses an X-Forwarded-For header value and returns the first valid IP address.
// Sometimes IP addresses in this header can be 'unknown' (http://stackoverflow.com/a/11285650).
// A Squid configuration directive can also set the value to "unknown" (http://www.squid-cache.org/Doc/config/forwarded_for/).
// Therefore taking the left-most IP address that is not unknown.
func ParseXForwardedFor(header string) (netip.Addr, bool) {
	for v := range FieldsSeqXForwardedFor(header) {
		if addr, err := ParseAddr(v); err == nil {
			return addr, true
		}
	}

	return netip.Addr{}, false
}

var asciiSpace = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}

// FieldsSeqXForwardedFor splits a string of IPs from an X-Forwarded-For header into a sequence of fields.
// It ignores spaces and commas between IPs, yielding each value to the caller function.
func FieldsSeqXForwardedFor(s string) iter.Seq[string] {
	return func(yield func(string) bool) {
		start := -1

		for i := 0; i < len(s); {
			size := 1
			r := rune(s[i])

			if r == ',' || asciiSpace[s[i]] != 0 {
				if start >= 0 {
					if !yield(s[start:i]) {
						return
					}

					start = -1
				}
			} else if start < 0 {
				start = i
			}

			i += size
		}

		if start >= 0 {
			yield(s[start:])
		}
	}
}
