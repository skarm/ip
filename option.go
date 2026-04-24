package ip

import (
	"net/netip"
	"net/textproto"
	"strings"
)

// Option configures an Extractor.
type Option interface {
	apply(*Extractor) error
}

type funcOption struct {
	f func(*Extractor) error
}

func (fdo *funcOption) apply(cfg *Extractor) error {
	return fdo.f(cfg)
}

func newFuncOption(f func(*Extractor) error) *funcOption {
	return &funcOption{f: f}
}

// WithHeaders overrides the default header priority.
//
// Header names are normalized to lower-case and deduplicated
// case-insensitively. Unknown headers are treated as single-IP de-facto
// headers.
func WithHeaders(headers ...string) Option {
	return newFuncOption(func(cfg *Extractor) error {
		normalized := make([]string, 0, len(headers))
		seen := make(map[string]struct{}, len(headers))

		for _, header := range headers {
			if header == "" {
				return &ConfigError{
					Option: "headers",
					Err:    ErrInvalidConfig,
				}
			}

			key := strings.ToLower(header)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			normalized = append(normalized, key)
		}

		cfg.setHeaders(normalized)

		return nil
	})
}

// WithStrict enables strict extraction mode.
//
// Strict mode returns errors for malformed proxy headers, conflicting header
// values, suspicious proxy usage from untrusted remotes, and invalid
// configuration.
func WithStrict() Option {
	return newFuncOption(func(cfg *Extractor) error {
		cfg.strict = true
		return nil
	})
}

// WithProxyMode sets the proxy trust mode.
//
// ProxiesAllowedList still requires at least one trusted proxy to be
// configured, either through WithTrustedProxies or by setting trusted proxies
// via a custom option.
func WithProxyMode(mode ProxyMode) Option {
	return newFuncOption(func(cfg *Extractor) error {
		switch mode {
		case ProxiesDenied, ProxiesAllowedList, ProxiesAllowedAll:
			cfg.proxyMode = mode
			return nil
		default:
			return &ConfigError{
				Option: "proxy mode",
				Value:  mode.String(),
				Err:    ErrInvalidConfig,
			}
		}
	})
}

// WithTrustedProxies configures the trusted proxy allow-list.
//
// Each entry may be either a single IP address or a CIDR prefix. Supplying at
// least one trusted proxy automatically enables ProxiesAllowedList mode.
func WithTrustedProxies(proxies ...string) Option {
	return newFuncOption(func(cfg *Extractor) error {
		addrs, prefixes, err := parseTrustedProxies(proxies)
		if err != nil {
			return err
		}

		cfg.trustedProxyAddrs = addrs
		cfg.trustedProxyPrefixes = prefixes
		if len(addrs) > 0 || len(prefixes) > 0 {
			cfg.proxyMode = ProxiesAllowedList
		}

		return nil
	})
}

// WithUnsafeTrustAllProxies trusts proxy headers from any source.
//
// This mode is unsafe for internet-facing services because clients can spoof
// x-forwarded-for, forwarded, and similar headers unless an upstream proxy
// strips and rewrites them.
func WithUnsafeTrustAllProxies() Option {
	return WithProxyMode(ProxiesAllowedAll)
}

func parseTrustedProxies(list []string) (map[netip.Addr]struct{}, []netip.Prefix, error) {
	var (
		addrs    map[netip.Addr]struct{}
		prefixes []netip.Prefix
	)

	for _, raw := range list {
		pfx, err := netip.ParsePrefix(raw)
		if err == nil {
			pfx = normalizeTrustedPrefix(pfx)
			if pfx.Bits() == pfx.Addr().BitLen() {
				if addrs == nil {
					addrs = make(map[netip.Addr]struct{}, len(list))
				}
				addrs[pfx.Addr()] = struct{}{}
			} else {
				prefixes = append(prefixes, pfx)
			}
			continue
		}

		ip, ipErr := netip.ParseAddr(raw)
		if ipErr != nil {
			return nil, nil, &ConfigError{
				Option: "trusted proxies",
				Value:  raw,
				Err:    ErrInvalidTrustedProxy,
			}
		}

		if addrs == nil {
			addrs = make(map[netip.Addr]struct{}, len(list))
		}
		addrs[ip.WithZone("")] = struct{}{}
	}

	return addrs, prefixes, nil
}

func (e *Extractor) setHeaders(headers []string) {
	e.headers = append(e.headers[:0], headers...)
	e.headerCanonical = make([]string, len(headers))
	e.headerKinds = make([]headerKind, len(headers))
	e.headerIndex = make(map[string]int, len(headers)*2)

	for i, header := range headers {
		e.headerCanonical[i] = textproto.CanonicalMIMEHeaderKey(header)
		e.headerKinds[i] = headerKindForName(header)
		e.headerIndex[header] = i
		e.headerIndex[e.headerCanonical[i]] = i
	}
}

func headerKindForName(header string) headerKind {
	switch header {
	case Forwarded:
		return headerForwarded
	case XForwardedFor:
		return headerXForwardedFor
	default:
		return headerSingleIP
	}
}

func normalizeTrustedPrefix(pfx netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(pfx.Addr().WithZone(""), pfx.Bits()).Masked()
}
