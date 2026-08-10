package ip

import (
	"net/netip"
	"net/textproto"
	"strconv"
	"strings"
)

// Option configures an [Extractor]. Option implementations are provided by this
// package; external implementations are not supported.
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

// WithHeaders replaces the default proxy-header priority.
//
// Header names are validated, normalized to lower-case, and deduplicated
// case-insensitively. [Forwarded] and [XForwardedFor] use their chain parsers;
// other names use [HeaderSingleIP]. Use [WithHeaderSpecs] when another header
// carries a proxy chain. Calling WithHeaders without arguments disables proxy
// headers.
func WithHeaders(headers ...string) Option {
	specs := make([]HeaderSpec, 0, len(headers))
	for _, header := range headers {
		specs = append(specs, HeaderSpec{Name: header, Kind: headerKindForName(strings.ToLower(header))})
	}

	return WithHeaderSpecs(specs...)
}

// WithHeaderSpecs replaces proxy-header priority and selects the parser for
// every header. Names are validated as HTTP field names, normalized to
// lower-case, and deduplicated case-insensitively. The first occurrence wins.
// Calling WithHeaderSpecs without arguments disables proxy headers.
func WithHeaderSpecs(headers ...HeaderSpec) Option {
	return newFuncOption(func(cfg *Extractor) error {
		normalized := make([]HeaderSpec, 0, len(headers))
		seen := make(map[string]struct{}, len(headers))

		for _, header := range headers {
			if !validHeaderName(header.Name) {
				return &ConfigError{
					Option: "headers",
					Value:  header.Name,
					Err:    ErrInvalidConfig,
				}
			}

			if !validHeaderKind(header.Kind) {
				return &ConfigError{
					Option: "header kind",
					Value:  strconv.FormatUint(uint64(header.Kind), 10),
					Err:    ErrInvalidConfig,
				}
			}

			key := strings.ToLower(header.Name)
			if _, ok := seen[key]; ok {
				continue
			}

			seen[key] = struct{}{}
			normalized = append(normalized, HeaderSpec{Name: key, Kind: header.Kind})
		}

		cfg.setHeaderSpecs(normalized)

		return nil
	})
}

// WithStrict enables strict extraction mode.
//
// Strict mode returns extraction errors for malformed, unverifiable, ambiguous,
// or conflicting proxy metadata. In allow-list mode it also rejects configured
// proxy headers received from an untrusted immediate peer. WithStrict does not
// change the proxy mode or choose how middleware handles extraction errors.
func WithStrict() Option {
	return newFuncOption(func(cfg *Extractor) error {
		cfg.strict = true
		return nil
	})
}

// WithProxyMode sets the proxy trust mode.
//
// [ProxiesAllowedList] requires at least one trusted proxy configured through
// [WithTrustedProxies]. WithTrustedProxies does not change an explicitly
// selected mode, regardless of option order.
func WithProxyMode(mode ProxyMode) Option {
	return newFuncOption(func(cfg *Extractor) error {
		switch mode {
		case ProxiesDenied, ProxiesAllowedList, ProxiesAllowedAll:
			cfg.proxyMode = mode
			cfg.proxyModeExplicit = true

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
// Each entry may be a single IP address or a CIDR prefix. This option replaces
// any previously configured allow-list. Supplying at least one proxy enables
// [ProxiesAllowedList] unless a mode was explicitly selected with
// [WithProxyMode] or [WithUnsafeTrustAllProxies].
func WithTrustedProxies(proxies ...string) Option {
	return newFuncOption(func(cfg *Extractor) error {
		addrs, prefixes, err := parseTrustedProxies(proxies)
		if err != nil {
			return err
		}

		cfg.trustedProxyAddrs = addrs
		cfg.trustedProxyPrefixes = prefixes

		if !cfg.proxyModeExplicit && (len(addrs) > 0 || len(prefixes) > 0) {
			cfg.proxyMode = ProxiesAllowedList
		}

		return nil
	})
}

// WithMaxHeaderBytes sets the maximum aggregate byte size of configured proxy
// header values processed by one extraction. The limit must be greater than
// zero.
func WithMaxHeaderBytes(limit int) Option {
	return withPositiveLimit("max header bytes", limit, func(cfg *Extractor, value int) { cfg.maxHeaderBytes = value })
}

// WithMaxHeaderValues sets the maximum number of physical configured proxy
// header values processed by one extraction. The limit must be greater than
// zero.
func WithMaxHeaderValues(limit int) Option {
	return withPositiveLimit("max header values", limit, func(cfg *Extractor, value int) { cfg.maxHeaderValues = value })
}

// WithMaxHops sets the maximum number of elements in a proxy chain. The limit
// must be greater than zero.
func WithMaxHops(limit int) Option {
	return withPositiveLimit("max hops", limit, func(cfg *Extractor, value int) { cfg.maxHops = value })
}

// WithMaxTokenBytes sets the maximum byte size of one proxy-chain element or
// single-IP header value. The limit must be greater than zero.
func WithMaxTokenBytes(limit int) Option {
	return withPositiveLimit("max token bytes", limit, func(cfg *Extractor, value int) { cfg.maxTokenBytes = value })
}

func withPositiveLimit(name string, limit int, set func(*Extractor, int)) Option {
	return newFuncOption(func(cfg *Extractor) error {
		if limit <= 0 {
			return &ConfigError{Option: name, Value: strconv.Itoa(limit), Err: ErrInvalidConfig}
		}

		set(cfg, limit)

		return nil
	})
}

// WithUnsafeTrustAllProxies trusts proxy headers from any source.
//
// This mode is unsafe for internet-facing services because clients can spoof
// forwarding metadata unless an upstream proxy strips incoming values and
// writes a canonical replacement.
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
			pfx, err = normalizeTrustedPrefix(pfx)
			if err != nil {
				return nil, nil, &ConfigError{
					Option: "trusted proxies",
					Value:  raw,
					Err:    ErrInvalidTrustedProxy,
				}
			}

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

		addrs[normalizeAddr(ip)] = struct{}{}
	}

	return addrs, prefixes, nil
}

func (e *Extractor) setHeaders(headers []string) {
	specs := make([]HeaderSpec, len(headers))

	for i, header := range headers {
		specs[i] = HeaderSpec{Name: header, Kind: headerKindForName(header)}
	}

	e.setHeaderSpecs(specs)
}

func (e *Extractor) setHeaderSpecs(headers []HeaderSpec) {
	e.headers = make([]string, len(headers))
	e.headerCanonical = make([]string, len(headers))
	e.headerKinds = make([]HeaderKind, len(headers))
	e.headerIndex = make(map[string]int, len(headers)*2)
	e.headerIndexesByLength = make(map[int][]int, len(headers))

	for i, header := range headers {
		e.headers[i] = header.Name
		e.headerCanonical[i] = textproto.CanonicalMIMEHeaderKey(header.Name)
		e.headerKinds[i] = header.Kind
		e.headerIndex[header.Name] = i
		e.headerIndex[e.headerCanonical[i]] = i
		e.headerIndexesByLength[len(header.Name)] = append(e.headerIndexesByLength[len(header.Name)], i)
	}
}

func headerKindForName(header string) HeaderKind {
	switch header {
	case Forwarded:
		return HeaderForwarded
	case XForwardedFor:
		return HeaderXForwardedFor
	default:
		return HeaderSingleIP
	}
}

func validHeaderKind(kind HeaderKind) bool {
	return kind == HeaderForwarded || kind == HeaderXForwardedFor || kind == HeaderSingleIP
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}

	for i := 0; i < len(name); i++ {
		if !isTokenChar(name[i]) {
			return false
		}
	}

	return true
}

func normalizeTrustedPrefix(pfx netip.Prefix) (netip.Prefix, error) {
	addr := pfx.Addr().WithZone("")
	bits := pfx.Bits()

	if addr.Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, ErrInvalidTrustedProxy
		}

		addr = addr.Unmap()
		bits -= 96
	}

	return netip.PrefixFrom(addr, bits).Masked(), nil
}
