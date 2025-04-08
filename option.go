package ip

import "net/netip"

// Option sets options such as parameters.
type Option interface {
	apply(*Extractor)
}

type funcOption struct {
	f func(*Extractor)
}

func (fdo *funcOption) apply(cfg *Extractor) {
	fdo.f(cfg)
}

func newFuncOption(f func(*Extractor)) *funcOption {
	return &funcOption{f: f}
}

// WithHeaders overrides default header list.
func WithHeaders(headers ...string) Option {
	return newFuncOption(func(cfg *Extractor) {
		cfg.headers = headers
	})
}

// WithTrustedProxies sets list of trusted proxies (CIDR or IP format).
func WithTrustedProxies(proxies ...string) Option {
	return newFuncOption(func(cfg *Extractor) {
		cfg.trustedProxies = parseTrustedProxies(proxies)
	})
}

func parseTrustedProxies(list []string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(list))

	for _, raw := range list {
		pfx, err := netip.ParsePrefix(raw)
		if err != nil {
			ip, err := netip.ParseAddr(raw)
			if err != nil {
				continue
			}

			bits := 32
			if ip.Is6() {
				bits = 128
			}

			pfx = netip.PrefixFrom(ip, bits)
		}

		result = append(result, pfx)
	}

	return result
}
