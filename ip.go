// Package ip extracts client IP addresses from HTTP requests and header-like
// metadata.
//
// By default, the package ignores proxy headers and uses only the immediate
// transport peer. Configure [WithTrustedProxies] to accept forwarding
// metadata from known peers. [WithUnsafeTrustAllProxies] accepts forwarding
// metadata from any peer and is unsafe without an external trust boundary.
//
// Use [Extractor.ExtractResult] when callers need the selected address together
// with its source, decision reason, and verified proxy-hop count.
package ip

import "net/netip"

// Header-name constants use lowercase values for direct use with
// [Extractor.ExtractFrom] and gRPC metadata. Matching remains case-insensitive.
const (
	// XForwardedFor is the de facto X-Forwarded-For proxy-chain header.
	XForwardedFor = "x-forwarded-for"
	// Forwarded is the RFC 7239 Forwarded header.
	Forwarded = "forwarded"
	// XRealIP is the de facto X-Real-IP single-address header.
	XRealIP = "x-real-ip"
	// XClientIP is the de facto X-Client-IP single-address header.
	XClientIP = "x-client-ip"
	// CFConnectingIP is the Cloudflare single-address header.
	CFConnectingIP = "cf-connecting-ip"
	// FastlyClientIP is the Fastly single-address header.
	FastlyClientIP = "fastly-client-ip"
	// TrueClientIP is the de facto True-Client-IP single-address header.
	TrueClientIP = "true-client-ip"
	// XClusterClientIP is the de facto X-Cluster-Client-IP single-address header.
	XClusterClientIP = "x-cluster-client-ip"
	// XForwarded is a legacy, ambiguous single-address header.
	XForwarded = "x-forwarded"
	// ForwardedFor is a legacy, ambiguous single-address header.
	ForwardedFor = "forwarded-for"
)

const (
	// DefaultMaxHeaderBytes limits the aggregate size of configured proxy
	// header values processed by one extraction.
	DefaultMaxHeaderBytes = 32 << 10
	// DefaultMaxHeaderValues limits the number of physical values of configured
	// proxy headers.
	DefaultMaxHeaderValues = 64
	// DefaultMaxHops limits elements in one proxy chain.
	DefaultMaxHops = 64
	// DefaultMaxTokenBytes limits one proxy-chain element or single-IP value.
	DefaultMaxTokenBytes = 4 << 10

	maxErrorValueBytes = 256
)

// HeaderKind selects the parser used for a configured proxy header.
type HeaderKind uint8

const (
	// HeaderForwarded parses an RFC 7239 Forwarded list.
	HeaderForwarded HeaderKind = iota
	// HeaderXForwardedFor parses a comma-separated IP chain.
	HeaderXForwardedFor
	// HeaderSingleIP parses one IP or IP:port value.
	HeaderSingleIP
)

// HeaderSpec binds a proxy header name to its parser.
type HeaderSpec struct {
	// Name is the case-insensitive HTTP field name.
	Name string
	// Kind selects the parser for Name.
	Kind HeaderKind
}

// Extractor applies proxy trust, parsing, and resource-limit rules to client IP
// metadata.
//
// Permissive mode treats malformed or unverifiable proxy-chain elements as
// trust boundaries and falls back to the immediate transport peer when needed.
// Strict mode returns typed errors for malformed, unverifiable, ambiguous, or
// conflicting proxy metadata.
type Extractor struct {
	maxHeaderBytes        int
	maxHeaderValues       int
	maxHops               int
	maxTokenBytes         int
	headerIndex           map[string]int
	headerIndexesByLength map[int][]int
	trustedProxyAddrs     map[netip.Addr]struct{}
	headers               []string
	headerCanonical       []string
	headerKinds           []HeaderKind
	trustedProxyPrefixes  []netip.Prefix
	proxyMode             ProxyMode
	proxyModeExplicit     bool
	strict                bool
}

// New creates an Extractor.
//
// Defaults:
//   - proxy mode: ProxiesDenied
//   - error handling: permissive
//   - header priority: Forwarded, X-Forwarded-For, then de-facto single-IP headers
//
// In permissive mode malformed, unknown, or obfuscated chain elements stop
// trust traversal and cause a conservative fallback to the immediate peer. Use
// [WithStrict] to surface malformed, unverifiable, ambiguous, or conflicting
// headers as errors.
func New(opts ...Option) (*Extractor, error) {
	e := &Extractor{
		proxyMode:       ProxiesDenied,
		maxHeaderBytes:  DefaultMaxHeaderBytes,
		maxHeaderValues: DefaultMaxHeaderValues,
		maxHops:         DefaultMaxHops,
		maxTokenBytes:   DefaultMaxTokenBytes,
	}
	e.setHeaders([]string{
		Forwarded,
		XForwardedFor,
		XRealIP,
		XClientIP,
		CFConnectingIP,
		FastlyClientIP,
		TrueClientIP,
		XClusterClientIP,
		XForwarded,
		ForwardedFor,
	})

	for _, opt := range opts {
		if err := opt.apply(e); err != nil {
			return nil, err
		}
	}

	if e.proxyMode == ProxiesAllowedList && e.trustedProxyCount() == 0 {
		return nil, &ConfigError{
			Option: "proxy mode",
			Err:    ErrMissingTrustedProxies,
		}
	}

	return e, nil
}

// Must returns e if err is nil and panics otherwise.
//
// Use Must only during process initialization when the supplied options are
// static and invalid configuration makes startup impossible. Do not call Must
// from request handlers, background job iterations, or code that builds
// options from untrusted or runtime-controlled input; handle the error returned
// by New explicitly in those cases.
func Must(e *Extractor, err error) *Extractor {
	if err != nil {
		panic(err)
	}

	return e
}
