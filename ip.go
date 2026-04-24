// Package ip extracts client IP addresses from HTTP requests.
//
// By default, proxy headers are ignored and only Request.RemoteAddr is used.
// This fail-closed default prevents clients from spoofing their address by
// sending x-forwarded-for, forwarded, or similar headers directly.
package ip

import (
	"errors"
	"iter"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Header constants used by the extractor.
//
// The values are intentionally lower-case so they can be used directly with
// ExtractFrom and gRPC metadata, which commonly store header names in
// lower-case. HTTP header names remain case-insensitive.
//
// Standardized header: Forwarded (RFC 7239).
// De-facto proxy headers: X-Forwarded-For, X-Real-IP, X-Client-IP,
// CF-Connecting-IP, Fastly-Client-IP, True-Client-IP, X-Cluster-Client-IP.
// Ambiguous legacy headers: X-Forwarded, Forwarded-For.
const (
	XForwardedFor    = "x-forwarded-for"     // Used by load balancers such as AWS ELB and by many reverse proxies.
	Forwarded        = "forwarded"           // Standardized by RFC 7239.
	XRealIP          = "x-real-ip"           // Common nginx proxy/FastCGI header and a frequent alternative to x-forwarded-for.
	XClientIP        = "x-client-ip"         // De-facto header used by platforms such as Amazon EC2 and Heroku.
	CFConnectingIP   = "cf-connecting-ip"    // Cloudflare client IP header. See https://developers.cloudflare.com/fundamentals/reference/http-request-headers/#cf-connecting-ip.
	FastlyClientIP   = "fastly-client-ip"    // Used by Fastly and by Firebase Hosting when forwarding to Cloud Functions.
	TrueClientIP     = "true-client-ip"      // Used by Akamai and also supported by Cloudflare.
	XClusterClientIP = "x-cluster-client-ip" // Seen in Rackspace load balancers and Riverbed Stingray.
	XForwarded       = "x-forwarded"         // Legacy, ambiguous non-standard header.
	ForwardedFor     = "forwarded-for"       // Legacy, ambiguous non-standard header.
)

// ProxyMode controls when proxy headers are trusted.
type ProxyMode uint8

const (
	// ProxiesDenied ignores all proxy headers and only uses Request.RemoteAddr.
	ProxiesDenied ProxyMode = iota
	// ProxiesAllowedList trusts proxy headers only when the immediate remote
	// address belongs to the configured trusted proxy allow-list.
	ProxiesAllowedList
	// ProxiesAllowedAll trusts proxy headers from any source.
	//
	// This mode is unsafe for internet-facing services unless an upstream
	// component sanitizes and rewrites forwarding headers.
	ProxiesAllowedAll
)

// String returns the Go-style symbolic name of m.
func (m ProxyMode) String() string {
	switch m {
	case ProxiesDenied:
		return "ProxiesDenied"
	case ProxiesAllowedList:
		return "ProxiesAllowedList"
	case ProxiesAllowedAll:
		return "ProxiesAllowedAll"
	default:
		return "ProxyMode(" + strconv.FormatUint(uint64(m), 10) + ")"
	}
}

// Extractor extracts client IP addresses from HTTP requests.
//
// The same extractor supports both permissive and strict behavior:
// permissive mode ignores malformed proxy headers and falls back to safer
// sources, while strict mode returns detailed errors for malformed,
// suspicious, or conflicting proxy metadata.
type Extractor struct {
	headers              []string
	headerCanonical      []string
	headerKinds          []headerKind
	headerIndex          map[string]int
	proxyMode            ProxyMode
	trustedProxyAddrs    map[netip.Addr]struct{}
	trustedProxyPrefixes []netip.Prefix
	strict               bool
}

type headerKind uint8

const (
	headerForwarded headerKind = iota
	headerXForwardedFor
	headerSingleIP
)

// New creates an Extractor.
//
// Defaults:
//   - proxy mode: ProxiesDenied
//   - error handling: permissive
//   - header priority: Forwarded, X-Forwarded-For, then de-facto single-IP headers
//
// In permissive mode the extractor ignores malformed proxy headers and falls
// back to safer sources. Use WithStrict to surface malformed or conflicting
// headers as errors.
func New(opts ...Option) (*Extractor, error) {
	e := &Extractor{
		proxyMode: ProxiesDenied,
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
func Must(e *Extractor, err error) *Extractor {
	if err != nil {
		panic(err)
	}
	return e
}

// Extract returns the client IP address for r.
//
// In permissive mode malformed proxy headers are ignored. In strict mode the
// extractor returns typed errors for malformed headers, conflicting header
// values, suspicious proxy usage, and invalid configuration.
func (e *Extractor) Extract(r *http.Request) (netip.Addr, error) {
	return e.ExtractFrom(r.Header, r.RemoteAddr)
}

// ExtractFrom returns the client IP address from header values and remoteAddr.
//
// headers may come from net/http headers, gRPC metadata, or any other source
// that can be represented as map[string][]string. Header names are matched
// case-insensitively. In strict mode, multiple physical keys that normalize to
// the same logical header (for example "X-Forwarded-For" and
// "x-forwarded-for") cause ErrAmbiguousHeader. This applies only to headers
// configured in the extractor. In permissive mode, the exact lower-case
// spelling wins; if it is absent, the lexicographically smallest key wins.
func (e *Extractor) ExtractFrom(headers map[string][]string, remoteAddr string) (netip.Addr, error) {
	remoteIP, remoteErr := ParseRemoteAddr(remoteAddr)
	mode := parseModeForExtractor(e.strict)

	switch e.proxyMode {
	case ProxiesDenied:
		if remoteErr != nil {
			return netip.Addr{}, wrapRemoteAddrError(remoteAddr, remoteErr)
		}

		return remoteIP, nil
	case ProxiesAllowedList:
		if remoteErr != nil {
			return netip.Addr{}, wrapRemoteAddrError(remoteAddr, remoteErr)
		}

		if !e.isTrusted(remoteIP) {
			if e.strict && e.hasProxyHeaders(headers) {
				return netip.Addr{}, &HeaderError{
					Header: "proxy headers",
					Err:    ErrUntrustedProxy,
				}
			}

			return remoteIP, nil
		}

		selected, err := e.selectHeaderValues(headers, e.strict)
		if err != nil {
			return netip.Addr{}, err
		}

		return e.extractWithTrustedHeaders(selected, remoteIP, mode)
	case ProxiesAllowedAll:
		selected, err := e.selectHeaderValues(headers, e.strict)
		if err != nil {
			return netip.Addr{}, err
		}

		ip, err := e.extractWithTrustedHeaders(selected, remoteIP, mode)
		if err == nil {
			return ip, nil
		}

		if !errors.Is(err, ErrNoIP) {
			return netip.Addr{}, err
		}

		if remoteErr == nil {
			return remoteIP, nil
		}

		return netip.Addr{}, wrapRemoteAddrError(remoteAddr, remoteErr)
	default:
		return netip.Addr{}, &ConfigError{
			Option: "proxy mode",
			Value:  e.proxyMode.String(),
			Err:    ErrInvalidConfig,
		}
	}
}

func (e *Extractor) extractWithTrustedHeaders(valuesByHeader [][]string, remoteAddr netip.Addr, mode parseMode) (netip.Addr, error) {
	if len(valuesByHeader) == 0 {
		if remoteAddr.IsValid() {
			return remoteAddr, nil
		}

		return netip.Addr{}, ErrNoIP
	}

	var (
		candidate    netip.Addr
		candidateSet bool
	)

	for i, name := range e.headers {
		values := valuesByHeader[i]
		if len(values) == 0 {
			continue
		}

		ip, ok, err := e.extractFromHeader(name, e.headerKinds[i], values, remoteAddr, mode)
		if err != nil {
			return netip.Addr{}, err
		}
		if !ok {
			continue
		}
		if !candidateSet {
			candidate = ip
			candidateSet = true
			if !e.strict {
				return candidate, nil
			}

			continue
		}
		if candidate != ip {
			return netip.Addr{}, &HeaderError{
				Header: name,
				Value:  strings.Join(values, ", "),
				Err:    ErrConflictingHeaders,
			}
		}
	}

	if candidateSet {
		return candidate, nil
	}

	if remoteAddr.IsValid() {
		return remoteAddr, nil
	}

	return netip.Addr{}, ErrNoIP
}

func (e *Extractor) extractFromHeader(name string, kind headerKind, values []string, remoteAddr netip.Addr, mode parseMode) (netip.Addr, bool, error) {
	switch kind {
	case headerForwarded:
		nodes, err := parseForwardedValues(values, mode)
		if err != nil {
			return netip.Addr{}, false, wrapHeaderError(name, strings.Join(values, ", "), err)
		}

		return e.clientFromProxyChain(name, nodes, remoteAddr)
	case headerXForwardedFor:
		nodes, err := parseXForwardedForValues(values, mode)
		if err != nil {
			return netip.Addr{}, false, wrapHeaderError(name, strings.Join(values, ", "), err)
		}

		return e.clientFromProxyChain(name, nodes, remoteAddr)
	}

	node, ok, err := parseSingleIPHeader(name, values, e.strict)
	if err != nil {
		return netip.Addr{}, false, err
	}
	if !ok || !node.addr.IsValid() {
		return netip.Addr{}, false, nil
	}

	return node.addr, true, nil
}

func (e *Extractor) clientFromProxyChain(header string, nodes []proxyNode, remoteAddr netip.Addr) (netip.Addr, bool, error) {
	if len(nodes) == 0 {
		return netip.Addr{}, false, nil
	}

	if e.proxyMode == ProxiesAllowedAll {
		for _, node := range nodes {
			if node.addr.IsValid() {
				return node.addr, true, nil
			}
		}

		return netip.Addr{}, false, nil
	}

	for i := len(nodes) - 1; i >= 0; i-- {
		node := nodes[i]
		if !node.addr.IsValid() {
			if e.strict {
				return netip.Addr{}, false, &HeaderError{
					Header: header,
					Value:  node.raw,
					Err:    ErrUntrustedProxy,
				}
			}

			return remoteAddr, true, nil
		}

		if !e.isTrusted(node.addr) {
			return node.addr, true, nil
		}
	}

	return remoteAddr, true, nil
}

func (e *Extractor) isTrusted(addr netip.Addr) bool {
	if _, ok := e.trustedProxyAddrs[addr]; ok {
		return true
	}

	return slices.ContainsFunc(e.trustedProxyPrefixes, func(proxy netip.Prefix) bool {
		return proxy.Contains(addr)
	})
}

func (e *Extractor) trustedProxyCount() int {
	return len(e.trustedProxyAddrs) + len(e.trustedProxyPrefixes)
}

func (e *Extractor) hasProxyHeaders(headers map[string][]string) bool {
	for i, name := range e.headers {
		if len(headers[name]) > 0 {
			return true
		}

		canonical := e.headerCanonical[i]
		if canonical != name && len(headers[canonical]) > 0 {
			return true
		}
	}

	for key, values := range headers {
		if len(values) == 0 {
			continue
		}
		if _, ok := e.indexForHeaderKey(key); ok {
			return true
		}
	}

	return false
}

// ParseRemoteAddr parses Request.RemoteAddr.
//
// Request.RemoteAddr usually contains "IP:port", but net/http documents that
// the field has no defined format. This helper accepts either "IP:port" or a
// bare IP address and strips IPv6 zones.
func ParseRemoteAddr(addr string) (netip.Addr, error) {
	if ip, err := ParseAddrPort(addr); err == nil {
		return ip, nil
	}

	return ParseAddr(addr)
}

// ParseAddrPort parses s as a numeric IP:port pair and strips any IPv6 zone.
func ParseAddrPort(addrPort string) (netip.Addr, error) {
	ipp, err := netip.ParseAddrPort(addrPort)
	if err != nil {
		return netip.Addr{}, err
	}

	return ipp.Addr().WithZone(""), nil
}

// ParseAddr parses s as an IP address and strips any IPv6 zone.
func ParseAddr(addr string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Addr{}, err
	}

	return ip.WithZone(""), nil
}

// ParseForwarded parses a single RFC 7239 Forwarded field-value and returns all
// valid IP addresses extracted from "for=" parameters in wire order.
//
// Valid non-IP node identifiers such as "unknown" and obfuscated identifiers
// are skipped. If the header contains malformed elements, the function returns
// the successfully parsed addresses together with the first parse error.
func ParseForwarded(header string) ([]netip.Addr, error) {
	nodes, err := parseForwardedValues([]string{header}, parsePartial)
	return collectNodeAddrs(nodes), err
}

// ParseXForwardedFor parses a single X-Forwarded-For field-value and returns
// all valid IP addresses in wire order.
//
// "unknown" entries are ignored. If the header contains malformed tokens, the
// function returns the successfully parsed addresses together with the first
// parse error.
func ParseXForwardedFor(header string) ([]netip.Addr, error) {
	nodes, err := parseXForwardedForValues([]string{header}, parsePartial)
	return collectNodeAddrs(nodes), err
}

type proxyNode struct {
	addr netip.Addr
	raw  string
}

type parseMode uint8

const (
	parsePermissive parseMode = iota
	parseStrict
	parsePartial
)

func (m parseMode) strictSyntax() bool {
	return m != parsePermissive
}

func (e *Extractor) selectHeaderValues(headers map[string][]string, strict bool) ([][]string, error) {
	if len(headers) == 0 {
		return nil, nil
	}

	selected := make([][]string, len(e.headers))
	selectedKeys := make([]string, len(e.headers))

	for key, values := range headers {
		if len(values) == 0 {
			continue
		}

		idx, ok := e.indexForHeaderKey(key)
		if !ok {
			continue
		}

		chosenKey := selectedKeys[idx]
		if chosenKey == "" {
			selectedKeys[idx] = key
			selected[idx] = values
			continue
		}

		if strict {
			return nil, &HeaderError{
				Header: e.headers[idx],
				Err:    ErrAmbiguousHeader,
			}
		}

		lower := e.headers[idx]
		chosenIsLower := chosenKey == lower
		keyIsLower := key == lower
		if (!chosenIsLower && keyIsLower) || (chosenIsLower == keyIsLower && key < chosenKey) {
			selectedKeys[idx] = key
			selected[idx] = values
		}
	}

	return selected, nil
}

func (e *Extractor) indexForHeaderKey(key string) (int, bool) {
	if idx, ok := e.headerIndex[key]; ok {
		return idx, true
	}

	idx, ok := e.headerIndex[strings.ToLower(key)]
	return idx, ok
}

func collectNodeAddrs(nodes []proxyNode) []netip.Addr {
	addrs := make([]netip.Addr, 0, len(nodes))

	for _, node := range nodes {
		if node.addr.IsValid() {
			addrs = append(addrs, node.addr)
		}
	}

	return addrs
}

func parseModeForExtractor(strict bool) parseMode {
	if strict {
		return parseStrict
	}

	return parsePermissive
}

func parseForwardedValues(values []string, mode parseMode) ([]proxyNode, error) {
	var (
		nodes    []proxyNode
		firstErr error
	)

	for _, value := range values {
		for elem := range forwardedElementsSeq(value) {
			node, ok, err := parseForwardedElement(elem, mode.strictSyntax())
			if err != nil {
				switch mode {
				case parseStrict:
					return nil, err
				case parsePartial:
					if firstErr == nil {
						firstErr = err
					}
				}
				continue
			}
			if ok {
				nodes = append(nodes, node)
			}
		}
	}

	return nodes, firstErr
}

func parseXForwardedForValues(values []string, mode parseMode) ([]proxyNode, error) {
	var (
		nodes    []proxyNode
		firstErr error
	)

	for _, value := range values {
		for token := range fieldsSeqXForwardedFor(value) {
			node, ok, err := parseHeaderIPNode(token)
			if err != nil {
				switch mode {
				case parseStrict:
					return nil, err
				case parsePartial:
					if firstErr == nil {
						firstErr = err
					}
				}
				continue
			}
			if ok {
				nodes = append(nodes, node)
			}
		}
	}

	return nodes, firstErr
}

func forwardedElementsSeq(s string) iter.Seq[string] {
	return func(yield func(string) bool) {
		var (
			start    int
			inQuotes bool
			escaped  bool
		)

		for i := 0; i < len(s); i++ {
			switch s[i] {
			case '\\':
				if inQuotes {
					escaped = !escaped
				}
			case '"':
				if !escaped {
					inQuotes = !inQuotes
				}
				escaped = false
			case ',':
				if inQuotes {
					escaped = false
					continue
				}

				if elem := strings.TrimSpace(s[start:i]); elem != "" {
					if !yield(elem) {
						return
					}
				}

				start = i + 1
				escaped = false
			default:
				escaped = false
			}
		}

		if elem := strings.TrimSpace(s[start:]); elem != "" {
			yield(elem)
		}
	}
}

func parseForwardedElement(s string, strictSyntax bool) (proxyNode, bool, error) {
	value, ok, err := parseForwardedForValue(s, strictSyntax)
	if err != nil || !ok {
		return proxyNode{}, ok, err
	}

	node, err := parseForwardedNode(value)
	if err != nil {
		if strictSyntax {
			return proxyNode{}, false, err
		}

		return proxyNode{}, false, nil
	}

	return node, true, nil
}

func parseForwardedForValue(s string, strict bool) (string, bool, error) {
	var (
		i      int
		found  bool
		result string
	)

	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == ';') {
			i++
		}
		if i >= len(s) {
			break
		}

		keyStart := i
		for i < len(s) && s[i] != '=' && s[i] != ';' {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			if strict {
				return "", false, ErrInvalidForwarded
			}

			return "", false, nil
		}

		key := strings.TrimSpace(s[keyStart:i])
		i++

		value, next, err := consumeForwardedValue(s, i)
		if err != nil {
			if strict {
				return "", false, ErrInvalidForwarded
			}

			return "", false, nil
		}
		i = next

		if !strings.EqualFold(key, "for") {
			continue
		}
		if found && strict {
			return "", false, ErrInvalidForwarded
		}

		found = true
		result = value
	}

	return result, found, nil
}

func consumeForwardedValue(s string, start int) (string, int, error) {
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	if start >= len(s) {
		return "", start, ErrInvalidForwarded
	}

	if s[start] == '"' {
		var b strings.Builder
		for i := start + 1; i < len(s); i++ {
			switch s[i] {
			case '\\':
				i++
				if i >= len(s) {
					return "", 0, ErrInvalidForwarded
				}
				b.WriteByte(s[i])
			case '"':
				j := i + 1
				for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
					j++
				}
				if j < len(s) && s[j] != ';' {
					return "", 0, ErrInvalidForwarded
				}
				return b.String(), j, nil
			default:
				b.WriteByte(s[i])
			}
		}

		return "", 0, ErrInvalidForwarded
	}

	end := start
	for end < len(s) && s[end] != ';' {
		end++
	}

	value := strings.TrimSpace(s[start:end])
	if value == "" {
		return "", 0, ErrInvalidForwarded
	}

	return value, end, nil
}

func parseForwardedNode(v string) (proxyNode, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return proxyNode{}, ErrInvalidForwarded
	}

	if strings.HasPrefix(v, "[") {
		end := strings.IndexByte(v, ']')
		if end < 0 {
			return proxyNode{}, ErrInvalidForwarded
		}

		ip, err := ParseAddr(v[1:end])
		if err != nil || !ip.Is6() {
			return proxyNode{}, ErrInvalidForwarded
		}

		rest := v[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return proxyNode{}, ErrInvalidForwarded
			}
			if err := validateForwardedPort(rest[1:]); err != nil {
				return proxyNode{}, err
			}
		}

		return proxyNode{addr: ip, raw: v}, nil
	}

	host := v
	port := ""
	if idx := strings.LastIndexByte(v, ':'); idx >= 0 {
		host = v[:idx]
		port = v[idx+1:]
		if strings.Contains(host, ":") {
			return proxyNode{}, ErrInvalidForwarded
		}
		if err := validateForwardedPort(port); err != nil {
			return proxyNode{}, err
		}
	}

	switch {
	case strings.EqualFold(host, "unknown"):
		return proxyNode{raw: v}, nil
	case strings.HasPrefix(host, "_"):
		if !isValidObfuscatedIdentifier(host) {
			return proxyNode{}, ErrInvalidForwarded
		}
		return proxyNode{raw: v}, nil
	}

	ip, err := ParseAddr(host)
	if err != nil {
		return proxyNode{}, ErrInvalidForwarded
	}
	if ip.Is6() {
		return proxyNode{}, ErrInvalidForwarded
	}

	return proxyNode{addr: ip, raw: v}, nil
}

func validateForwardedPort(port string) error {
	if port == "" {
		return ErrInvalidForwarded
	}
	if port[0] == '_' {
		if !isValidObfuscatedIdentifier(port) {
			return ErrInvalidForwarded
		}
		return nil
	}

	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return ErrInvalidForwarded
		}
	}

	return nil
}

func isValidObfuscatedIdentifier(v string) bool {
	if len(v) < 2 || v[0] != '_' {
		return false
	}

	for i := 1; i < len(v); i++ {
		c := v[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			continue
		}

		return false
	}

	return true
}

func parseSingleIPHeader(header string, values []string, strict bool) (proxyNode, bool, error) {
	if strict && len(values) > 1 {
		return proxyNode{}, false, &HeaderError{
			Header: header,
			Value:  strings.Join(values, ", "),
			Err:    ErrAmbiguousHeader,
		}
	}

	for _, value := range values {
		node, ok, err := parseHeaderIPNode(value)
		if err != nil {
			if strict {
				return proxyNode{}, false, wrapHeaderError(header, value, err)
			}
			continue
		}
		if ok {
			return node, true, nil
		}
	}

	return proxyNode{}, false, nil
}

func parseHeaderIPNode(v string) (proxyNode, bool, error) {
	v = strings.TrimSpace(v)
	if strings.EqualFold(v, "unknown") {
		return proxyNode{raw: v}, true, nil
	}

	ip, err := ParseRemoteAddr(v)
	if err != nil {
		return proxyNode{}, false, ErrInvalidIP
	}

	return proxyNode{addr: ip, raw: v}, true, nil
}

var asciiSpace = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}

// fieldsSeqXForwardedFor splits a comma-separated X-Forwarded-For value into
// individual tokens, trimming ASCII whitespace and skipping empty entries.
func fieldsSeqXForwardedFor(s string) iter.Seq[string] {
	return func(yield func(string) bool) {
		start := -1

		for i := 0; i < len(s); i++ {
			if s[i] == ',' || asciiSpace[s[i]] != 0 {
				if start >= 0 {
					if !yield(s[start:i]) {
						return
					}

					start = -1
				}

				continue
			}

			if start < 0 {
				start = i
			}
		}

		if start >= 0 {
			yield(s[start:])
		}
	}
}
