package ip

import (
	"net/netip"
	"slices"
	"strconv"
)

// ProxyMode controls when proxy headers are trusted.
type ProxyMode uint8

const (
	// ProxiesDenied ignores all proxy headers and uses only the immediate
	// transport peer.
	ProxiesDenied ProxyMode = iota
	// ProxiesAllowedList trusts configured proxy headers only when the immediate
	// transport peer belongs to the trusted proxy allow-list.
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

func (e *Extractor) clientFromProxyChain(header string, nodes []proxyNode, remoteAddr netip.Addr) (Result, bool, error) {
	if len(nodes) == 0 {
		return Result{}, false, nil
	}

	if e.strict {
		// Strict validation covers the entire header, including elements to
		// the left of the first untrusted address selected during traversal.
		for _, node := range nodes {
			if node.kind != proxyNodeIP || !node.addr.IsValid() {
				err := node.err
				if err == nil {
					err = ErrUnverifiableChain
				}

				return Result{}, false, &HeaderError{Header: header, Value: formatHeaderValue(node.raw), Err: err}
			}
		}
	}

	if e.proxyMode == ProxiesAllowedAll {
		var client netip.Addr

		for _, node := range nodes {
			if node.kind != proxyNodeIP || !node.addr.IsValid() {
				continue
			}

			if !client.IsValid() {
				client = node.addr
			}
		}

		if client.IsValid() {
			return Result{Addr: client, Source: SourceProxyHeader, Header: header, Reason: ReasonSelectedHeader}, true, nil
		}

		return Result{}, false, nil
	}

	// The caller verified the immediate transport peer before this method.
	trustedHops := 1

	for _, node := range slices.Backward(nodes) {
		if node.kind != proxyNodeIP || !node.addr.IsValid() {
			return Result{
				Addr:        remoteAddr,
				Source:      SourceRemoteAddr,
				Header:      header,
				TrustedHops: trustedHops,
				Reason:      ReasonUnverifiableChain,
			}, true, nil
		}

		if !e.isTrusted(node.addr) {
			return Result{
				Addr:        node.addr,
				Source:      SourceProxyHeader,
				Header:      header,
				TrustedHops: trustedHops,
				Reason:      ReasonSelectedHeader,
			}, true, nil
		}

		trustedHops++
	}

	return Result{
		Addr:        remoteAddr,
		Source:      SourceRemoteAddr,
		Header:      header,
		TrustedHops: trustedHops,
		Reason:      ReasonNoUntrustedHop,
	}, true, nil
}

func (e *Extractor) isTrusted(addr netip.Addr) bool {
	addr = normalizeAddr(addr)
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
