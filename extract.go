package ip

import (
	"errors"
	"net/http"
	"net/netip"
)

// Extract returns the client IP address for r.
//
// It applies the same decision rules as [Extractor.ExtractResult] and discards
// the provenance fields. On error, Extract returns an invalid address.
func (e *Extractor) Extract(r *http.Request) (netip.Addr, error) {
	return e.ExtractFrom(r.Header, r.RemoteAddr)
}

// ExtractResult returns the client IP together with its trust provenance.
// It reads proxy metadata from r.Header and the immediate peer from
// r.RemoteAddr.
func (e *Extractor) ExtractResult(r *http.Request) (Result, error) {
	return e.ExtractResultFrom(r.Header, r.RemoteAddr)
}

// ExtractFrom returns the client IP address from header values and remoteAddr.
//
// The headers map may come from [http.Header], gRPC metadata, or another source
// represented as map[string][]string. Header names are matched
// case-insensitively. In strict mode, multiple physical keys that normalize to
// the same configured name cause [ErrAmbiguousHeader].
func (e *Extractor) ExtractFrom(headers map[string][]string, remoteAddr string) (netip.Addr, error) {
	// Keep the safe default path independent of provenance construction. This is
	// the common case for services that do not trust proxy metadata.
	if e.proxyMode == ProxiesDenied {
		if addrPort, err := netip.ParseAddrPort(remoteAddr); err == nil {
			remoteIP := addrPort.Addr()
			if remoteAddr[0] != '[' {
				return remoteIP, nil
			}

			return normalizeNonIPv4Addr(remoteIP), nil
		}

		remoteIP, err := ParseAddr(remoteAddr)
		if err != nil {
			return netip.Addr{}, wrapRemoteAddrError(remoteAddr, err)
		}

		return remoteIP, nil
	}

	result, err := e.ExtractResultFrom(headers, remoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}

	return result.Addr, nil
}

// ExtractResultFrom returns the client IP and trust provenance from headers and
// remoteAddr. It is the header-map equivalent of [Extractor.ExtractResult].
func (e *Extractor) ExtractResultFrom(headers map[string][]string, remoteAddr string) (Result, error) {
	remoteIP, remoteErr := ParseRemoteAddr(remoteAddr)
	mode := parseModeForExtractor(e.strict)

	switch e.proxyMode {
	case ProxiesDenied:
		if remoteErr != nil {
			return Result{}, wrapRemoteAddrError(remoteAddr, remoteErr)
		}

		return remoteResult(remoteIP, ReasonProxyHeadersDenied), nil
	case ProxiesAllowedList:
		if remoteErr != nil {
			return Result{}, wrapRemoteAddrError(remoteAddr, remoteErr)
		}

		if !e.isTrusted(remoteIP) {
			if e.strict && e.hasProxyHeaders(headers) {
				return Result{}, &HeaderError{Header: "proxy headers", Err: ErrUntrustedProxy}
			}

			return remoteResult(remoteIP, ReasonUntrustedImmediatePeer), nil
		}

		return e.extractWithTrustedHeaderMap(headers, remoteIP, mode)
	case ProxiesAllowedAll:
		result, err := e.extractWithTrustedHeaderMap(headers, remoteIP, mode)
		if err == nil {
			return result, nil
		}

		if !errors.Is(err, ErrNoIP) {
			return Result{}, err
		}

		if remoteErr == nil {
			return remoteResult(remoteIP, ReasonNoProxyHeaders), nil
		}

		return Result{}, wrapRemoteAddrError(remoteAddr, remoteErr)
	default:
		return Result{}, &ConfigError{
			Option: "proxy mode",
			Value:  e.proxyMode.String(),
			Err:    ErrInvalidConfig,
		}
	}
}

func remoteResult(addr netip.Addr, reason Reason) Result {
	return Result{Addr: addr, Source: SourceRemoteAddr, Reason: reason}
}

func (e *Extractor) extractWithTrustedHeaderMap(headers map[string][]string, remoteAddr netip.Addr, mode parseMode) (Result, error) {
	const inlineHeaderCount = 16

	var (
		inlineValues [inlineHeaderCount][]string
		inlineKeys   [inlineHeaderCount]string
		selected     [][]string
		selectedKeys []string
	)

	if len(e.headers) <= inlineHeaderCount {
		selected = inlineValues[:len(e.headers)]
		selectedKeys = inlineKeys[:len(e.headers)]
	} else {
		selected = make([][]string, len(e.headers))
		selectedKeys = make([]string, len(e.headers))
	}

	found, err := e.selectHeaderValues(headers, selected, selectedKeys)
	if err != nil {
		return Result{}, err
	}

	if !found {
		if remoteAddr.IsValid() {
			return remoteResult(remoteAddr, ReasonNoProxyHeaders), nil
		}

		return Result{}, ErrNoIP
	}

	return e.extractWithTrustedHeaders(selected, remoteAddr, mode)
}

func (e *Extractor) extractWithTrustedHeaders(valuesByHeader [][]string, remoteAddr netip.Addr, mode parseMode) (Result, error) {
	if len(valuesByHeader) == 0 {
		if remoteAddr.IsValid() {
			return remoteResult(remoteAddr, ReasonNoProxyHeaders), nil
		}

		return Result{}, ErrNoIP
	}

	var (
		candidate    Result
		candidateSet bool
	)

	for i, name := range e.headers {
		values := valuesByHeader[i]
		if len(values) == 0 {
			continue
		}

		result, ok, err := e.extractFromHeader(name, e.headerKinds[i], values, remoteAddr, mode)
		if err != nil {
			return Result{}, err
		}

		if !ok {
			continue
		}

		if !candidateSet {
			candidate = result
			candidateSet = true

			if !e.strict {
				return candidate, nil
			}

			continue
		}

		if candidate.Addr != result.Addr {
			return Result{}, &HeaderError{
				Header: name,
				Value:  formatHeaderValues(values),
				Err:    ErrConflictingHeaders,
			}
		}
	}

	if candidateSet {
		return candidate, nil
	}

	if remoteAddr.IsValid() {
		return remoteResult(remoteAddr, ReasonNoProxyHeaders), nil
	}

	return Result{}, ErrNoIP
}

func (e *Extractor) extractFromHeader(name string, kind HeaderKind, values []string, remoteAddr netip.Addr, mode parseMode) (Result, bool, error) {
	var inlineNodes [inlineProxyNodeCount]proxyNode

	switch kind {
	case HeaderForwarded:
		nodes, err := parseForwardedValuesInto(values, mode, e.maxHops, e.maxTokenBytes, inlineNodes[:0])
		if err != nil {
			return Result{}, false, wrapHeaderError(name, formatHeaderValues(values), err)
		}

		return e.clientFromProxyChain(name, nodes, remoteAddr)
	case HeaderXForwardedFor:
		nodes, err := parseXForwardedForValuesInto(values, mode, e.maxHops, e.maxTokenBytes, inlineNodes[:0])
		if err != nil {
			return Result{}, false, wrapHeaderError(name, formatHeaderValues(values), err)
		}

		return e.clientFromProxyChain(name, nodes, remoteAddr)
	}

	node, ok, err := parseSingleIPHeader(name, values, e.strict, e.maxTokenBytes)
	if err != nil {
		return Result{}, false, err
	}

	if !ok {
		return Result{}, false, nil
	}

	if node.kind != proxyNodeIP || !node.addr.IsValid() {
		if e.strict {
			nodeErr := node.err
			if nodeErr == nil {
				nodeErr = ErrUnverifiableChain
			}

			return Result{}, false, &HeaderError{Header: name, Value: formatHeaderValue(node.raw), Err: nodeErr}
		}

		if e.proxyMode == ProxiesAllowedList && remoteAddr.IsValid() {
			return Result{
				Addr:        remoteAddr,
				Source:      SourceRemoteAddr,
				Header:      name,
				TrustedHops: 1,
				Reason:      ReasonUnverifiableChain,
			}, true, nil
		}

		return Result{}, false, nil
	}

	trustedHops := 0
	if e.proxyMode == ProxiesAllowedList {
		trustedHops = 1
	}

	return Result{
		Addr:        node.addr,
		Source:      SourceProxyHeader,
		Header:      name,
		TrustedHops: trustedHops,
		Reason:      ReasonSelectedHeader,
	}, true, nil
}
