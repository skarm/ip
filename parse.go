package ip

import (
	"net/netip"
	"strings"
)

// ParseForwarded parses one RFC 7239 Forwarded field value and returns valid IP
// addresses from for parameters in wire order.
//
// Valid non-IP node identifiers such as "unknown" and obfuscated identifiers
// are omitted. If the field value contains malformed elements, ParseForwarded
// returns the valid addresses together with the first parse error.
func ParseForwarded(header string) ([]netip.Addr, error) {
	if len(header) > DefaultMaxHeaderBytes {
		return nil, &LimitError{Limit: DefaultMaxHeaderBytes, Actual: len(header), Err: ErrHeaderTooLarge}
	}

	var inlineNodes [inlineProxyNodeCount]proxyNode

	nodes, err := parseForwardedValuesInto(
		[]string{header},
		parsePartial,
		DefaultMaxHops,
		DefaultMaxTokenBytes,
		inlineNodes[:0],
	)

	return collectNodeAddrs(nodes), err
}

// ParseXForwardedFor parses one X-Forwarded-For field value and returns valid IP
// addresses in wire order.
//
// "unknown" entries are omitted. If the field value contains malformed tokens,
// ParseXForwardedFor returns the valid addresses together with the first parse
// error.
func ParseXForwardedFor(header string) ([]netip.Addr, error) {
	if len(header) > DefaultMaxHeaderBytes {
		return nil, &LimitError{Limit: DefaultMaxHeaderBytes, Actual: len(header), Err: ErrHeaderTooLarge}
	}

	var inlineNodes [inlineProxyNodeCount]proxyNode

	nodes, err := parseXForwardedForValuesInto(
		[]string{header},
		parsePartial,
		DefaultMaxHops,
		DefaultMaxTokenBytes,
		inlineNodes[:0],
	)

	return collectNodeAddrs(nodes), err
}

const inlineProxyNodeCount = 8

type proxyNodeKind uint8

const (
	proxyNodeIP proxyNodeKind = iota
	proxyNodeUnknown
	proxyNodeObfuscated
	proxyNodeInvalid
)

type proxyNode struct {
	addr netip.Addr
	raw  string
	err  error
	kind proxyNodeKind
}

type parseMode uint8

const (
	parsePermissive parseMode = iota
	parseStrict
	parsePartial
)

type proxyListKind uint8

const (
	proxyListForwarded proxyListKind = iota
	proxyListXForwardedFor
)

func parseForwardedValuesInto(values []string, mode parseMode, maxHops, maxTokenBytes int, nodes []proxyNode) ([]proxyNode, error) {
	return parseProxyValuesInto(values, mode, maxHops, maxTokenBytes, nodes, proxyListForwarded)
}

func parseXForwardedForValuesInto(values []string, mode parseMode, maxHops, maxTokenBytes int, nodes []proxyNode) ([]proxyNode, error) {
	return parseProxyValuesInto(values, mode, maxHops, maxTokenBytes, nodes, proxyListXForwardedFor)
}

func parseProxyValuesInto(values []string, mode parseMode, maxHops, maxTokenBytes int, nodes []proxyNode, kind proxyListKind) ([]proxyNode, error) {
	estimated := estimateListElements(values, maxHops)
	if cap(nodes) < estimated {
		nodes = make([]proxyNode, 0, estimated)
	} else {
		nodes = nodes[:0]
	}

	var (
		hops     int
		firstErr error
	)

	for _, value := range values {
		elements := proxyElements{value: value, kind: kind}

		for {
			element, ok := elements.next()
			if !ok {
				break
			}

			hops++

			if hops > maxHops {
				return nil, &LimitError{Limit: maxHops, Actual: hops, Err: ErrTooManyHops}
			}

			if len(element) > maxTokenBytes {
				return nil, &LimitError{Limit: maxTokenBytes, Actual: len(element), Err: ErrTokenTooLarge}
			}

			node, ok, err := parseProxyElement(kind, element)
			if err != nil {
				switch mode {
				case parseStrict:
					return nil, err
				case parsePartial:
					if firstErr == nil {
						firstErr = err
					}
				case parsePermissive:
					nodes = append(nodes, proxyNode{kind: proxyNodeInvalid, raw: element, err: err})
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

type proxyElements struct {
	value    string
	position int
	kind     proxyListKind
	done     bool
}

func (e *proxyElements) next() (string, bool) {
	if e.done {
		return "", false
	}

	start := e.position

	if e.kind == proxyListXForwardedFor {
		if offset := strings.IndexByte(e.value[start:], ','); offset >= 0 {
			e.position = start + offset + 1
			return trimOWS(e.value[start : start+offset]), true
		}

		e.done = true

		return trimOWS(e.value[start:]), true
	}

	var (
		inQuotes bool
		escaped  bool
	)

	for i := start; i < len(e.value); i++ {
		switch e.value[i] {
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

			e.position = i + 1

			return trimOWS(e.value[start:i]), true
		default:
			escaped = false
		}
	}

	e.done = true

	return trimOWS(e.value[start:]), true
}

func parseProxyElement(kind proxyListKind, element string) (proxyNode, bool, error) {
	if kind == proxyListForwarded {
		return parseForwardedElement(element)
	}

	return parseHeaderIPNode(element)
}

func estimateListElements(values []string, maxHops int) int {
	count := 0

	for _, value := range values {
		count++
		count += strings.Count(value, ",")

		if count >= maxHops {
			return maxHops
		}
	}

	return count
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

func normalizeAddr(addr netip.Addr) netip.Addr {
	if addr.Is4() {
		return addr
	}

	return normalizeNonIPv4Addr(addr)
}

func normalizeNonIPv4Addr(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}

// ParseRemoteAddr parses the RemoteAddr value of an HTTP request.
//
// The field usually contains "IP:port", but net/http does not define its format.
// ParseRemoteAddr accepts either "IP:port" or a bare IP address. It normalizes
// IPv4-mapped IPv6 addresses to IPv4 and removes IPv6 zones.
func ParseRemoteAddr(addr string) (netip.Addr, error) {
	if addrPort, err := netip.ParseAddrPort(addr); err == nil {
		remoteIP := addrPort.Addr()
		if addr[0] != '[' {
			return remoteIP, nil
		}

		return normalizeNonIPv4Addr(remoteIP), nil
	}

	return ParseAddr(addr)
}

// ParseAddrPort parses addrPort as a numeric IP:port pair. It normalizes
// IPv4-mapped IPv6 addresses to IPv4 and removes IPv6 zones.
func ParseAddrPort(addrPort string) (netip.Addr, error) {
	ipp, err := netip.ParseAddrPort(addrPort)
	if err != nil {
		return netip.Addr{}, err
	}

	return normalizeAddr(ipp.Addr()), nil
}

// ParseAddr parses addr as an IP address. It normalizes IPv4-mapped IPv6
// addresses to IPv4 and removes IPv6 zones.
func ParseAddr(addr string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Addr{}, err
	}

	return normalizeAddr(ip), nil
}
