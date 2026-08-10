package ip

import (
	"net/netip"
	"strings"
)

func parseSingleIPHeader(header string, values []string, strict bool, maxTokenBytes int) (proxyNode, bool, error) {
	if len(values) == 0 {
		return proxyNode{}, false, nil
	}

	if len(values) > 1 {
		value := formatHeaderValues(values)

		if strict {
			return proxyNode{}, false, &HeaderError{
				Header: header,
				Value:  value,
				Err:    ErrAmbiguousHeader,
			}
		}

		return proxyNode{kind: proxyNodeInvalid, raw: value, err: ErrAmbiguousHeader}, true, nil
	}

	value := values[0]

	if len(value) > maxTokenBytes {
		return proxyNode{}, false, &HeaderError{
			Header: header,
			Value:  formatHeaderValue(value),
			Err:    &LimitError{Limit: maxTokenBytes, Actual: len(value), Err: ErrTokenTooLarge},
		}
	}

	node, ok, err := parseHeaderIPNode(value)
	if err != nil {
		if strict {
			return proxyNode{}, false, wrapHeaderError(header, formatHeaderValue(value), err)
		}

		return proxyNode{kind: proxyNodeInvalid, raw: value, err: err}, true, nil
	}

	return node, ok, nil
}

func parseHeaderIPNode(v string) (proxyNode, bool, error) {
	v = trimOWS(v)
	if strings.EqualFold(v, "unknown") {
		return proxyNode{kind: proxyNodeUnknown, raw: v}, true, nil
	}

	if addr, err := netip.ParseAddr(v); err == nil {
		return proxyNode{kind: proxyNodeIP, addr: normalizeAddr(addr), raw: v}, true, nil
	}

	if addrPort, err := netip.ParseAddrPort(v); err == nil {
		return proxyNode{kind: proxyNodeIP, addr: normalizeAddr(addrPort.Addr()), raw: v}, true, nil
	}

	return proxyNode{}, false, ErrInvalidIP
}
