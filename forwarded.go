package ip

import (
	"net/netip"
	"strings"
)

func parseForwardedElement(s string) (proxyNode, bool, error) {
	value, ok, err := parseForwardedForValue(s)
	if err != nil {
		return proxyNode{}, false, err
	}

	if !ok {
		// A valid Forwarded element may omit for=, but then it does not
		// identify the preceding hop. Preserve it as an unverifiable trust
		// boundary instead of deleting it from the chain.
		return proxyNode{kind: proxyNodeUnknown, raw: s}, true, nil
	}

	node, err := parseForwardedNode(value)
	if err != nil {
		return proxyNode{}, false, err
	}

	return node, true, nil
}

func parseForwardedForValue(s string) (string, bool, error) {
	const inlineForwardedPairCount = 8

	var (
		i          int
		found      bool
		result     string
		inlineSeen [inlineForwardedPairCount]string
		seen       = inlineSeen[:0]
		seenMap    map[string]struct{}
	)

	for i < len(s) {
		if s[i] == ';' {
			// RFC 7239 permits an omitted forwarded-pair before or after a
			// semicolon. Preserve an entirely empty element as a missing-for
			// trust boundary instead of dropping it in the list splitter.
			i++
			continue
		}

		nameStart := i
		for i < len(s) && isTokenChar(s[i]) {
			i++
		}

		if i == nameStart {
			return "", false, ErrInvalidForwarded
		}

		name := s[nameStart:i]

		if seenMap == nil {
			if containsFold(seen, name) {
				return "", false, ErrInvalidForwarded
			}

			if len(seen) < cap(seen) {
				seen = append(seen, name)
			} else {
				seenMap = make(map[string]struct{}, len(seen)+1)
				for _, previous := range seen {
					seenMap[strings.ToLower(previous)] = struct{}{}
				}
			}
		}

		if seenMap != nil {
			normalizedName := strings.ToLower(name)
			if _, duplicate := seenMap[normalizedName]; duplicate {
				return "", false, ErrInvalidForwarded
			}

			seenMap[normalizedName] = struct{}{}
		}

		if i >= len(s) || s[i] != '=' {
			return "", false, ErrInvalidForwarded
		}

		i++

		value, next, err := consumeForwardedPairValue(s, i)
		if err != nil {
			return "", false, ErrInvalidForwarded
		}

		if err := validateForwardedPair(name, value); err != nil {
			return "", false, ErrInvalidForwarded
		}

		i = next

		if strings.EqualFold(name, "for") {
			found = true
			result = value
		}

		if i >= len(s) {
			break
		}

		if s[i] != ';' {
			return "", false, ErrInvalidForwarded
		}

		i++
	}

	return result, found, nil
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}

	return false
}

func validateForwardedPair(name, value string) error {
	switch {
	case strings.EqualFold(name, "by"):
		_, err := parseForwardedNode(value)
		return err
	case strings.EqualFold(name, "host"):
		return validateForwardedHost(value)
	case strings.EqualFold(name, "proto"):
		if !isValidURIScheme(value) {
			return ErrInvalidForwarded
		}
	}

	return nil
}

func consumeForwardedPairValue(s string, start int) (string, int, error) {
	if start >= len(s) {
		return "", start, ErrInvalidForwarded
	}

	if s[start] == '"' {
		return consumeForwardedQuotedString(s, start)
	}

	end := start

	for end < len(s) && isTokenChar(s[end]) {
		end++
	}

	if end == start {
		return "", start, ErrInvalidForwarded
	}

	return s[start:end], end, nil
}

func consumeForwardedQuotedString(s string, start int) (string, int, error) {
	var (
		b            strings.Builder
		unescaped    bool
		segmentStart = start + 1
	)

	for i := start + 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			if !unescaped {
				return s[segmentStart:i], i + 1, nil
			}

			b.WriteString(s[segmentStart:i])

			return b.String(), i + 1, nil
		case c == '\\':
			if !unescaped {
				b.Grow(len(s) - segmentStart)

				unescaped = true
			}

			b.WriteString(s[segmentStart:i])

			i++
			if i >= len(s) || !isQuotedPairChar(s[i]) {
				return "", start, ErrInvalidForwarded
			}

			b.WriteByte(s[i])
			segmentStart = i + 1
		case isQuotedTextChar(c):
		default:
			return "", start, ErrInvalidForwarded
		}
	}

	return "", start, ErrInvalidForwarded
}

func trimOWS(s string) string {
	return strings.Trim(s, " \t")
}

func isTokenChar(c byte) bool {
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
	}
}

func isQuotedTextChar(c byte) bool {
	return c == '\t' || c == ' ' || c == '!' || c >= '#' && c <= '[' || c >= ']' && c <= '~' || c >= 0x80
}

func isQuotedPairChar(c byte) bool {
	return c == '\t' || c == ' ' || c >= 0x21 && c <= 0x7e || c >= 0x80
}

func parseForwardedNode(v string) (proxyNode, error) {
	if v == "" {
		return proxyNode{}, ErrInvalidForwarded
	}

	if strings.HasPrefix(v, "[") {
		end := strings.IndexByte(v, ']')
		if end < 0 {
			return proxyNode{}, ErrInvalidForwarded
		}

		rawIP, err := netip.ParseAddr(v[1:end])
		if err != nil || !rawIP.Is6() || rawIP.Zone() != "" {
			return proxyNode{}, ErrInvalidForwarded
		}

		ip := normalizeAddr(rawIP)
		rest := v[end+1:]

		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return proxyNode{}, ErrInvalidForwarded
			}

			if err := validateForwardedPort(rest[1:]); err != nil {
				return proxyNode{}, err
			}
		}

		return proxyNode{kind: proxyNodeIP, addr: ip, raw: v}, nil
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
		return proxyNode{kind: proxyNodeUnknown, raw: v}, nil
	case strings.HasPrefix(host, "_"):
		if !isValidObfuscatedIdentifier(host) {
			return proxyNode{}, ErrInvalidForwarded
		}

		return proxyNode{kind: proxyNodeObfuscated, raw: v}, nil
	}

	ip, err := ParseAddr(host)
	if err != nil {
		return proxyNode{}, ErrInvalidForwarded
	}

	if ip.Is6() {
		return proxyNode{}, ErrInvalidForwarded
	}

	return proxyNode{kind: proxyNodeIP, addr: ip, raw: v}, nil
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

	if len(port) > 5 {
		return ErrInvalidForwarded
	}

	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return ErrInvalidForwarded
		}
	}

	return nil
}

func validateForwardedHost(value string) error {
	host := value

	if strings.HasPrefix(value, "[") {
		end := strings.IndexByte(value, ']')
		if end < 0 || end == 1 {
			return ErrInvalidForwarded
		}

		literal := value[1:end]

		addr, err := netip.ParseAddr(literal)
		if (err != nil || !addr.Is6() || addr.Zone() != "") && !isValidIPvFuture(literal) {
			return ErrInvalidForwarded
		}

		rest := value[end+1:]

		if rest == "" {
			return nil
		}

		if rest[0] != ':' || !isDecimal(rest[1:], true) {
			return ErrInvalidForwarded
		}

		return nil
	}

	if idx := strings.LastIndexByte(value, ':'); idx >= 0 {
		host = value[:idx]
		if strings.Contains(host, ":") || !isDecimal(value[idx+1:], true) {
			return ErrInvalidForwarded
		}
	}

	if !isValidURIRegName(host) {
		return ErrInvalidForwarded
	}

	return nil
}

func isValidURIScheme(value string) bool {
	if value == "" || !isASCIIAlpha(value[0]) {
		return false
	}

	for i := 1; i < len(value); i++ {
		c := value[i]
		if !isASCIIAlpha(c) && (c < '0' || c > '9') && c != '+' && c != '-' && c != '.' {
			return false
		}
	}

	return true
}

func isValidIPvFuture(value string) bool {
	if len(value) < 4 || value[0] != 'v' && value[0] != 'V' {
		return false
	}

	i := 1

	for i < len(value) && isHexDigit(value[i]) {
		i++
	}

	if i == 1 || i >= len(value) || value[i] != '.' {
		return false
	}

	i++

	if i >= len(value) {
		return false
	}

	for ; i < len(value); i++ {
		c := value[i]
		if !isURIUnreserved(c) && !isURISubDelimiter(c) && c != ':' {
			return false
		}
	}

	return true
}

func isValidURIRegName(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]

		switch {
		case isURIUnreserved(c), isURISubDelimiter(c):
			continue
		case c == '%' && i+2 < len(value) && isHexDigit(value[i+1]) && isHexDigit(value[i+2]):
			i += 2
		default:
			return false
		}
	}

	return true
}

func isURIUnreserved(c byte) bool {
	return isASCIIAlpha(c) || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

func isURISubDelimiter(c byte) bool {
	switch c {
	case '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=':
		return true
	default:
		return false
	}
}

func isASCIIAlpha(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f'
}

func isDecimal(value string, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
	}

	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}

	return true
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
