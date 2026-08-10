package ip

import (
	"errors"
	"strconv"
)

var (
	// ErrNoIP reports that no client IP could be determined.
	ErrNoIP = errors.New("ip: client IP not found")
	// ErrInvalidIP reports an invalid IP token in a proxy header.
	ErrInvalidIP = errors.New("ip: invalid IP")
	// ErrInvalidForwarded reports a malformed RFC 7239 Forwarded header value.
	ErrInvalidForwarded = errors.New("ip: invalid Forwarded header")
	// ErrInvalidHeader reports a malformed or unsupported proxy header value.
	ErrInvalidHeader = errors.New("ip: invalid proxy header")
	// ErrInvalidRemoteAddr reports an invalid transport-peer address.
	ErrInvalidRemoteAddr = errors.New("ip: invalid remote address")
	// ErrUntrustedProxy reports proxy headers received from an untrusted source.
	ErrUntrustedProxy = errors.New("ip: untrusted proxy")
	// ErrUnverifiableChain reports a syntactically valid proxy-chain element
	// that does not identify a verifiable preceding hop, such as unknown, an
	// obfuscated node, or a Forwarded element without for=.
	ErrUnverifiableChain = errors.New("ip: unverifiable proxy chain")
	// ErrAmbiguousHeader reports multiple physical header keys for one configured
	// name or multiple values for a single-value header.
	ErrAmbiguousHeader = errors.New("ip: ambiguous proxy header")
	// ErrConflictingHeaders reports trusted headers resolving to different IPs.
	ErrConflictingHeaders = errors.New("ip: conflicting proxy headers")
	// ErrInvalidConfig reports invalid extractor configuration.
	ErrInvalidConfig = errors.New("ip: invalid configuration")
	// ErrMissingTrustedProxies reports that allow-list mode was selected without
	// configuring any trusted proxies.
	ErrMissingTrustedProxies = errors.New("ip: trusted proxies are required")
	// ErrInvalidTrustedProxy reports an invalid trusted proxy IP or CIDR.
	ErrInvalidTrustedProxy = errors.New("ip: invalid trusted proxy")
	// ErrLimitExceeded reports that proxy metadata exceeded a configured
	// resource limit.
	ErrLimitExceeded = errors.New("ip: proxy metadata limit exceeded")
	// ErrHeaderTooLarge reports that configured proxy header values exceed the
	// maximum aggregate byte count.
	ErrHeaderTooLarge = errors.New("ip: proxy headers too large")
	// ErrTooManyHeaderValues reports too many physical proxy header values.
	ErrTooManyHeaderValues = errors.New("ip: too many proxy header values")
	// ErrTooManyHops reports a proxy chain longer than the configured maximum.
	ErrTooManyHops = errors.New("ip: too many proxy hops")
	// ErrTokenTooLarge reports a proxy-chain token longer than the configured
	// maximum.
	ErrTokenTooLarge = errors.New("ip: proxy token too large")
)

// LimitError describes a resource limit exceeded while processing proxy
// metadata.
type LimitError struct {
	// Limit is the configured maximum.
	Limit int
	// Actual is the observed value that exceeded Limit.
	Actual int
	// Err identifies the specific limit that was exceeded.
	Err error
}

func (e *LimitError) Error() string {
	return e.Err.Error() + ": limit " + strconv.Itoa(e.Limit) + ", actual " + strconv.Itoa(e.Actual)
}

// Unwrap returns both [ErrLimitExceeded] and the specific error in e.Err.
func (e *LimitError) Unwrap() error {
	return errors.Join(ErrLimitExceeded, e.Err)
}

// HeaderError describes a problem with a specific header or header-like field.
type HeaderError struct {
	// Header identifies the header or transport field that failed validation.
	Header string
	// Value is the offending value when one is available.
	Value string
	// Err is the underlying validation error.
	Err error
}

func (e *HeaderError) Error() string {
	switch {
	case e.Header == "" && e.Value == "":
		return e.Err.Error()
	case e.Value == "":
		return e.Header + ": " + e.Err.Error()
	default:
		return e.Header + " " + strconv.Quote(e.Value) + ": " + e.Err.Error()
	}
}

// Unwrap returns the underlying validation error.
func (e *HeaderError) Unwrap() error {
	return e.Err
}

// ConfigError describes an invalid extractor option or constructor argument.
type ConfigError struct {
	// Option identifies the invalid option or configuration field.
	Option string
	// Value is the rejected value when one is available.
	Value string
	// Err is the underlying configuration error.
	Err error
}

func (e *ConfigError) Error() string {
	switch {
	case e.Option == "" && e.Value == "":
		return e.Err.Error()
	case e.Value == "":
		return e.Option + ": " + e.Err.Error()
	default:
		return e.Option + " " + strconv.Quote(e.Value) + ": " + e.Err.Error()
	}
}

// Unwrap returns the underlying configuration error.
func (e *ConfigError) Unwrap() error {
	return e.Err
}

func wrapRemoteAddrError(value string, err error) error {
	return &HeaderError{
		Header: "RemoteAddr",
		Value:  formatHeaderValue(value),
		Err:    errors.Join(ErrInvalidRemoteAddr, err),
	}
}

func wrapHeaderError(header, value string, err error) error {
	switch {
	case errors.Is(err, ErrInvalidForwarded):
		return &HeaderError{Header: header, Value: value, Err: err}
	case errors.Is(err, ErrInvalidIP):
		return &HeaderError{Header: header, Value: value, Err: err}
	default:
		return &HeaderError{Header: header, Value: value, Err: errors.Join(ErrInvalidHeader, err)}
	}
}
