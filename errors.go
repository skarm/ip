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
	// ErrInvalidRemoteAddr reports an invalid Request.RemoteAddr value.
	ErrInvalidRemoteAddr = errors.New("ip: invalid remote address")
	// ErrUntrustedProxy reports proxy headers received from an untrusted source.
	ErrUntrustedProxy = errors.New("ip: untrusted proxy")
	// ErrAmbiguousHeader reports duplicate or ambiguous single-value headers.
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
)

// HeaderError describes a problem with a specific header or header-like field.
type HeaderError struct {
	Header string
	Value  string
	Err    error
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

func (e *HeaderError) Unwrap() error {
	return e.Err
}

// ConfigError describes an invalid extractor option or constructor argument.
type ConfigError struct {
	Option string
	Value  string
	Err    error
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

func (e *ConfigError) Unwrap() error {
	return e.Err
}

func wrapRemoteAddrError(value string, err error) error {
	return &HeaderError{
		Header: "RemoteAddr",
		Value:  value,
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
