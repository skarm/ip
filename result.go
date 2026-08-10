package ip

import (
	"net/netip"
	"strconv"
)

// Source identifies where an extracted address came from.
type Source uint8

const (
	// SourceRemoteAddr means the address came from the immediate transport
	// peer.
	SourceRemoteAddr Source = iota
	// SourceProxyHeader means the address came from the header named by
	// [Result.Header].
	SourceProxyHeader
)

// String returns the Go-style symbolic name of s.
func (s Source) String() string {
	switch s {
	case SourceRemoteAddr:
		return "SourceRemoteAddr"
	case SourceProxyHeader:
		return "SourceProxyHeader"
	default:
		return "Source(" + strconv.FormatUint(uint64(s), 10) + ")"
	}
}

// Reason explains why the extractor selected Result.Addr.
type Reason uint8

const (
	// ReasonSelectedHeader means a configured proxy header supplied the selected
	// client address.
	ReasonSelectedHeader Reason = iota
	// ReasonProxyHeadersDenied means proxy headers were disabled and the immediate
	// transport peer was selected.
	ReasonProxyHeadersDenied
	// ReasonUntrustedImmediatePeer means the immediate peer was not trusted to
	// supply proxy headers and was selected instead.
	ReasonUntrustedImmediatePeer
	// ReasonNoProxyHeaders means no configured proxy header supplied a usable
	// address, so the immediate transport peer was selected.
	ReasonNoProxyHeaders
	// ReasonUnverifiableChain means an unverifiable chain element stopped trust
	// traversal and caused a fallback to the immediate transport peer.
	ReasonUnverifiableChain
	// ReasonNoUntrustedHop means every parsed chain address was trusted, so the
	// immediate transport peer was selected conservatively.
	ReasonNoUntrustedHop
)

// String returns the Go-style symbolic name of r.
func (r Reason) String() string {
	switch r {
	case ReasonSelectedHeader:
		return "ReasonSelectedHeader"
	case ReasonProxyHeadersDenied:
		return "ReasonProxyHeadersDenied"
	case ReasonUntrustedImmediatePeer:
		return "ReasonUntrustedImmediatePeer"
	case ReasonNoProxyHeaders:
		return "ReasonNoProxyHeaders"
	case ReasonUnverifiableChain:
		return "ReasonUnverifiableChain"
	case ReasonNoUntrustedHop:
		return "ReasonNoUntrustedHop"
	default:
		return "Reason(" + strconv.FormatUint(uint64(r), 10) + ")"
	}
}

// Result contains an extracted address and its trust provenance.
type Result struct {
	// Addr is the normalized selected address.
	Addr netip.Addr
	// Header names the configured proxy header that participated in the decision.
	// It is empty when no proxy header participated.
	Header string
	// TrustedHops is the number of trusted proxy identities verified before the
	// decision. In allow-list mode it includes the immediate transport peer.
	TrustedHops int
	// Source identifies whether Addr came from the transport peer or a proxy
	// header.
	Source Source
	// Reason explains why Addr was selected.
	Reason Reason
}
