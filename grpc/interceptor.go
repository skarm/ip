// Package grpcip connects [ip.Extractor] to gRPC server and client
// interceptors.
//
// Server interceptors extract an address from incoming metadata and the
// transport peer. Client interceptors propagate an address previously stored
// with [ip.WithContext]. The extractor's proxy mode and trusted-peer
// configuration determine whether incoming metadata is trusted.
package grpcip

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/skarm/ip"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// OriginalClientIP is a dedicated metadata key for propagating a normalized
// original client IP between authenticated internal services. Pass
// OriginalClientIP to [ip.WithHeaders] when configuring the receiving
// extractor.
const OriginalClientIP = "original-client-ip"

// ServerErrorHandler maps a server-side extraction failure to an RPC error.
// Returning nil preserves best-effort behavior and continues with the original
// context.
type ServerErrorHandler func(context.Context, error) error

// Extract returns the client IP address extracted from the incoming RPC
// context.
//
// Incoming metadata is treated as request headers and peer.Addr.String() is
// used as the remote address. The extractor applies the same trust model and
// parsing rules as [ip.Extractor.ExtractFrom]. Extract returns [ip.ErrNoIP] when
// ex is nil. Other failures, including a missing peer address, are reported by
// [ip.Extractor.ExtractFrom].
func Extract(ctx context.Context, ex *ip.Extractor) (netip.Addr, error) {
	if ex == nil {
		return netip.Addr{}, ip.ErrNoIP
	}

	return ex.ExtractFrom(headerValues(ctx), remoteAddr(ctx))
}

// UnaryServerInterceptor returns best-effort unary server middleware that
// stores a successfully extracted client IP in the RPC context.
//
// If extraction fails, UnaryServerInterceptor discards the error and calls the
// handler with the original context.
func UnaryServerInterceptor(ex *ip.Extractor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, _ = contextWithIP(ctx, ex)
		return handler(ctx, req)
	}
}

// UnaryServerInterceptorWithErrorHandler returns unary server middleware that
// stores a successfully extracted client IP in the RPC context.
//
// On extraction failure it calls onError. A non-nil returned error rejects the
// RPC without calling the handler. A nil error calls the handler with the
// original context. UnaryServerInterceptorWithErrorHandler panics if onError is
// nil.
func UnaryServerInterceptorWithErrorHandler(ex *ip.Extractor, onError ServerErrorHandler) grpc.UnaryServerInterceptor {
	if onError == nil {
		panic("grpcip: nil server error handler")
	}

	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		contextWithAddr, err := contextWithIP(ctx, ex)
		if err != nil {
			if mapped := onError(ctx, err); mapped != nil {
				return nil, mapped
			}

			contextWithAddr = ctx
		}

		return handler(contextWithAddr, req)
	}
}

// StreamServerInterceptor returns best-effort stream server middleware that
// stores a successfully extracted client IP in the stream context.
//
// If extraction fails, StreamServerInterceptor discards the error and calls the
// handler with the original stream context.
func StreamServerInterceptor(ex *ip.Extractor) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, _ := contextWithIP(stream.Context(), ex)
		return handler(srv, &serverStream{ServerStream: stream, ctx: ctx})
	}
}

// StreamServerInterceptorWithErrorHandler returns stream server middleware that
// stores a successfully extracted client IP in the stream context.
//
// On extraction failure it calls onError. A non-nil returned error rejects the
// RPC without calling the handler. A nil error calls the handler with the
// original stream context. StreamServerInterceptorWithErrorHandler panics if
// onError is nil.
func StreamServerInterceptorWithErrorHandler(ex *ip.Extractor, onError ServerErrorHandler) grpc.StreamServerInterceptor {
	if onError == nil {
		panic("grpcip: nil server error handler")
	}

	return func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := contextWithIP(stream.Context(), ex)
		if err != nil {
			if mapped := onError(stream.Context(), err); mapped != nil {
				return mapped
			}

			ctx = stream.Context()
		}

		return handler(srv, &serverStream{ServerStream: stream, ctx: ctx})
	}
}

// ErrInvalidForwardedBy reports an invalid RFC 7239 by node supplied to
// [WithForwardedBy].
var ErrInvalidForwardedBy = errors.New("grpcip: invalid Forwarded by node")

// ClientPropagationOption configures RFC 7239 Forwarded client propagation.
// Implementations are provided by this package; external implementations are
// not supported.
type ClientPropagationOption interface {
	applyClientPropagation(*clientPropagationConfig) error
}

type clientPropagationOptionFunc func(*clientPropagationConfig) error

func (f clientPropagationOptionFunc) applyClientPropagation(cfg *clientPropagationConfig) error {
	return f(cfg)
}

type clientPropagationConfig struct {
	forwardedBy string
}

// WithForwardedBy adds an RFC 7239 by parameter to propagated Forwarded values.
// The node must be an IP address, "unknown", or an obfuscated node beginning
// with an underscore, such as "_orders_api".
//
// The by parameter is diagnostic metadata, not an authenticated service
// identity.
// Use mTLS, SPIFFE, or another authenticated transport identity for
// authorization decisions.
func WithForwardedBy(node string) ClientPropagationOption {
	return clientPropagationOptionFunc(func(cfg *clientPropagationConfig) error {
		formatted, err := formatForwardedBy(node)
		if err != nil {
			return err
		}

		cfg.forwardedBy = formatted

		return nil
	})
}

// UnaryClientPropagationInterceptor returns a unary client interceptor that
// propagates the client IP stored in the RPC context through RFC 7239 Forwarded
// metadata.
//
// When the context contains a valid address, the interceptor replaces existing
// Forwarded values and emits one for parameter. Otherwise it removes existing
// Forwarded values. Use [NewUnaryClientPropagationInterceptor] with
// [WithForwardedBy] to include a by parameter.
func UnaryClientPropagationInterceptor() grpc.UnaryClientInterceptor {
	interceptor, _ := NewUnaryClientPropagationInterceptor()
	return interceptor
}

// NewUnaryClientPropagationInterceptor returns a configured unary client
// propagation interceptor. It validates options before returning.
func NewUnaryClientPropagationInterceptor(options ...ClientPropagationOption) (grpc.UnaryClientInterceptor, error) {
	cfg, err := newClientPropagationConfig(options)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(contextWithOutgoingIP(ctx, cfg.forwardedBy), method, req, reply, cc, opts...)
	}, nil
}

// StreamClientPropagationInterceptor returns a stream client interceptor that
// propagates the client IP stored in the RPC context through RFC 7239 Forwarded
// metadata.
//
// When the context contains a valid address, the interceptor replaces existing
// Forwarded values and emits one for parameter. Otherwise it removes existing
// Forwarded values. Use [NewStreamClientPropagationInterceptor] with
// [WithForwardedBy] to include a by parameter.
func StreamClientPropagationInterceptor() grpc.StreamClientInterceptor {
	interceptor, _ := NewStreamClientPropagationInterceptor()
	return interceptor
}

// NewStreamClientPropagationInterceptor returns a configured stream client
// propagation interceptor. It validates options before returning.
func NewStreamClientPropagationInterceptor(options ...ClientPropagationOption) (grpc.StreamClientInterceptor, error) {
	cfg, err := newClientPropagationConfig(options)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return streamer(contextWithOutgoingIP(ctx, cfg.forwardedBy), desc, cc, method, opts...)
	}, nil
}

func newClientPropagationConfig(options []ClientPropagationOption) (clientPropagationConfig, error) {
	var cfg clientPropagationConfig

	for _, option := range options {
		if option == nil {
			return clientPropagationConfig{}, errors.New("grpcip: nil client propagation option")
		}

		if err := option.applyClientPropagation(&cfg); err != nil {
			return clientPropagationConfig{}, err
		}
	}

	return cfg, nil
}

// UnaryClientOriginalIPInterceptor returns a unary client interceptor that
// propagates the normalized client IP under [OriginalClientIP].
//
// When the context contains a valid address, the interceptor replaces existing
// values with one raw IP value. Otherwise it removes existing values of that
// key. The transport must authenticate the calling service, and the receiver
// must trust only authenticated peers.
func UnaryClientOriginalIPInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(contextWithOutgoingOriginalIP(ctx), method, req, reply, cc, opts...)
	}
}

// StreamClientOriginalIPInterceptor returns the stream-client equivalent of
// [UnaryClientOriginalIPInterceptor].
func StreamClientOriginalIPInterceptor() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return streamer(contextWithOutgoingOriginalIP(ctx), desc, cc, method, opts...)
	}
}

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *serverStream) Context() context.Context {
	return s.ctx
}

func contextWithIP(ctx context.Context, ex *ip.Extractor) (context.Context, error) {
	addr, err := Extract(ctx, ex)
	if err != nil {
		return ctx, err
	}

	return ip.WithContext(ctx, addr), nil
}

func contextWithOutgoingIP(ctx context.Context, forwardedBy string) context.Context {
	return contextWithOutgoingValue(ctx, ip.Forwarded, func(addr netip.Addr) string {
		return formatForwarded(addr, forwardedBy)
	})
}

func contextWithOutgoingOriginalIP(ctx context.Context) context.Context {
	return contextWithOutgoingValue(ctx, OriginalClientIP, func(addr netip.Addr) string {
		return addr.Unmap().WithZone("").String()
	})
}

func contextWithOutgoingValue(ctx context.Context, key string, format func(netip.Addr) string) context.Context {
	addr, ok := ip.Ctx(ctx)
	if !ok || !addr.IsValid() {
		md, hasMetadata := metadata.FromOutgoingContext(ctx)
		if !hasMetadata || len(md.Get(key)) == 0 {
			return ctx
		}

		md = md.Copy()
		md.Delete(key)

		return metadata.NewOutgoingContext(ctx, md)
	}

	value := format(addr)

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		return metadata.AppendToOutgoingContext(ctx, key, value)
	}

	md = md.Copy()
	md.Set(key, value)

	return metadata.NewOutgoingContext(ctx, md)
}

func formatForwarded(addr netip.Addr, forwardedBy string) (value string) {
	addr = addr.Unmap().WithZone("")

	if addr.Is6() {
		value = `for="[` + addr.String() + `]"`
	} else {
		value = "for=" + addr.String()
	}

	if forwardedBy != "" {
		value += ";by=" + forwardedBy
	}

	return value
}

func formatForwardedBy(node string) (string, error) {
	if node == "" || strings.TrimSpace(node) != node {
		return "", ErrInvalidForwardedBy
	}

	if addr, err := netip.ParseAddr(node); err == nil {
		if addr.Zone() != "" {
			return "", ErrInvalidForwardedBy
		}

		addr = addr.Unmap()

		if addr.Is6() {
			return `"[` + addr.String() + `]"`, nil
		}

		return addr.String(), nil
	}

	if strings.EqualFold(node, "unknown") {
		return "unknown", nil
	}

	if validObfuscatedNode(node) {
		return node, nil
	}

	return "", ErrInvalidForwardedBy
}

func validObfuscatedNode(node string) bool {
	if len(node) < 2 || node[0] != '_' {
		return false
	}

	for i := 1; i < len(node); i++ {
		c := node[i]

		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			continue
		}

		return false
	}

	return true
}

func headerValues(ctx context.Context) map[string][]string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}

	return md
}

func remoteAddr(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}

	if addr, ok := p.Addr.(*net.TCPAddr); ok {
		return addr.AddrPort().String()
	}

	return p.Addr.String()
}
