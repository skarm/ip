// Package grpcip provides gRPC helpers and interceptors for extracting and
// propagating client IP addresses.
package grpcip

import (
	"context"
	"net/netip"

	"github.com/skarm/ip"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// Extract returns the client IP address extracted from the incoming RPC
// context.
//
// Incoming metadata is treated as request headers and peer.Addr.String() is
// used as the remote address. The extractor applies the same trust model and
// parsing rules as Extractor.ExtractFrom.
func Extract(ctx context.Context, ex *ip.Extractor) (netip.Addr, error) {
	if ex == nil {
		return netip.Addr{}, ip.ErrNoIP
	}

	return ex.ExtractFrom(headerValues(ctx), remoteAddr(ctx))
}

// UnaryServerInterceptor returns a unary server interceptor that stores the
// extracted client IP in the RPC context.
//
// The interceptor uses incoming metadata as headers and peer.Addr.String() as
// the remote address. If extraction fails, the original context is preserved.
func UnaryServerInterceptor(ex *ip.Extractor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(contextWithIP(ctx, ex), req)
	}
}

// StreamServerInterceptor returns a stream server interceptor that stores the
// extracted client IP in the stream context.
//
// The interceptor uses incoming metadata as headers and peer.Addr.String() as
// the remote address. If extraction fails, the original stream context is
// preserved.
func StreamServerInterceptor(ex *ip.Extractor) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, &serverStream{ServerStream: stream, ctx: contextWithIP(stream.Context(), ex)})
	}
}

// UnaryClientPropagationInterceptor returns a unary client interceptor that
// propagates the client IP stored in ctx to outgoing RPC metadata.
//
// The interceptor appends a forwarded header with a single for= parameter when
// ip.Ctx(ctx) contains a valid address. It propagates the original client IP;
// it does not attempt to synthesize a full proxy hop record with by=.
func UnaryClientPropagationInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(contextWithOutgoingIP(ctx), method, req, reply, cc, opts...)
	}
}

// StreamClientPropagationInterceptor returns a stream client interceptor that
// propagates the client IP stored in ctx to outgoing RPC metadata.
//
// The interceptor appends a forwarded header with a single for= parameter when
// ip.Ctx(ctx) contains a valid address. It propagates the original client IP;
// it does not attempt to synthesize a full proxy hop record with by=.
func StreamClientPropagationInterceptor() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return streamer(contextWithOutgoingIP(ctx), desc, cc, method, opts...)
	}
}

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *serverStream) Context() context.Context {
	return s.ctx
}

func contextWithIP(ctx context.Context, ex *ip.Extractor) context.Context {
	if addr, err := Extract(ctx, ex); err == nil {
		return ip.WithContext(ctx, addr)
	}

	return ctx
}

func contextWithOutgoingIP(ctx context.Context) context.Context {
	addr, ok := ip.Ctx(ctx)
	if !ok || !addr.IsValid() {
		return ctx
	}

	return metadata.AppendToOutgoingContext(ctx, ip.Forwarded, formatForwarded(addr))
}

func formatForwarded(addr netip.Addr) string {
	addr = addr.Unmap().WithZone("")

	if addr.Is6() {
		return `for="[` + addr.String() + `]"`
	}

	return "for=" + addr.String()
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

	return p.Addr.String()
}
