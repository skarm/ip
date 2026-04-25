package grpcip_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/skarm/ip"
	grpcip "github.com/skarm/ip/grpc"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func TestUnaryServerInterceptorStoresExtractedIP(t *testing.T) {
	ex := mustExtractor(t, ip.WithTrustedProxies("10.0.0.2"))
	ctx := incomingContext(
		map[string][]string{ip.XForwardedFor: {"198.51.100.10"}},
		tcpAddr("10.0.0.2:443"),
	)

	var got netip.Addr
	interceptor := grpcip.UnaryServerInterceptor(ex)
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Call"}, func(ctx context.Context, req any) (any, error) {
		got, _ = ip.Ctx(ctx)
		return nil, nil
	})
	if err != nil {
		t.Fatalf("UnaryServerInterceptor() error = %v", err)
	}
	if got.String() != "198.51.100.10" {
		t.Fatalf("expected context IP %q, got %q", "198.51.100.10", got.String())
	}
}

func TestExtract(t *testing.T) {
	ex := mustExtractor(t, ip.WithTrustedProxies("10.0.0.2"))
	ctx := incomingContext(
		map[string][]string{ip.XForwardedFor: {"198.51.100.10"}},
		tcpAddr("10.0.0.2:443"),
	)

	got, err := grpcip.Extract(ctx, ex)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if got.String() != "198.51.100.10" {
		t.Fatalf("expected extracted IP %q, got %q", "198.51.100.10", got.String())
	}
}

func TestUnaryServerInterceptorLeavesContextUnchangedOnExtractError(t *testing.T) {
	ex := mustExtractor(t)
	ctx := incomingContext(
		map[string][]string{ip.XForwardedFor: {"198.51.100.10"}},
		unixAddr("/tmp/grpc.sock"),
	)

	interceptor := grpcip.UnaryServerInterceptor(ex)
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Call"}, func(ctx context.Context, req any) (any, error) {
		if _, ok := ip.Ctx(ctx); ok {
			t.Fatal("expected context to stay unchanged")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("UnaryServerInterceptor() error = %v", err)
	}
}

func TestStreamServerInterceptorStoresExtractedIP(t *testing.T) {
	ex := mustExtractor(t, ip.WithTrustedProxies("10.0.0.2"))
	ctx := incomingContext(
		map[string][]string{ip.XForwardedFor: {"198.51.100.10"}},
		tcpAddr("10.0.0.2:443"),
	)

	var got netip.Addr
	interceptor := grpcip.StreamServerInterceptor(ex)
	err := interceptor(nil, &testServerStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: "/test.Service/Stream"}, func(srv any, stream grpc.ServerStream) error {
		got, _ = ip.Ctx(stream.Context())
		return nil
	})
	if err != nil {
		t.Fatalf("StreamServerInterceptor() error = %v", err)
	}
	if got.String() != "198.51.100.10" {
		t.Fatalf("expected context IP %q, got %q", "198.51.100.10", got.String())
	}
}

func TestStreamServerInterceptorLeavesContextUnchangedOnExtractError(t *testing.T) {
	ex := mustExtractor(t)
	ctx := incomingContext(
		map[string][]string{ip.XForwardedFor: {"198.51.100.10"}},
		unixAddr("/tmp/grpc.sock"),
	)

	interceptor := grpcip.StreamServerInterceptor(ex)
	err := interceptor(nil, &testServerStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: "/test.Service/Stream"}, func(srv any, stream grpc.ServerStream) error {
		if _, ok := ip.Ctx(stream.Context()); ok {
			t.Fatal("expected context to stay unchanged")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("StreamServerInterceptor() error = %v", err)
	}
}

func TestUnaryClientPropagationInterceptorAddsOutgoingHeader(t *testing.T) {
	ctx := ip.WithContext(context.Background(), netip.MustParseAddr("198.51.100.10"))
	interceptor := grpcip.UnaryClientPropagationInterceptor()

	var got []string
	err := interceptor(ctx, "/test.Service/Call", nil, nil, nil, func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			t.Fatal("expected outgoing metadata")
		}
		got = md.Get(ip.Forwarded)
		return nil
	})
	if err != nil {
		t.Fatalf("UnaryClientPropagationInterceptor() error = %v", err)
	}
	if len(got) != 1 || got[0] != "for=198.51.100.10" {
		t.Fatalf("expected outgoing %q metadata, got %v", ip.Forwarded, got)
	}
}

func TestUnaryClientPropagationInterceptorFormatsIPv6(t *testing.T) {
	ctx := ip.WithContext(context.Background(), netip.MustParseAddr("2001:db8::1"))
	interceptor := grpcip.UnaryClientPropagationInterceptor()

	var got []string
	err := interceptor(ctx, "/test.Service/Call", nil, nil, nil, func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			t.Fatal("expected outgoing metadata")
		}
		got = md.Get(ip.Forwarded)
		return nil
	})
	if err != nil {
		t.Fatalf("UnaryClientPropagationInterceptor() error = %v", err)
	}
	if len(got) != 1 || got[0] != `for="[2001:db8::1]"` {
		t.Fatalf("expected outgoing %q metadata, got %v", ip.Forwarded, got)
	}
}

func TestUnaryClientPropagationInterceptorUnmapsIPv4MappedIPv6(t *testing.T) {
	ctx := ip.WithContext(context.Background(), netip.MustParseAddr("::ffff:198.51.100.10"))
	interceptor := grpcip.UnaryClientPropagationInterceptor()

	var got []string
	err := interceptor(ctx, "/test.Service/Call", nil, nil, nil, func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			t.Fatal("expected outgoing metadata")
		}
		got = md.Get(ip.Forwarded)
		return nil
	})
	if err != nil {
		t.Fatalf("UnaryClientPropagationInterceptor() error = %v", err)
	}
	if len(got) != 1 || got[0] != "for=198.51.100.10" {
		t.Fatalf("expected outgoing %q metadata, got %v", ip.Forwarded, got)
	}
}

func TestUnaryClientPropagationInterceptorStripsIPv6Zone(t *testing.T) {
	addr, err := netip.ParseAddr("fe80::1%eth0")
	if err != nil {
		t.Fatalf("ParseAddr() error = %v", err)
	}

	ctx := ip.WithContext(context.Background(), addr)
	interceptor := grpcip.UnaryClientPropagationInterceptor()

	var got []string
	err = interceptor(ctx, "/test.Service/Call", nil, nil, nil, func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			t.Fatal("expected outgoing metadata")
		}
		got = md.Get(ip.Forwarded)
		return nil
	})
	if err != nil {
		t.Fatalf("UnaryClientPropagationInterceptor() error = %v", err)
	}
	if len(got) != 1 || got[0] != `for="[fe80::1]"` {
		t.Fatalf("expected outgoing %q metadata, got %v", ip.Forwarded, got)
	}
}

func TestUnaryClientPropagationInterceptorLeavesContextWithoutIP(t *testing.T) {
	interceptor := grpcip.UnaryClientPropagationInterceptor()

	err := interceptor(context.Background(), "/test.Service/Call", nil, nil, nil, func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		if md, ok := metadata.FromOutgoingContext(ctx); ok && len(md.Get(ip.Forwarded)) > 0 {
			t.Fatal("expected no forwarded metadata")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("UnaryClientPropagationInterceptor() error = %v", err)
	}
}

func TestStreamClientPropagationInterceptorAddsOutgoingHeader(t *testing.T) {
	ctx := ip.WithContext(context.Background(), netip.MustParseAddr("198.51.100.10"))
	interceptor := grpcip.StreamClientPropagationInterceptor()

	var got []string
	_, err := interceptor(ctx, &grpc.StreamDesc{}, nil, "/test.Service/Stream", func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			t.Fatal("expected outgoing metadata")
		}
		got = md.Get(ip.Forwarded)
		return nil, nil
	})
	if err != nil {
		t.Fatalf("StreamClientPropagationInterceptor() error = %v", err)
	}
	if len(got) != 1 || got[0] != "for=198.51.100.10" {
		t.Fatalf("expected outgoing %q metadata, got %v", ip.Forwarded, got)
	}
}

func mustExtractor(t *testing.T, opts ...ip.Option) *ip.Extractor {
	t.Helper()

	ex, err := ip.New(opts...)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return ex
}

func incomingContext(headers map[string][]string, addr net.Addr) context.Context {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD(headers))
	return peer.NewContext(ctx, &peer.Peer{Addr: addr})
}

func tcpAddr(addr string) net.Addr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(addr))
}

func unixAddr(name string) net.Addr {
	return &net.UnixAddr{Name: name, Net: "unix"}
}

type testServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *testServerStream) Context() context.Context {
	return s.ctx
}

func (s *testServerStream) SetHeader(metadata.MD) error {
	return nil
}

func (s *testServerStream) SendHeader(metadata.MD) error {
	return nil
}

func (s *testServerStream) SetTrailer(metadata.MD) {}

func (s *testServerStream) SendMsg(any) error {
	return nil
}

func (s *testServerStream) RecvMsg(any) error {
	return io.EOF
}
