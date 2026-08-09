package grpcip_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/skarm/ip"
	grpcip "github.com/skarm/ip/grpc"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestUnaryServerInterceptorStoresExtractedIP(t *testing.T) {
	ex := mustExtractor(t, ip.WithTrustedProxies("10.0.0.2"))
	ctx := incomingContext(
		map[string][]string{ip.XForwardedFor: {"198.51.100.10"}},
		tcpAddr(),
	)

	var got netip.Addr
	interceptor := grpcip.UnaryServerInterceptor(ex)
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Call"}, func(ctx context.Context, _ any) (any, error) {
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
		tcpAddr(),
	)

	got, err := grpcip.Extract(ctx, ex)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if got.String() != "198.51.100.10" {
		t.Fatalf("expected extracted IP %q, got %q", "198.51.100.10", got.String())
	}
}

func TestExtractRejectsNilExtractor(t *testing.T) {
	got, err := grpcip.Extract(context.Background(), nil)
	if !errors.Is(err, ip.ErrNoIP) {
		t.Fatalf("Extract() error = %v, want ErrNoIP", err)
	}
	if got.IsValid() {
		t.Fatalf("Extract() address = %v, want invalid address", got)
	}
}

func TestExtractWithoutPeerReturnsRemoteAddressError(t *testing.T) {
	ex := mustExtractor(t)

	_, err := grpcip.Extract(context.Background(), ex)
	if !errors.Is(err, ip.ErrInvalidRemoteAddr) {
		t.Fatalf("Extract() error = %v, want ErrInvalidRemoteAddr", err)
	}
}

func TestExtractAllowAllUsesMetadataWithoutPeer(t *testing.T) {
	ex := mustExtractor(t,
		ip.WithHeaders(grpcip.OriginalClientIP),
		ip.WithUnsafeTrustAllProxies(),
	)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		grpcip.OriginalClientIP, "198.51.100.10",
	))

	got, err := grpcip.Extract(ctx, ex)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if got != netip.MustParseAddr("198.51.100.10") {
		t.Fatalf("Extract() = %v, want 198.51.100.10", got)
	}
}

func TestUnaryServerInterceptorLeavesContextUnchangedOnExtractError(t *testing.T) {
	ex := mustExtractor(t)
	ctx := incomingContext(
		map[string][]string{ip.XForwardedFor: {"198.51.100.10"}},
		unixAddr("/tmp/grpc.sock"),
	)

	interceptor := grpcip.UnaryServerInterceptor(ex)
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Call"}, func(ctx context.Context, _ any) (any, error) {
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
		tcpAddr(),
	)

	var got netip.Addr
	interceptor := grpcip.StreamServerInterceptor(ex)
	err := interceptor(nil, &testServerStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: "/test.Service/Stream"}, func(_ any, stream grpc.ServerStream) error {
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
	err := interceptor(nil, &testServerStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: "/test.Service/Stream"}, func(_ any, stream grpc.ServerStream) error {
		if _, ok := ip.Ctx(stream.Context()); ok {
			t.Fatal("expected context to stay unchanged")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("StreamServerInterceptor() error = %v", err)
	}
}

func TestUnaryServerInterceptorWithErrorHandlerMapsError(t *testing.T) {
	ex := mustExtractor(t, ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2"))
	ctx := incomingContext(
		map[string][]string{ip.XForwardedFor: {"not-an-ip"}},
		tcpAddr(),
	)

	var got error
	interceptor := grpcip.UnaryServerInterceptorWithErrorHandler(ex, func(_ context.Context, err error) error {
		got = err
		return status.Error(codes.PermissionDenied, "rejected")
	})
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Call"}, func(context.Context, any) (any, error) {
		t.Fatal("handler must not be called")
		return nil, nil
	})
	if !errors.Is(got, ip.ErrInvalidIP) {
		t.Fatalf("mapped extraction error = %v, want ErrInvalidIP", got)
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status code = %v, want %v", status.Code(err), codes.PermissionDenied)
	}
}

func TestStreamServerInterceptorWithErrorHandlerMapsError(t *testing.T) {
	ex := mustExtractor(t, ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2"))
	ctx := incomingContext(
		map[string][]string{ip.XForwardedFor: {"not-an-ip"}},
		tcpAddr(),
	)

	var got error
	interceptor := grpcip.StreamServerInterceptorWithErrorHandler(ex, func(_ context.Context, err error) error {
		got = err
		return status.Error(codes.PermissionDenied, "rejected")
	})
	err := interceptor(nil, &testServerStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: "/test.Service/Stream"}, func(any, grpc.ServerStream) error {
		t.Fatal("handler must not be called")
		return nil
	})
	if !errors.Is(got, ip.ErrInvalidIP) {
		t.Fatalf("mapped extraction error = %v, want ErrInvalidIP", got)
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status code = %v, want %v", status.Code(err), codes.PermissionDenied)
	}
}

func TestUnaryServerInterceptorWithErrorHandlerContinues(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		wantAddr    netip.Addr
		wantOnError bool
	}{
		{
			name: "successful extraction",
			ctx: incomingContext(
				map[string][]string{ip.XForwardedFor: {"198.51.100.10"}},
				tcpAddr(),
			),
			wantAddr: netip.MustParseAddr("198.51.100.10"),
		},
		{
			name: "ignored extraction error",
			ctx: incomingContext(
				map[string][]string{ip.XForwardedFor: {"not-an-ip"}},
				tcpAddr(),
			),
			wantOnError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := mustExtractor(t, ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2"))
			onErrorCalled := false
			interceptor := grpcip.UnaryServerInterceptorWithErrorHandler(ex, func(context.Context, error) error {
				onErrorCalled = true
				return nil
			})

			var gotAddr netip.Addr
			_, err := interceptor(tt.ctx, nil, nil, func(ctx context.Context, _ any) (any, error) {
				gotAddr, _ = ip.Ctx(ctx)
				return nil, nil
			})
			if err != nil {
				t.Fatalf("interceptor error = %v", err)
			}
			if onErrorCalled != tt.wantOnError {
				t.Fatalf("onError called = %v, want %v", onErrorCalled, tt.wantOnError)
			}
			if gotAddr != tt.wantAddr {
				t.Fatalf("context address = %v, want %v", gotAddr, tt.wantAddr)
			}
		})
	}
}

func TestStreamServerInterceptorWithErrorHandlerContinues(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		wantAddr    netip.Addr
		wantOnError bool
	}{
		{
			name: "successful extraction",
			ctx: incomingContext(
				map[string][]string{ip.XForwardedFor: {"198.51.100.10"}},
				tcpAddr(),
			),
			wantAddr: netip.MustParseAddr("198.51.100.10"),
		},
		{
			name: "ignored extraction error",
			ctx: incomingContext(
				map[string][]string{ip.XForwardedFor: {"not-an-ip"}},
				tcpAddr(),
			),
			wantOnError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := mustExtractor(t, ip.WithStrict(), ip.WithTrustedProxies("10.0.0.2"))
			onErrorCalled := false
			interceptor := grpcip.StreamServerInterceptorWithErrorHandler(ex, func(context.Context, error) error {
				onErrorCalled = true
				return nil
			})

			var gotAddr netip.Addr
			err := interceptor(nil, &testServerStream{ctx: tt.ctx}, nil, func(_ any, stream grpc.ServerStream) error {
				gotAddr, _ = ip.Ctx(stream.Context())
				return nil
			})
			if err != nil {
				t.Fatalf("interceptor error = %v", err)
			}
			if onErrorCalled != tt.wantOnError {
				t.Fatalf("onError called = %v, want %v", onErrorCalled, tt.wantOnError)
			}
			if gotAddr != tt.wantAddr {
				t.Fatalf("context address = %v, want %v", gotAddr, tt.wantAddr)
			}
		})
	}
}

func TestServerInterceptorsWithErrorHandlerPanicOnNil(t *testing.T) {
	tests := []struct {
		name string
		run  func()
	}{
		{name: "unary", run: func() { grpcip.UnaryServerInterceptorWithErrorHandler(nil, nil) }},
		{name: "stream", run: func() { grpcip.StreamServerInterceptorWithErrorHandler(nil, nil) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("expected panic")
				}
			}()
			tt.run()
		})
	}
}

func TestExtractDedicatedOriginalClientIP(t *testing.T) {
	t.Parallel()

	ex := mustExtractor(t,
		ip.WithHeaders(grpcip.OriginalClientIP),
		ip.WithTrustedProxies("10.0.0.2"),
	)
	ctx := incomingContext(
		map[string][]string{grpcip.OriginalClientIP: {"198.51.100.10"}},
		tcpAddr(),
	)

	got, err := grpcip.Extract(ctx, ex)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if got.String() != "198.51.100.10" {
		t.Fatalf("Extract() = %v, want 198.51.100.10", got)
	}
}

func TestOriginalClientIPMetadataKey(t *testing.T) {
	t.Parallel()

	if grpcip.OriginalClientIP != "original-client-ip" {
		t.Fatalf("OriginalClientIP = %q, want %q", grpcip.OriginalClientIP, "original-client-ip")
	}
}

func TestUnaryClientPropagationInterceptorAddsOutgoingHeader(t *testing.T) {
	ctx := ip.WithContext(context.Background(), netip.MustParseAddr("198.51.100.10"))
	interceptor := grpcip.UnaryClientPropagationInterceptor()

	var got []string
	err := interceptor(ctx, "/test.Service/Call", nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
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
	err := interceptor(ctx, "/test.Service/Call", nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
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
	err := interceptor(ctx, "/test.Service/Call", nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
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
	err = interceptor(ctx, "/test.Service/Call", nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
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

	err := interceptor(context.Background(), "/test.Service/Call", nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		if md, ok := metadata.FromOutgoingContext(ctx); ok && len(md.Get(ip.Forwarded)) > 0 {
			t.Fatal("expected no forwarded metadata")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("UnaryClientPropagationInterceptor() error = %v", err)
	}
}

func TestUnaryClientInterceptorsRemoveStaleMetadataWithoutIP(t *testing.T) {
	tests := []struct {
		name        string
		key         string
		interceptor grpc.UnaryClientInterceptor
	}{
		{
			name:        "Forwarded",
			key:         ip.Forwarded,
			interceptor: grpcip.UnaryClientPropagationInterceptor(),
		},
		{
			name:        "original client IP",
			key:         grpcip.OriginalClientIP,
			interceptor: grpcip.UnaryClientOriginalIPInterceptor(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
				tt.key, "stale-value",
				"x-request-id", "request-1",
			))

			err := tt.interceptor(ctx, "/test.Service/Call", nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
				md, ok := metadata.FromOutgoingContext(ctx)
				if !ok {
					t.Fatal("expected outgoing metadata")
				}
				if got := md.Get(tt.key); len(got) != 0 {
					t.Fatalf("stale %q metadata was propagated: %v", tt.key, got)
				}
				if got := md.Get("x-request-id"); len(got) != 1 || got[0] != "request-1" {
					t.Fatalf("unrelated metadata = %v, want preserved value", got)
				}

				return nil
			})
			if err != nil {
				t.Fatalf("interceptor error = %v", err)
			}
		})
	}
}

func TestStreamClientPropagationInterceptorAddsOutgoingHeader(t *testing.T) {
	ctx := ip.WithContext(context.Background(), netip.MustParseAddr("198.51.100.10"))
	interceptor := grpcip.StreamClientPropagationInterceptor()

	var got []string
	_, err := interceptor(ctx, &grpc.StreamDesc{}, nil, "/test.Service/Stream", func(ctx context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn, _ string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
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

func TestNewUnaryClientPropagationInterceptorAddsForwardedBy(t *testing.T) {
	ctx := ip.WithContext(context.Background(), netip.MustParseAddr("198.51.100.10"))
	interceptor, err := grpcip.NewUnaryClientPropagationInterceptor(
		grpcip.WithForwardedBy("_orders_api"),
	)
	if err != nil {
		t.Fatalf("NewUnaryClientPropagationInterceptor() error = %v", err)
	}

	var got []string
	err = interceptor(ctx, "/test.Service/Call", nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			t.Fatal("expected outgoing metadata")
		}
		got = md.Get(ip.Forwarded)
		return nil
	})
	if err != nil {
		t.Fatalf("interceptor error = %v", err)
	}
	if len(got) != 1 || got[0] != "for=198.51.100.10;by=_orders_api" {
		t.Fatalf("forwarded metadata = %v", got)
	}
}

func TestNewStreamClientPropagationInterceptorFormatsIPv6ForwardedBy(t *testing.T) {
	ctx := ip.WithContext(context.Background(), netip.MustParseAddr("198.51.100.10"))
	interceptor, err := grpcip.NewStreamClientPropagationInterceptor(
		grpcip.WithForwardedBy("2001:db8::5"),
	)
	if err != nil {
		t.Fatalf("NewStreamClientPropagationInterceptor() error = %v", err)
	}

	var got []string
	_, err = interceptor(ctx, &grpc.StreamDesc{}, nil, "/test.Service/Stream", func(ctx context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn, _ string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			t.Fatal("expected outgoing metadata")
		}
		got = md.Get(ip.Forwarded)
		return nil, nil
	})
	if err != nil {
		t.Fatalf("interceptor error = %v", err)
	}
	if len(got) != 1 || got[0] != `for=198.51.100.10;by="[2001:db8::5]"` {
		t.Fatalf("forwarded metadata = %v", got)
	}
}

func TestWithForwardedByValidation(t *testing.T) {
	tests := []struct {
		name string
		node string
	}{
		{name: "empty", node: ""},
		{name: "service name without obfuscated prefix", node: "orders-api"},
		{name: "invalid obfuscated node", node: "_orders/api"},
		{name: "surrounding whitespace", node: " _orders_api"},
		{name: "address with port", node: "192.0.2.1:443"},
		{name: "zoned IPv6 address", node: "fe80::1%eth0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := grpcip.NewUnaryClientPropagationInterceptor(
				grpcip.WithForwardedBy(tt.node),
			)
			if !errors.Is(err, grpcip.ErrInvalidForwardedBy) {
				t.Fatalf("error = %v, want ErrInvalidForwardedBy", err)
			}
		})
	}
}

func TestWithForwardedByFormatsSupportedNodes(t *testing.T) {
	tests := []struct {
		name string
		node string
		want string
	}{
		{name: "IPv4", node: "192.0.2.5", want: "for=198.51.100.10;by=192.0.2.5"},
		{name: "mapped IPv4", node: "::ffff:192.0.2.5", want: "for=198.51.100.10;by=192.0.2.5"},
		{name: "unknown", node: "UNKNOWN", want: "for=198.51.100.10;by=unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interceptor, err := grpcip.NewUnaryClientPropagationInterceptor(grpcip.WithForwardedBy(tt.node))
			if err != nil {
				t.Fatalf("NewUnaryClientPropagationInterceptor() error = %v", err)
			}
			ctx := ip.WithContext(context.Background(), netip.MustParseAddr("198.51.100.10"))

			err = interceptor(ctx, "/test.Service/Call", nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
				md, ok := metadata.FromOutgoingContext(ctx)
				if !ok {
					t.Fatal("expected outgoing metadata")
				}
				got := md.Get(ip.Forwarded)
				if len(got) != 1 || got[0] != tt.want {
					t.Fatalf("forwarded metadata = %v, want %q", got, tt.want)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("interceptor error = %v", err)
			}
		})
	}
}

func TestNewStreamClientPropagationInterceptorRejectsNilOption(t *testing.T) {
	interceptor, err := grpcip.NewStreamClientPropagationInterceptor(nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if interceptor != nil {
		t.Fatal("interceptor must be nil on configuration error")
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

func tcpAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort("10.0.0.2:443"))
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

func TestUnaryClientPropagationInterceptorReplacesExistingForwardedMetadata(t *testing.T) {
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		ip.Forwarded, "for=203.0.113.99",
		"x-request-id", "request-1",
	))
	ctx = ip.WithContext(ctx, netip.MustParseAddr("198.51.100.10"))
	interceptor := grpcip.UnaryClientPropagationInterceptor()

	err := interceptor(ctx, "/test.Service/Call", nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			t.Fatal("expected outgoing metadata")
		}
		if got := md.Get(ip.Forwarded); len(got) != 1 || got[0] != "for=198.51.100.10" {
			t.Fatalf("forwarded metadata = %v, want one replaced value", got)
		}
		if got := md.Get("x-request-id"); len(got) != 1 || got[0] != "request-1" {
			t.Fatalf("unrelated metadata = %v, want preserved value", got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("interceptor error = %v", err)
	}
}

func TestUnaryClientOriginalIPInterceptorUsesDedicatedMetadata(t *testing.T) {
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		grpcip.OriginalClientIP, "203.0.113.99",
		ip.Forwarded, "for=203.0.113.10",
	))
	ctx = ip.WithContext(ctx, netip.MustParseAddr("::ffff:198.51.100.10"))
	interceptor := grpcip.UnaryClientOriginalIPInterceptor()

	err := interceptor(ctx, "/test.Service/Call", nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			t.Fatal("expected outgoing metadata")
		}
		if got := md.Get(grpcip.OriginalClientIP); len(got) != 1 || got[0] != "198.51.100.10" {
			t.Fatalf("original client IP metadata = %v", got)
		}
		if got := md.Get(ip.Forwarded); len(got) != 1 || got[0] != "for=203.0.113.10" {
			t.Fatalf("external Forwarded metadata was modified: %v", got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("interceptor error = %v", err)
	}
}

func TestStreamClientOriginalIPInterceptorUsesDedicatedMetadata(t *testing.T) {
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		grpcip.OriginalClientIP, "203.0.113.99",
		ip.Forwarded, "for=203.0.113.10",
	))
	ctx = ip.WithContext(ctx, netip.MustParseAddr("2001:db8::10"))
	interceptor := grpcip.StreamClientOriginalIPInterceptor()

	_, err := interceptor(ctx, &grpc.StreamDesc{}, nil, "/test.Service/Stream", func(ctx context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn, _ string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			t.Fatal("expected outgoing metadata")
		}
		if got := md.Get(grpcip.OriginalClientIP); len(got) != 1 || got[0] != "2001:db8::10" {
			t.Fatalf("original client IP metadata = %v", got)
		}
		if got := md.Get(ip.Forwarded); len(got) != 1 || got[0] != "for=203.0.113.10" {
			t.Fatalf("external Forwarded metadata was modified: %v", got)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("interceptor error = %v", err)
	}
}
