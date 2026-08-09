# gRPC interceptors for client IP addresses

`github.com/skarm/ip/grpc` contains optional gRPC adapters for the root
`github.com/skarm/ip` extractor. It is a separate Go module so applications that
only use `net/http` do not acquire `google.golang.org/grpc` dependencies.

The module requires the Go version declared in `grpc/go.mod`.

## Incoming RPC extraction

`grpcip.Extract` applies the root extractor to:

- incoming gRPC metadata as header values;
- `peer.Addr.String()` as the immediate transport peer.

The configured proxy mode, trusted proxy allow-list, strict parsing, typed
headers, limits, and trust-boundary rules are therefore the same as for HTTP.

## Server interceptors

### Best-effort

`UnaryServerInterceptor` and `StreamServerInterceptor` preserve the original
best-effort behavior. When extraction fails, the RPC handler is still called
with the original context.

Use these only when the address is optional telemetry:

```go
server := grpc.NewServer(
    grpc.ChainUnaryInterceptor(
        grpcip.UnaryServerInterceptor(extractor),
    ),
)
```

### Explicit error handling

Security-sensitive services should map extraction failures to an RPC error:

```go
onError := grpcip.ServerErrorHandler(func(ctx context.Context, err error) error {
    return status.Error(codes.Unauthenticated, "invalid client IP metadata")
})

server := grpc.NewServer(
    grpc.ChainUnaryInterceptor(
        grpcip.UnaryServerInterceptorWithErrorHandler(extractor, onError),
    ),
    grpc.ChainStreamInterceptor(
        grpcip.StreamServerInterceptorWithErrorHandler(extractor, onError),
    ),
)
```

Returning a non-nil error rejects the remote procedure call (RPC) without
calling its handler. Returning nil continues with the original context, which
lets the callback record the extraction failure while preserving best-effort
behavior.

The handler reads a successfully validated address with `ip.Ctx(ctx)`.

## Recommended internal propagation

For service-to-service propagation, prefer the dedicated metadata key:

```text
original-client-ip
```

Install the client interceptor on the calling service:

```go
connection, err := grpc.NewClient(
    target,
    grpc.WithChainUnaryInterceptor(
        grpcip.UnaryClientOriginalIPInterceptor(),
    ),
    grpc.WithChainStreamInterceptor(
        grpcip.StreamClientOriginalIPInterceptor(),
    ),
)
```

The interceptors read the normalized IP from `ip.Ctx(ctx)`, replace any existing
value of the dedicated key, and write exactly one raw IP value. When the context
has no valid address, they remove any existing value of that key while preserving
unrelated outgoing metadata.

Configure the receiver explicitly:

```go
extractor := ip.Must(ip.New(
    ip.WithStrict(),
    ip.WithTrustedProxies("10.0.0.0/8"),
    ip.WithHeaders(grpcip.OriginalClientIP),
))
```

This compatibility form compiles against the minimum root module version in
`grpc/go.mod`; an unknown name passed to `WithHeaders` uses the single-IP
parser. After the gRPC module requires a root release that provides typed
header specifications, prefer the explicit equivalent
`WithHeaderSpecs(ip.HeaderSpec{Name: grpcip.OriginalClientIP, Kind:
ip.HeaderSingleIP})`.

The dedicated metadata value is still only an assertion made by the calling
service. It is trustworthy only when:

- the RPC transport authenticates the caller, normally with mTLS;
- only authenticated internal services can reach the listener;
- the receiver allow-lists the immediate service/proxy peers;
- external ingress cannot inject or preserve this metadata key;
- each boundary replaces rather than appends the value.

Do not treat a propagated IP as cryptographic proof of the end user's identity.

## RFC `Forwarded` compatibility propagation

`UnaryClientPropagationInterceptor` and
`StreamClientPropagationInterceptor` support integrations that require RFC
7239 `Forwarded` metadata. They replace all existing outgoing `forwarded`
values with one normalized `for=` parameter. If the context has no valid client
IP, they remove existing `forwarded` values.

An integration that also needs to identify the forwarding node can configure an
RFC 7239 `by=` value during startup:

```go
interceptor, err := grpcip.NewUnaryClientPropagationInterceptor(
    grpcip.WithForwardedBy("_orders_api"),
)
if err != nil {
    return err
}
```

`WithForwardedBy` accepts an IP address, `unknown`, or an RFC obfuscated node
beginning with `_`. The value is diagnostic metadata only. It is not proof of
the caller's identity; use mTLS, SPIFFE, or another authenticated transport
identity for authorization.

Prefer the dedicated internal key for new service-to-service protocols. Mixing
an internal assertion with externally supplied `Forwarded` data makes trust
boundaries harder to audit.

## Unary example

```go
func handler(ctx context.Context, request *pb.Request) (*pb.Response, error) {
    addr, ok := ip.Ctx(ctx)
    if !ok {
        return nil, status.Error(codes.Internal, "client IP missing")
    }

    _ = addr // use for logs, policy, or rate limiting according to provenance
    return &pb.Response{}, nil
}
```

## Testing the nested module

Test the module independently against the dependency versions recorded in
`grpc/go.mod`:

```bash
cd grpc
GOWORK=off go test ./...
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
GOWORK=off golangci-lint run -v --config ../.golangci.yml ./...
```

The root and gRPC modules are versioned independently. A gRPC release uses its
own `grpc/vX.Y.Z` tag.
