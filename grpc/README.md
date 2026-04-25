## gRPC IP Interceptors

`github.com/skarm/ip/grpc` contains gRPC helpers and interceptors built on top
of the root `github.com/skarm/ip` extractor.

The nested `go.mod` keeps `google.golang.org/grpc` out of the root module
unless gRPC support is explicitly imported.

### API

- `grpcip.Extract` extracts the client IP from incoming metadata plus
  `peer.Addr`.
- `grpcip.UnaryServerInterceptor` and `grpcip.StreamServerInterceptor` store
  the extracted IP in the RPC context via `ip.WithContext`.
- Read the stored IP with `ip.Ctx`, the same way as in the HTTP middleware
  path.
- `grpcip.UnaryClientPropagationInterceptor` and
  `grpcip.StreamClientPropagationInterceptor` propagate the IP already stored in
  context through outgoing `forwarded` metadata.

### Notes

- Incoming metadata is treated as request headers and is parsed through
  `Extractor.ExtractFrom`, so proxy trust mode, strict mode, and RFC 7239
  handling stay consistent with the root package.
- Propagation interceptors emit a single `forwarded` header with a `for=`
  parameter for the client IP. They propagate the original client IP and do not
  try to synthesize a full proxy hop record with `by=`.
