# Client IP extractor

`github.com/skarm/ip` extracts a client IP address from HTTP requests and
header-like metadata without trusting forwarding headers by default.

The package is intended for services running directly on the network or behind
one or more explicitly trusted reverse proxies. It keeps the transport peer,
proxy chain, parser strictness, and result provenance separate so callers can
make security decisions deliberately.

## Quick start

The following program uses the safe default: forwarding headers are ignored and
only the direct transport peer from `RemoteAddr` is accepted.

```go
package main

import (
    "fmt"
    "log"
    "net/http"

    "github.com/skarm/ip"
)

func main() {
    extractor := ip.Must(ip.New())

    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        addr, ok := ip.Ctx(r.Context())
        if !ok {
            http.Error(w, "client IP unavailable", http.StatusInternalServerError)
            return
        }

        fmt.Fprintln(w, addr)
    })

    protected := extractor.MiddlewareWithErrorHandler(
        handler,
        func(w http.ResponseWriter, _ *http.Request, _ error) {
            http.Error(w, "invalid client network metadata", http.StatusBadRequest)
        },
    )

    log.Fatal(http.ListenAndServe(":8080", protected))
}
```

Do not enable `WithUnsafeTrustAllProxies` merely because the service is behind
a reverse proxy. Configure the exact proxy addresses or CIDR prefixes instead.

### Service behind trusted proxies

Configure every address or CIDR that may be the immediate or intermediate
proxy:

```go
extractor := ip.Must(ip.New(
    ip.WithTrustedProxies(
        "10.0.0.0/8",
        "2001:db8:100::/48",
    ),
))

result, err := extractor.ExtractResult(r)
if err != nil {
    log.Printf("extract client IP: %v", err)
    return
}

log.Printf(
    "client_ip=%s source=%s header=%q trusted_hops=%d reason=%s",
    result.Addr,
    result.Source,
    result.Header,
    result.TrustedHops,
    result.Reason,
)
```

`WithTrustedProxies` enables `ProxiesAllowedList` unless an explicit proxy mode
was selected. The option replaces the previous allow-list rather than adding
to it.

## Security model

The client controls every forwarding header unless a trusted proxy removes
incoming values and writes a new, canonical chain. Therefore:

- the default mode ignores all proxy headers and uses only `RemoteAddr`;
- allow-list mode processes headers only when the immediate transport peer is
  trusted;
- a proxy chain is evaluated from right to left;
- malformed, `unknown`, and obfuscated hops are trust boundaries;
- addresses to the left of an unverifiable boundary never affect the result;
- trusting all proxies is explicit and unsafe for an internet-facing service.

A returned IP is not cryptographic proof of identity. Use authenticated
transport and trusted proxy configuration when the value affects ACLs,
rate-limits, fraud controls, or audit records.

## Requirements

The root module supports Go 1.25.0 and newer.

The optional `github.com/skarm/ip/grpc` submodule has its own dependencies and
Go version; see [`grpc/README.md`](grpc/README.md).

## Proxy modes

### `ProxiesDenied`

Default and safest mode. All proxy headers are ignored and `RemoteAddr` is
returned.

### `ProxiesAllowedList`

Headers are considered only when the immediate peer belongs to the configured
IP/CIDR allow-list. For a chain such as:

```text
client, proxy-a, proxy-b
```

the extractor starts with the trusted immediate peer from `RemoteAddr`, then
checks `proxy-b`, `proxy-a`, and the client from right to left. The first valid,
untrusted address is selected as the client.

If every chain element is trusted, the extractor conservatively returns the
immediate transport peer with `ReasonNoUntrustedHop`. If it reaches an
unverifiable element in permissive mode, it returns the immediate peer with
`ReasonUnverifiableChain`. Use `ExtractResult` when this distinction matters.

### `ProxiesAllowedAll`

Enabled with `WithUnsafeTrustAllProxies`. It accepts proxy metadata from any
peer and returns the first valid IP in header order.

Do not use this mode for an internet-facing service unless another enforced
network boundary strips and rewrites forwarding metadata.

## Strict and permissive parsing

Permissive mode is the default. It tolerates malformed metadata where it can do
so without crossing an unverifiable trust boundary and falls back to the
transport peer when necessary.

`WithStrict` makes malformed, ambiguous, conflicting, untrusted, or
unverifiable proxy metadata an error. Syntactically valid elements such as
`for=unknown`, obfuscated nodes, or an element without `for=` return
`ErrUnverifiableChain` rather than being skipped:

```go
extractor := ip.Must(ip.New(
    ip.WithStrict(),
    ip.WithTrustedProxies("10.0.0.0/8"),
))
```

Strict extraction alone does not reject an HTTP request. Choose the middleware
contract explicitly.

## HTTP middleware

### Best-effort enrichment

`Middleware` preserves the original best-effort behavior. On extraction
failure it calls the next handler without a client IP in context:

```go
handler := extractor.Middleware(next)
```

Use this only when the address is optional, for example for diagnostics.

### Fail-closed validation

For security-sensitive request paths, provide an `HTTPErrorHandler` that writes
the response. On extraction failure `next` is not called:

```go
handler := extractor.MiddlewareWithErrorHandler(
    next,
    func(w http.ResponseWriter, r *http.Request, err error) {
        http.Error(w, "invalid client network metadata", http.StatusBadRequest)
    },
)
```

Read the validated address from the handler context:

```go
addr, ok := ip.Ctx(r.Context())
```

## Result provenance

`Extract` and `ExtractFrom` preserve the compact `(netip.Addr, error)` API.
`ExtractResult` and `ExtractResultFrom` additionally return:

- `Source`: transport peer or proxy header;
- `Header`: the logical header that participated in the decision;
- `TrustedHops`: trusted proxy identities verified while evaluating the header;
- `Reason`: selected header, disabled headers, untrusted immediate peer,
  missing metadata, unverifiable chain, or no untrusted hop.

Callers using an IP for authorization or abuse prevention should check the
provenance rather than assuming every successful extraction has equal trust.

## Header parsing

Default priority:

1. `Forwarded`;
2. `X-Forwarded-For`;
3. `X-Real-IP`;
4. `X-Client-IP`;
5. `CF-Connecting-IP`;
6. `Fastly-Client-IP`;
7. `True-Client-IP`;
8. `X-Cluster-Client-IP`;
9. `X-Forwarded`;
10. `Forwarded-For`.

`Forwarded` is parsed using RFC 7239 token, quoted-string, list, duplicate
parameter, node, host, and protocol rules. Only HTTP optional whitespace (space
and horizontal tab) is ignored where the grammar permits it.
`X-Forwarded-For` is parsed only as a comma-separated list. The remaining
default headers contain one IP or IP:port value.

Header matching is case-insensitive. In strict mode, multiple physical map keys
that normalize to the same configured name return `ErrAmbiguousHeader`. In
permissive mode, an exact lower-case key wins; otherwise the lexicographically
smallest spelling is used deterministically.

### Explicit custom header types

Use `WithHeaderSpecs` instead of relying on implicit parsing:

```go
extractor := ip.Must(ip.New(
    ip.WithTrustedProxies("10.0.0.0/8"),
    ip.WithHeaderSpecs(
        ip.HeaderSpec{Name: "x-edge-chain", Kind: ip.HeaderXForwardedFor},
        ip.HeaderSpec{Name: "x-edge-client-ip", Kind: ip.HeaderSingleIP},
    ),
))
```

Header names are validated as HTTP field names and normalized to lower case.
`WithHeaders` remains available; known standard names use their chain parser
and unknown names use `HeaderSingleIP`.

## Resource limits

Every extractor has bounded defaults:

- aggregate configured header values: `DefaultMaxHeaderBytes` (32 KiB);
- physical values: `DefaultMaxHeaderValues` (64);
- proxy-chain elements: `DefaultMaxHops` (64);
- one token or value: `DefaultMaxTokenBytes` (4 KiB).

Override them when the deployment has stricter limits:

```go
extractor := ip.Must(ip.New(
    ip.WithMaxHeaderBytes(8 << 10),
    ip.WithMaxHeaderValues(16),
    ip.WithMaxHops(16),
    ip.WithMaxTokenBytes(1024),
))
```

Use `errors.Is` to match `ErrLimitExceeded` and a specific error such as
`ErrHeaderTooLarge` or `ErrTooManyHops`. Use `errors.As` to inspect
`*ip.LimitError`.

## IP normalization

Parsed addresses are normalized consistently:

- IPv4-mapped IPv6 addresses are unmapped to IPv4;
- IPv6 zones are removed;
- trusted individual addresses and CIDR prefixes use the same representation;
- context and gRPC propagation use normalized addresses.

Do not use zone-scoped link-local addresses as a cross-host proxy identity.
Prefer routable addresses or deployment-specific network identities.

## Topology examples

### Direct service

```text
client -> service
```

Use the defaults. The result comes from `RemoteAddr`.

### One reverse proxy

```text
client -> trusted proxy -> service
```

Allow-list the proxy address/CIDR and configure it to replace client-supplied
forwarding headers.

### CDN and load balancer

```text
client -> CDN -> load balancer -> service
```

Allow-list both trusted layers and preserve their canonical right-appended
chain. Never allow the public client to connect directly to the service on the
same listener.

### HTTP to internal gRPC

Use the dedicated original-client-IP gRPC metadata described in
[`grpc/README.md`](grpc/README.md), authenticate service-to-service traffic, and
allow-list only authenticated internal peers.

## Errors

Configuration failures use `*ConfigError`; header and transport failures use
`*HeaderError`; resource failures use `*LimitError`. Sentinel errors support
`errors.Is`, and structured errors support `errors.As`.

Header values embedded in errors are quoted and bounded to prevent control
characters or very large untrusted values from expanding logs.

## Development

Run root-module checks:

```bash
go test ./...
go test -race ./...
go vet ./...
golangci-lint run -v --config .golangci.yml ./...
```

Run the independently versioned gRPC module against the root version recorded
in `grpc/go.mod`:

```bash
cd grpc
GOWORK=off go test ./...
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
GOWORK=off golangci-lint run -v --config ../.golangci.yml ./...
```

Fuzz targets cover `Forwarded`, `X-Forwarded-For`, and trust-boundary
invariants. CI checks and lints both modules and runs `govulncheck`.
