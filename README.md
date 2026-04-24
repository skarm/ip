## IP Extractor Library

Go package for extracting a client IP address from `net/http` requests with an explicit trust model for reverse proxies.

The exported header constants in this package use lower-case values so they can
be used directly with `ExtractFrom` and gRPC metadata. Header matching remains
case-insensitive.

### Defaults

- Proxy headers are disabled by default.
- Only `Request.RemoteAddr` is used unless proxy support is explicitly enabled.
- The default extractor is permissive: malformed proxy headers are ignored rather than turning the whole request into an error.

### Proxy Modes

- `ProxiesDenied`
  - Default mode.
  - Ignores `forwarded`, `x-forwarded-for`, and other proxy headers.
  - Safest choice unless the service is known to sit behind trusted reverse proxies.

- `ProxiesAllowedList`
  - Trusts proxy headers only when `Request.RemoteAddr` belongs to a configured allow-list.
  - Supports both individual IP addresses and CIDR ranges.
  - Recommended for production behind load balancers or reverse proxies.

- `ProxiesAllowedAll`
  - Trusts proxy headers from any source.
  - Unsafe unless an upstream component strips and rewrites forwarding headers.
  - Kept explicit via `WithUnsafeTrustAllProxies()`.

### Strict vs Permissive

- Permissive mode:
  - Ignores malformed proxy headers.
  - Falls back to safer sources when possible.
  - Good default for typical production handlers.

- Strict mode:
  - Returns typed errors for malformed `forwarded`, invalid IP tokens, conflicting trusted headers, untrusted proxy usage, and invalid configuration.
  - Returns `ErrAmbiguousHeader` when multiple physical keys normalize to the same configured logical header, such as `X-Forwarded-For` and `x-forwarded-for`.
  - Useful for diagnostics, ingress validation, and security-sensitive services.

### Header Handling

- Standardized:
  - `forwarded` is parsed according to RFC 7239, including quoted strings, escaping, IPv6-in-brackets, obfuscated identifiers, `unknown`, multiple header fields, and HTTP list semantics.

- De-facto:
  - `x-forwarded-for` is parsed as a comma-separated proxy chain.
  - `x-real-ip`, `x-client-ip`, `cf-connecting-ip`, `fastly-client-ip`, `true-client-ip`, and `x-cluster-client-ip` are treated as single-IP headers.

- Ambiguous / legacy:
  - `x-forwarded` and `forwarded-for` are treated as single-IP headers only.
  - They remain lower priority than `forwarded` and `x-forwarded-for`.

### Duplicate Header Keys

- Header matching is case-insensitive.
- In strict mode, multiple physical keys that normalize to the same logical header are rejected with `ErrAmbiguousHeader`.
- In permissive mode, `ExtractFrom` prefers the exact lower-case key when present. Otherwise it prefers the lexicographically smallest key spelling.
