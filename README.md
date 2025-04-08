## IP Extractor Library

A Go package for extracting client IP addresses from HTTP requests, handling proxy headers, and managing trusted networks.

### Features

- Supports all standard proxy headers (X-Forwarded-For, Forwarded, CF-Connecting-IP, etc.)
- RFC7239 Forwarded header parsing
- Trusted proxy CIDR validation
- Middleware for seamless integration with net/http
- IPv4/IPv6 support
- Customizable header priority

### Notes
- Invalid IPs in headers are automatically skipped
- IPv6 addresses are returned without zone identifiers
- By default trusts all proxies (configure properly for production)
