# Development

Interested wishing to contribute to **tinyproxy**? This guide will help you set up your development environment.

## Prerequisites

- **Go 1.23+**
- **mkcert** (for local TLS)
- **Node.js** (required only for building the documentation site)

## Building

To build the primary binary:
```bash
go build -o go-tinyproxy ./cmd/tinyproxy/
```

To run the server in development mode (reads from current directory `config/` and `certs/`):
```bash
ENV=dev go run ./cmd/tinyproxy/
```

## Testing

Run all tests:
```bash
go test ./...
```

Run tests with race detection:
```bash
go test -race ./...
```

## Project Structure

- `cmd/tinyproxy/` — Entry point, CLI subcommands, and dashboard CLI flags.
- `internal/cache/` — In-memory HTTP response cache with TTL and `Cache-Control` support.
- `internal/dashboard/` — Admin dashboard HTTP server, UI, log ring buffer, and stats collector.
- `internal/fastcgi/` — FastCGI client for PHP-FPM and similar backends.
- `internal/loadbalancer/` — Load balancing strategies and upstream health checks.
- `internal/server/botdetect/` — Bot detection: path scanning, user-agent blocking, and honeypot mode.
- `internal/server/compression/` — Gzip and brotli response compression.
- `internal/server/config/` — Custom block-syntax config parser, `VirtualHost`/`ServerConfig` types, and validation.
- `internal/server/fingerprint/` — JA3/JA4 TLS fingerprinting and `config/fingerprints.conf` blocklist.
- `internal/server/middleware/` — Logging, recovery, and request-ID middleware (not yet wired into the main handler chain).
- `internal/server/proxy/` — Reverse proxy with optional SOCKS5 tunnel.
- `internal/server/security/` — TLS hardening, IP rate limiting, and security headers.
- `internal/server/security/certmanager/` — ACME/Let's Encrypt certificate management.

## Documentation Site

The documentation site is built with Docusaurus.

```bash
cd website
npm install
npm start
```
