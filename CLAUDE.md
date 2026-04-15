# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project goal

tinyproxy is a **security-focused reverse proxy and web server** intended as a single-binary alternative to nginx + Traefik. The core differentiator is **native bot detection and AI-based attack prevention** — not bolted on via plugins, but built into the request pipeline. When adding features, prioritize security capabilities and keeping everything self-contained over convenience integrations.

## Commands

```bash
# Build
go build -o go-tinyproxy ./cmd/tinyproxy/

# Run (development — TLS on :8080 using local certs)
ENV=dev go run ./cmd/tinyproxy/

# Run (production — TLS on :443, HTTP redirect on :80)
go run ./cmd/tinyproxy/

# Lint
go vet ./...

# Tests (none yet — no test suite exists)
go test ./...
```

Dev mode requires mkcert certificates at `certs/localhost+2.pem` and `certs/localhost+2-key.pem`. Generate them with `mkcert localhost 127.0.0.1 ::1`.

## Architecture

### Request lifecycle

Every request flows through `VHostHandler.ServeHTTP` in `cmd/tinyproxy/main.go`:

1. **Virtual host lookup** — match `r.Host` against `ServerConfig.VHosts`; fall back to `"default"`
2. **Rate limiting** — token bucket via `security.RateLimit` (per-vhost, uses `golang.org/x/time`)
3. **Security headers** — X-Frame-Options, CSP, HSTS, XSS-Protection, X-Content-Type-Options
4. **Compression** — gzip/brotli if `compression on` in config
5. **Handler dispatch** — in priority order: FastCGI → `proxy_pass` reverse proxy → static file server

The `middleware/` package (logging, recovery, requestid) exists but is **not yet wired** into the main handler chain.

### Key packages

| Package | Role |
|---|---|
| `internal/server/config` | Custom block-syntax config parser + `VirtualHost`/`ServerConfig` types + validation |
| `internal/server/proxy` | Reverse proxy with optional SOCKS5 tunnel |
| `internal/server/security` | TLS hardening, IP rate limiting, security headers, body size limits |
| `internal/server/security/certmanager` | TLS cert loading; dev uses mkcert, prod uses per-vhost cert files |
| `internal/server/compression` | Gzip and brotli response compression |
| `internal/fastcgi` | FastCGI client (PHP-FPM etc.) |
| `config/validate.go` | Post-parse validation of `ServerConfig` |

### Configuration

Config is a custom block DSL at `config/vhosts.conf` — **not** YAML or TOML. The parser is hand-written in `internal/server/config/parser.go`. See the commented examples in `config/vhosts.conf` for the full directive set (`port`, `proxy_pass`, `root`, `ssl`, `security`, `rate_limit`, `socks5`, `fastcgi`).

Default vhost values (applied when a directive is absent): compression on, 100 req/min rate limit, HSTS max-age 31536000, X-Frame-Options SAMEORIGIN, 10MB max body size.

### Dev vs production mode

`ENV=dev` — listens on `:8080`, loads certs from `certs/` directory, uses `security.SecureTLSConfig()`.  
Production — listens on `:443`, loads per-vhost certs via `certmanager.GetTLSConfig`, spawns HTTP→HTTPS redirect on `:80`.
