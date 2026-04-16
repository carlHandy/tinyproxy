# TLS Fingerprinting (JA3/JA4) Design

**Date:** 2026-04-15  
**Branch:** tls-fingering  
**Status:** Approved

## Goal

Add native JA3 and JA4 TLS fingerprinting to tinyproxy. Every TLS connection is fingerprinted at the TCP layer before the HTTP handler runs. Fingerprints are used for three purposes:

1. **Blocking** — requests matching a global blocklist receive a 403 or honeypot response
2. **Logging** — JA3 and JA4 are appended to every access log line
3. **Upstream forwarding** — proxy_pass and load-balanced requests carry `X-JA3-Fingerprint` and `X-JA4-Fingerprint` headers

## Architecture & Data Flow

```
TCP connection accepted
    → fingerprintConn buffers full TLS ClientHello record
    → fingerprint.ParseClientHello() extracts fields
    → fingerprint.JA3() + fingerprint.JA4() compute hashes
    → stored on fingerprintConn
    ↓
http.Server.ConnContext fires
    → type-asserts net.Conn → *fingerprintConn
    → stores Fingerprints{JA3, JA4} in request context
    ↓
VHostHandler.ServeHTTP
    → checks global blocklist → 403/honeypot if matched
    → logs JA3 + JA4 in access log
    → sets X-JA3-Fingerprint / X-JA4-Fingerprint on proxy requests
```

## New Package: `internal/server/fingerprint/`

All parsing and hash computation is isolated here.

| File | Responsibility |
|---|---|
| `clienthello.go` | Parse raw ClientHello bytes into a `ClientHello` struct (version, cipher suites, extension IDs, curves, point formats) |
| `ja3.go` | Compute JA3 string (`SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`) and MD5 hash |
| `ja4.go` | Compute JA4 string per FoxIO spec |
| `context.go` | Context key type; `WithFingerprints(ctx, fp)` and `FromContext(ctx)` helpers |

### `ClientHello` parsing

1. Read 5-byte TLS record header: content type (`0x16`), legacy version (2 bytes), record length (2 bytes)
2. Read `length` bytes (the Handshake body)
3. Verify handshake type `0x01` (ClientHello)
4. Extract: client version, session ID, cipher suites, compression methods, extension list (type + data for each)

If parsing fails at any step, fingerprints are left empty. The connection is not dropped.

Maximum bytes buffered: 16KB (the TLS record size limit). In practice ClientHellos are 200–500 bytes.

### JA3 computation (Salesforce spec)

Fields: `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`

- Each field is a `-`-separated list of decimal values
- GREASE values (matching `0x?a?a` pattern) are excluded from all lists
- Fields joined with `,`, MD5-hashed → 32-char hex string

### JA4 computation (FoxIO spec)

Format: `{proto}{ver}{sni}{cipherCount}{extCount}_{cipherHex}_{extHex}`

- `proto`: `t` (TLS)
- `ver`: two-digit TLS version (`13`, `12`, `11`, `10`)
- `sni`: `d` if SNI extension present, `i` if absent
- `cipherCount`: two-digit zero-padded count of non-GREASE ciphers
- `extCount`: two-digit zero-padded count of non-GREASE extensions
- `cipherHex`: ciphers sorted, hex-joined, SHA-256, first 12 chars
- `extHex`: extension types sorted (excluding SNI `0x0000` and ALPN `0x0010`), hex-joined, SHA-256, first 12 chars

## Modified: `cmd/tinyproxy/main.go`

### `fingerprintConn` (replaces `peekedConn`)

```go
type fingerprintConn struct {
    net.Conn
    buf          []byte  // full ClientHello record for replay
    fingerprints fingerprint.Fingerprints
}
```

`sniffingListener.Accept()`:
1. Read 5-byte record header
2. Read record body (`length` bytes from header)
3. Buffer all bytes; call `fingerprint.Compute(buf)` → `Fingerprints{JA3, JA4}`
4. Return `*fingerprintConn` with buffered bytes and fingerprints
5. On plain HTTP (first byte != `0x16`): send redirect as before (no fingerprint needed)

### `http.Server.ConnContext`

```go
server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
    if tc, ok := c.(*tls.Conn); ok {
        if fc, ok := tc.NetConn().(*fingerprintConn); ok {
            return fingerprint.WithFingerprints(ctx, fc.fingerprints)
        }
    }
    return ctx
}
```

`http.Server` wraps the connection as `*tls.Conn` before `ConnContext` fires. `tls.Conn.NetConn()` (Go 1.18+) unwraps it back to our `*fingerprintConn`. This preserves `r.TLS` in HTTP handlers (the conn is still a real `*tls.Conn`) while giving us access to the fingerprint data.

## Global Blocklist

### `config/fingerprints.conf`

```
# Known scanner fingerprints
ja3:abc123def456...     # curl default
ja3:fed321cba987...     # Masscan
ja4:t13d1516h2_abc123   # Mirai variant
```

- One entry per line; prefix `ja3:` or `ja4:` disambiguates type
- `#` for comments; blank lines ignored
- Loaded at startup alongside `vhosts.conf`
- SIGHUP reloads both files atomically under the existing `sync.RWMutex`

### Blocklist in `VHostHandler`

```go
type VHostHandler struct {
    mu           sync.RWMutex
    config       *config.ServerConfig
    blocklist    map[string]struct{}  // "ja3:<hash>" or "ja4:<hash>"
    caches       map[string]*cache.Cache
    balancers    map[string]*loadbalancer.LoadBalancer
}
```

Check runs before rate limiting in `ServeHTTP`. On match, the vhost's honeypot setting determines response (honeypot content or plain 403), reusing `botdetect.block()`.

## Logging

Fingerprints appended to access log lines via `log.Printf` in `ServeHTTP`:

```
2026/04/15 12:00:00 GET /path 200 JA3=abc123 JA4=t13d1516h2_abc123def456
```

If fingerprints are empty (plain HTTP or parse failure), the fields are omitted.

## Upstream Header Forwarding

In `proxy/proxy.go`, before the upstream request is dispatched:

```go
if fp := fingerprint.FromContext(r.Context()); fp.JA3 != "" {
    outReq.Header.Set("X-JA3-Fingerprint", fp.JA3)
    outReq.Header.Set("X-JA4-Fingerprint", fp.JA4)
}
```

Applies to both single `proxy_pass` and load-balanced backends. Empty fingerprints produce no headers.

## Out of Scope

- Per-vhost fingerprint allowlists or blocklists
- QUIC / JA4+ variants
- Fingerprint-based rate limiting
- A fingerprint lookup/query API
- JA3S (server fingerprinting)

## Testing

- Unit tests for `ParseClientHello`, `JA3()`, `JA4()` using known ClientHello byte fixtures with expected hash outputs
- Unit test for blocklist loader: valid entries, comments, blank lines, unknown prefixes
- Integration: `fingerprintConn` replay correctness (bytes replayed exactly match input)
