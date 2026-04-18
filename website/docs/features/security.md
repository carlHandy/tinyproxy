# Security Features

**tinyproxy** is designed with security-first principles, providing robust defaults and easy hardening options.

## Default Security Headers

Every virtual host automatically includes following security headers unless overridden:

| Header | Default Value |
|---|---|
| `X-Frame-Options` | `SAMEORIGIN` |
| `X-Content-Type-Options` | `nosniff` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-XSS-Protection` | `1; mode=block` |

## Hardening with `security` Block

Use the `security` block to customize headers and limits:

```text
vhosts {
    example.com {
        security {
            frame_options    DENY
            content_type     nosniff
            csp              "default-src 'self'"
            rate_limit {
                requests 100
                window   1m
            }
        }
    }
}
```

## TLS Enforcement

All TLS connections in **tinyproxy** enforce modern security standards:
- **Minimum Version**: TLS 1.2
- **Cipher Suites**: Forward-secret only (ECDHE-AES-GCM, ECDHE-ChaCha20-Poly1305).
- **Preferred Curves**: X25519, P-256.

## Rate Limiting

The built-in rate limiter helps protect against brute-force attacks and resource exhaustion.
- **Default**: 100 requests per minute per IP.
- **Max Body Size**: 10 MB (default).

## TLS Fingerprinting (JA3 / JA4)

tinyproxy computes JA3 and JA4 fingerprints from the TLS ClientHello of every incoming connection before the HTTP handler runs. Fingerprints are available to the bot-detection pipeline and can be blocked via `config/fingerprints.conf`.

### Blocking fingerprints

Create `config/fingerprints.conf` (or `/etc/go-tinyproxy/fingerprints.conf` when installed) with one entry per line:

```text
# Block by JA3 hash
ja3:abc123def456...

# Block by JA4 string
ja4:t13d1516h2_...

# Inline comments are supported
ja3:deadbeef1234  # known scanner
```

Blocked connections receive the same response as bot-detected requests (403 or honeypot, depending on your `bot_protection` config). The blocklist is reloaded on `SIGHUP` alongside `vhosts.conf`.
