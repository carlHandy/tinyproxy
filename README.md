# tinyproxy

A security-focused reverse proxy and web server — a single-binary alternative to nginx + Traefik with native bot detection and AI crawler prevention built into the request pipeline.

## Requirements

- Go 1.23+
- [mkcert](https://github.com/FiloSottile/mkcert) (development only)

## Running

### Development

Dev mode listens on `:8080`. Both `http://localhost:8080` and `https://localhost:8080` work — plain HTTP connections are automatically redirected to HTTPS. Generate the local certificates once with mkcert:

```bash
mkcert localhost 127.0.0.1 ::1
mkdir -p certs
mv localhost+2.pem certs/
mv localhost+2-key.pem certs/
```

Then start the server:

```bash
ENV=dev go run ./cmd/tinyproxy/
```

### Production

Production mode listens on `:443` with automatic TLS via Let's Encrypt (ACME), and spins up an HTTP→HTTPS redirect on `:80`.

```bash
go build ./cmd/tinyproxy/
sudo ./tinyproxy
```

Certificates are obtained automatically for every domain defined in `config/vhosts.conf` and cached in the `certs/` directory. The server must be publicly reachable on port 80 for the ACME challenge.

## Configuration

Edit `config/vhosts.conf`. The format is a custom block DSL — not YAML or TOML.

### Reverse proxy

```
vhosts {
    example.com {
        port 443
        proxy_pass http://backend:8080
    }
}
```

### Static file server

```
vhosts {
    example.com {
        port 80
        root /var/www/html
    }
}
```

### PHP via FastCGI

```
vhosts {
    example.com {
        port 80
        root /var/www/html
        fastcgi {
            pass 127.0.0.1:9000
            index index.php
            param SCRIPT_FILENAME /var/www/html/$fastcgi_script_name
        }
    }
}
```

### SSL (production with your own certs)

```
vhosts {
    example.com {
        port 443
        proxy_pass http://backend:8080
        ssl {
            cert /etc/certs/example.com.crt
            key  /etc/certs/example.com.key
        }
    }
}
```

### SOCKS5 proxy for upstream connections

```
vhosts {
    example.com {
        proxy_pass http://backend:8080
        socks5 {
            address  127.0.0.1:1080
            username proxy_user
            password proxy_pass
        }
    }
}
```

### Security headers

```
vhosts {
    example.com {
        proxy_pass http://backend:8080
        security {
            frame_options    DENY
            content_type     nosniff
            xss_protection   "1; mode=block"
            csp              "default-src 'self'"
            hsts             "max-age=31536000; includeSubDomains"
            rate_limit {
                requests 100
                window   1m
            }
        }
    }
}
```

Defaults applied to every vhost: `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security: max-age=31536000; includeSubDomains`, 100 req/min rate limit, 10 MB max body size.

### Bot and AI crawler protection

Bot detection is opt-in per vhost. Enable it with a `bot_protection` block:

```
vhosts {
    example.com {
        proxy_pass http://backend:8080
        bot_protection {
            enabled        true
            block_scanners true
        }
    }
}
```

**`enabled`** — activates the middleware for this vhost.

**`block_scanners`** — blocks requests to known vulnerability-scanning paths: `/.env`, `/.git`, `/wp-admin`, `/phpMyAdmin`, `/actuator`, `/etc/passwd`, and others. Handles URL-encoded variants (`/.%65nv`) and path normalisation tricks (`//wp-admin`).

**`block <token>`** — add extra User-Agent substrings to block beyond the built-in list:

```
bot_protection {
    enabled true
    block   MyCustomScraper
}
```

**`allow <token>`** — permanently allow a User-Agent substring, overriding all block rules:

```
bot_protection {
    enabled true
    allow   FriendlyPartnerBot
}
```

#### Built-in blocked agents

AI crawlers and scrapers blocked by default when `enabled true`:

| Category | Agents |
|---|---|
| AI crawlers | GPTBot, ClaudeBot, CCBot, PerplexityBot, YouBot, anthropic-ai, cohere-ai, Bytespider |
| SEO bots | AhrefsBot, SemrushBot, MJ12bot, DotBot, PetalBot |
| Scrapers | python-requests, Scrapy, libwww-perl, masscan, zgrab |

#### Built-in allowed agents

Always permitted through, regardless of block rules:

Googlebot, bingbot, DuckDuckBot, Slurp (Yahoo), Baiduspider, facebookexternalhit, Twitterbot, LinkedInBot, Applebot

Allowlist matching uses word-boundary detection — a UA like `EvilGooglebot/1.0` is **not** treated as Googlebot.

## TLS

All TLS connections enforce:

- TLS 1.2 minimum
- Forward-secret cipher suites only (ECDHE-AES-GCM, ECDHE-ChaCha20-Poly1305)
- Preferred curves: X25519, P-256

## Development

```bash
# Build
go build ./cmd/tinyproxy/

# Run tests
go test ./...

# Vet
go vet ./...
```
