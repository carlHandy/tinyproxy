# tinyproxy

A security-focused reverse proxy and web server — a single-binary alternative to nginx + Traefik with native bot detection and AI crawler prevention built into the request pipeline.

## Requirements

- Go 1.23+ (only if building from source)
- [mkcert](https://github.com/FiloSottile/mkcert) (development only)

## Installation

You can download pre-compiled binaries and packages for your operating system from the [Releases page](https://github.com/carlHandy/tinyproxy/releases).

### Debian / Ubuntu
Download the `.deb` package and install it (replace `1.0.0` with the latest version):
```bash
wget https://github.com/carlHandy/tinyproxy/releases/download/v1.0.0/tinyproxy_1.0.0_linux_amd64.deb
sudo dpkg -i tinyproxy_1.0.0_linux_amd64.deb
```

### RHEL / Fedora / AlmaLinux
Download the `.rpm` package and install it (replace `1.0.0` with the latest version):
```bash
wget https://github.com/carlHandy/tinyproxy/releases/download/v1.0.0/tinyproxy_1.0.0_linux_amd64.rpm
sudo rpm -i tinyproxy_1.0.0_linux_amd64.rpm
```

### macOS / Linux (Standalone Binary)
Download the `.tar.gz` archive, extract it, and move the binary to your path:
```bash
wget https://github.com/carlHandy/tinyproxy/releases/download/v1.0.0/tinyproxy_1.0.0_linux_amd64.tar.gz
tar -xzf tinyproxy_1.0.0_linux_amd64.tar.gz
sudo mv tinyproxy /usr/local/bin/
```
*(Note: If you are on macOS or an ARM64 machine, make sure to grab the `darwin` or `arm64` archive instead!)*

### Windows
Download `tinyproxy_1.0.0_windows_amd64.zip` from the releases page, extract it, and run `tinyproxy.exe` from your command prompt or PowerShell.

### Build from Source
If you prefer to compile it yourself:
```bash
git clone https://github.com/carlHandy/tinyproxy.git
cd tinyproxy
go build -o tinyproxy ./cmd/tinyproxy/
sudo mv tinyproxy /usr/local/bin/
```

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
tinyproxy
```
*(Note: If not installed via a package manager to run as a service, you may need to run with `sudo` to bind to ports 80 and 443).*

Certificates are obtained automatically for every domain defined in `config/vhosts.conf` and cached in the `certs/` directory. The server must be publicly reachable on port 80 for the ACME challenge.

## Configuration

Edit `config/vhosts.conf`. The format is a custom block DSL — not YAML or TOML.

### Reverse proxy

```text
vhosts {
    example.com {
        port 443
        proxy_pass http://backend:8080
    }
}
```

### Static file server

```text
vhosts {
    example.com {
        port 80
        root /var/www/html
    }
}
```

### PHP via FastCGI

```text
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

```text
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

```text
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

```text
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

```text
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

```text
bot_protection {
    enabled true
    block   MyCustomScraper
}
```

**`allow <token>`** — permanently allow a User-Agent substring, overriding all block rules:

```text
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
