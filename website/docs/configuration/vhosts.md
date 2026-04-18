# Virtual Hosts (vhosts.conf)

**tinyproxy** uses a custom block-based Configuration DSL. The configuration file is typically located at `config/vhosts.conf`.

## Basic Structure

```text
vhosts {
    example.com {
        # Directives go here
    }
}
```

## Directives

### Reverse Proxy
Forward requests to an upstream server.
```text
proxy_pass http://localhost:3000
```

### Static File Server
Serve files from a local directory.
```text
root /var/www/html
```

### FastCGI (PHP)
Proxy to a FastCGI server (e.g., PHP-FPM).
```text
fastcgi {
    pass 127.0.0.1:9000
    index index.php
    param SCRIPT_FILENAME /var/www/html/$fastcgi_script_name
}
```

### SSL (Custom Certificates)
If you don't want to use automatic ACME, you can provide your own certificates.
```text
ssl {
    cert /path/to/cert.pem
    key  /path/to/key.pem
}
```

### SOCKS5 Upstream
Use a SOCKS5 proxy for upstream connections.
```text
socks5 {
    address  127.0.0.1:1080
    username myuser
    password mypass
}
```

## Advanced Configuration

### Load Balancing
Distribute traffic across multiple backends using an `upstream` block.
```text
vhosts {
    api.example.com {
        upstream {
            strategy cookie          # round_robin | least_conn | ip_hash | weighted | cookie
            cookie_name _tp_backend  # sticky-session cookie name (default: _tp_backend)

            backend http://10.0.0.1:8080 weight 3
            backend http://10.0.0.2:8080 weight 2
            backend http://10.0.0.3:8080

            health_check {
                path           /healthz
                interval       10s
                timeout        5s
                fail_threshold 3
                pass_threshold 2
            }
        }
    }
}
```

Available strategies:
- `round_robin` (Default)
- `least_conn`
- `ip_hash`
- `weighted`
- `cookie` (Sticky sessions)

### Response Caching
Cache upstream responses in memory.
```text
cache {
    enabled              true
    max_size             256MB   # maximum in-memory cache size
    default_ttl          5m      # fallback TTL when no Cache-Control header
    stale_while_revalidate 30s
    bypass_header        X-Cache-Bypass
}
```
