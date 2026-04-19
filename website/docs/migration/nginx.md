---
sidebar_position: 1
---

# Migrating from nginx

tinyproxy ships with a built-in migration tool that converts your existing nginx configuration into a tinyproxy `vhosts.conf`. It converts everything it can automatically and emits clearly-labelled `# UNSUPPORTED` stubs for directives not yet supported, so you know exactly what to review.

## Quick Start

If you have tinyproxy installed:

```bash
tinyproxy migrate /etc/nginx/nginx.conf
```

This writes two files in your current directory:
- `vhosts.conf` — your converted configuration, ready to use
- `migration-report.md` — a summary of what was converted and what needs manual attention

To specify custom output paths:

```bash
tinyproxy migrate /etc/nginx/nginx.conf --output config/vhosts.conf --report docs/migration-report.md
```

## Python Standalone (no install required)

If you haven't installed tinyproxy yet, use the standalone Python script:

```bash
pip install crossplane
python nginx-migrate.py /etc/nginx/nginx.conf
```

Download `nginx-migrate.py` from the [GitHub releases page](https://github.com/carlHandy/go-tinyproxy/releases).

## What Gets Converted Automatically

The following nginx directives are fully converted with no manual action required:

| nginx | tinyproxy |
|---|---|
| `server { }` | vhost block |
| `server_name example.com` | `example.com {` |
| `listen 443 ssl` | `port 443` + `ssl { }` |
| `root /var/www` | `root /var/www` |
| `proxy_pass http://backend:8080` | `proxy_pass http://backend:8080` |
| `ssl_certificate` / `ssl_certificate_key` | `ssl { cert … key … }` |
| `gzip on` / `gzip off` | `compression on` / `compression off` |
| `fastcgi_pass` / `fastcgi_index` / `fastcgi_param` | `fastcgi { … }` |
| Security `add_header` directives | `security { … }` |
| `limit_req_zone` + `limit_req` | `security { rate_limit { … } }` |
| `upstream { server … }` (multi-backend) | `upstream { backend … }` |
| `upstream` with `ip_hash` / `least_conn` | `upstream { strategy … }` |
| `client_max_body_size` | `max_body_size` |

## What Doesn't Convert

Directives with no tinyproxy equivalent are preserved as `# UNSUPPORTED` comment stubs inline in `vhosts.conf`:

```text
    # UNSUPPORTED[location]: location /api { proxy_pass http://api:3000; }
    # → No URL routing in tinyproxy
    # → See: https://tinyproxy.io/docs/migration/nginx-gap-analysis#url-routing
```

See the [Gap Analysis & Roadmap](./nginx-gap-analysis) for the full list and implementation priority.

## Cookbook

### Simple static site

**nginx:**
```nginx
server {
    server_name example.com;
    listen 80;
    root /var/www/html;
    gzip on;
}
```

**tinyproxy:**
```text
vhosts {
    example.com {
        port 80
        root /var/www/html
        compression on
    }
}
```

### Single reverse proxy

**nginx:**
```nginx
server {
    server_name api.example.com;
    listen 443 ssl;
    ssl_certificate     /etc/ssl/api.pem;
    ssl_certificate_key /etc/ssl/api-key.pem;
    proxy_pass http://api-backend:3000;
}
```

**tinyproxy:**
```text
vhosts {
    api.example.com {
        port 443
        proxy_pass http://api-backend:3000
        ssl {
            cert /etc/ssl/api.pem
            key  /etc/ssl/api-key.pem
        }
    }
}
```

### PHP-FPM / WordPress

**nginx:**
```nginx
server {
    server_name blog.example.com;
    listen 80;
    root /var/www/wordpress;
    fastcgi_pass  127.0.0.1:9000;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME /var/www/wordpress/$fastcgi_script_name;
}
```

**tinyproxy:**
```text
vhosts {
    blog.example.com {
        port 80
        root /var/www/wordpress
        fastcgi {
            pass  127.0.0.1:9000
            index index.php
            param SCRIPT_FILENAME /var/www/wordpress/$fastcgi_script_name
        }
    }
}
```

### Load-balanced API backend

**nginx:**
```nginx
upstream myapp {
    least_conn;
    server 10.0.0.1:8080 weight=3;
    server 10.0.0.2:8080;
}
server {
    server_name app.example.com;
    listen 80;
    proxy_pass http://myapp;
}
```

**tinyproxy:**
```text
vhosts {
    app.example.com {
        port 80
        upstream {
            strategy least_conn
            backend http://10.0.0.1:8080 weight 3
            backend http://10.0.0.2:8080
        }
    }
}
```

### SSL with security headers

**nginx:**
```nginx
server {
    server_name secure.example.com;
    listen 443 ssl;
    ssl_certificate     /etc/ssl/secure.pem;
    ssl_certificate_key /etc/ssl/secure-key.pem;
    add_header X-Frame-Options "DENY";
    add_header Content-Security-Policy "default-src 'self'";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
}
```

**tinyproxy:**
```text
vhosts {
    secure.example.com {
        port 443
        ssl {
            cert /etc/ssl/secure.pem
            key  /etc/ssl/secure-key.pem
        }
        security {
            frame_options DENY
            csp           "default-src 'self'"
            hsts          "max-age=31536000; includeSubDomains"
        }
    }
}
```

### Multi-vhost setup

**nginx:**
```nginx
server {
    server_name site-a.com;
    listen 80;
    root /var/www/site-a;
}
server {
    server_name site-b.com;
    listen 80;
    proxy_pass http://site-b-backend:5000;
}
```

**tinyproxy:**
```text
vhosts {
    site-a.com {
        port 80
        root /var/www/site-a
    }
    site-b.com {
        port 80
        proxy_pass http://site-b-backend:5000
    }
}
```

## Manual Review Checklist

After running the migration tool, check:

- [ ] Review every `# UNSUPPORTED` stub and decide how to handle it manually
- [ ] Verify SSL cert paths are correct on the target system
- [ ] Confirm backend URLs are reachable from tinyproxy's network
- [ ] Check rate limit values (`requests` / `window`) match your intent
- [ ] Test with `ENV=dev go run ./cmd/tinyproxy/` before deploying
- [ ] Remove the nginx fallback only after confirming tinyproxy handles your traffic correctly
