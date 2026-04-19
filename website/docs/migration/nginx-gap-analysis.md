---
sidebar_position: 3
---

# Gap Analysis & Roadmap

This page documents nginx features that tinyproxy does not yet support, grouped by implementation priority. Each item includes a brief rationale for why it blocks real-world migrations.

Directives in this list are emitted as `# UNSUPPORTED` stubs by the migration tool so you know exactly what to revisit when support is added.

---

## P1 — Blocks majority of real-world migrations

### URL Routing

**nginx:**
```nginx
location /api/ {
    proxy_pass http://api-backend:3000;
}
location / {
    root /var/www/html;
}
```

**Status:** Not supported. tinyproxy operates at the virtual host level — all requests for a vhost go to the same backend or root. Every nginx config that splits traffic by path requires `location` blocks.

**Planned:** Prefix, exact (`=`), and regex matching with per-location `proxy_pass`/`root`/`redirect`.

---

### Redirects

**nginx:**
```nginx
return 301 https://example.com$request_uri;
```

**Status:** Not supported.

**Planned:** `redirect` directive at the vhost level and (once location routing lands) per-location redirects.

---

### Try Files

**nginx:**
```nginx
try_files $uri $uri/ /index.html;
```

**Status:** Not supported. Used in almost every SPA and WordPress config to serve static files before falling back to a backend.

**Planned:** `try_files` directive on the static file handler.

---

## P2 — Common production patterns

### Proxy Set Header

**nginx:**
```nginx
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
add_header X-Custom-Header "value";
```

**Status:** Not supported for arbitrary headers. Security-specific `add_header` directives (X-Frame-Options, CSP, HSTS, etc.) are fully supported via the `security` block.

**Planned:** `proxy_set_header` and `add_header` directives for arbitrary request/response header manipulation.

---

### Auth Basic

**nginx:**
```nginx
auth_basic "Restricted";
auth_basic_user_file /etc/nginx/.htpasswd;
```

**Status:** Not supported.

**Planned:** `auth_basic` block per vhost backed by an htpasswd file.

---

### Limit Conn

**nginx:**
```nginx
limit_conn_zone $binary_remote_addr zone=conn:10m;
limit_conn conn 10;
```

**Status:** Not supported. Rate limiting (`limit_req`) is fully supported.

**Planned:** `security { limit_conn N }` directive alongside the existing `rate_limit` block.

---

### Error Pages

**nginx:**
```nginx
error_page 404 /404.html;
error_page 500 502 503 504 /50x.html;
```

**Status:** Not supported.

**Planned:** `error_page` directive mapping HTTP status codes to static files or backend paths.

---

### Timeouts

**nginx:**
```nginx
proxy_connect_timeout 5s;
proxy_read_timeout    30s;
proxy_send_timeout    30s;
```

**Status:** Not supported. Defaults are used.

**Planned:** `connect_timeout`, `read_timeout`, `send_timeout` directives inside the `upstream` block.

---

## P3 — Advanced / niche

### Rewrites

**nginx:**
```nginx
rewrite ^/old/(.*)$ /new/$1 permanent;
```

**Status:** Not supported. Requires location routing (P1) as a foundation.

**Planned:** After P1 lands — `rewrite` directive with regex and capture group support.

---

### Map

**nginx:**
```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
}
```

**Status:** Not supported.

---

### Geo

**nginx:**
```nginx
geo $country {
    default ZZ;
    1.2.3.0/24 US;
}
```

**Status:** Not supported.

---

### Logging

**nginx:**
```nginx
access_log /var/log/nginx/api.access.log combined;
error_log  /var/log/nginx/api.error.log warn;
```

**Status:** Not supported. tinyproxy logs all vhosts to a single stream.

**Planned:** Optional per-vhost log path and level in the vhost block.

---

## P4 — nginx Plus parity (no planned timeline)

These features are specific to the commercial nginx Plus product and are not currently on the tinyproxy roadmap.

### JWT

nginx Plus `auth_jwt` / `auth_jwt_key_file` directives for JSON Web Token validation. Not planned.

### OIDC

nginx Plus OIDC integration. Not planned. Use an upstream identity-aware proxy.

### njs

`js_include`, `js_content`, and related njs directives. Not planned.

### Lua

Lua-based request/response scripting. Not planned.

### Health Check Plus

The `health_check` directive in nginx Plus runs active probes configured as a location directive, distinct from tinyproxy's built-in `health_check` block in `upstream`. nginx Plus configs that use `health_check` inside `location` blocks will be stubbed.

---

## Contributing

If you need any of the P1–P3 features, please [open an issue](https://github.com/carlHandy/go-tinyproxy/issues) or submit a pull request. P1 items (URL routing, redirects, try\_files) are the highest leverage and will unlock the most migrations.
