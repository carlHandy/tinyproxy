---
sidebar_position: 2
---

# nginx Directive Map

Full reference mapping every nginx directive (open-source and nginx Plus) to its tinyproxy equivalent or an explanation of why it's not yet supported.

✅ = Fully converted  ⚠️ = Partially converted  ❌ = Unsupported (stubbed)

## Core Server Directives

| nginx directive | tinyproxy | Status | Notes |
|---|---|---|---|
| `server { }` | vhost block | ✅ | |
| `server_name` | hostname key | ✅ | First name used; aliases dropped |
| `listen` | `port` | ✅ | `ssl` flag detected |
| `root` | `root` | ✅ | |
| `proxy_pass` (single) | `proxy_pass` | ✅ | |
| `proxy_pass` (upstream ref) | `upstream { }` | ✅ | Named upstream resolved |
| `client_max_body_size` | `max_body_size` | ✅ | |
| `gzip on/off` | `compression on/off` | ✅ | brotli also enabled when on |
| `index` | — | ❌ | |
| `alias` | — | ❌ | Use `root` |
| `autoindex` | — | ❌ | |

## SSL / TLS

| nginx directive | tinyproxy | Status | Notes |
|---|---|---|---|
| `ssl_certificate` | `ssl { cert }` | ✅ | |
| `ssl_certificate_key` | `ssl { key }` | ✅ | |
| `ssl_protocols` | — | ❌ | tinyproxy enforces TLS 1.2+ always |
| `ssl_ciphers` | — | ❌ | Forward-secret ciphers enforced by default |
| `ssl_session_cache` | — | ❌ | |
| `ssl_session_timeout` | — | ❌ | |
| `ssl_prefer_server_ciphers` | — | ❌ | |

## Security Headers

| nginx directive | tinyproxy | Status |
|---|---|---|
| `add_header X-Frame-Options` | `security { frame_options }` | ✅ |
| `add_header X-Content-Type-Options` | `security { content_type }` | ✅ |
| `add_header X-XSS-Protection` | `security { xss_protection }` | ✅ |
| `add_header Content-Security-Policy` | `security { csp }` | ✅ |
| `add_header Strict-Transport-Security` | `security { hsts }` | ✅ |
| `add_header` (other) | — | ❌ | Generic header manipulation not yet supported |

## Rate Limiting

| nginx directive | tinyproxy | Status | Notes |
|---|---|---|---|
| `limit_req_zone` + `limit_req` | `security { rate_limit { } }` | ✅ | Rate and window extracted from zone definition |
| `limit_conn_zone` + `limit_conn` | — | ❌ | Connection limiting not yet supported |
| `limit_req_status` | — | ❌ | |

## FastCGI

| nginx directive | tinyproxy | Status |
|---|---|---|
| `fastcgi_pass` | `fastcgi { pass }` | ✅ |
| `fastcgi_index` | `fastcgi { index }` | ✅ |
| `fastcgi_param` | `fastcgi { param }` | ✅ |
| `fastcgi_read_timeout` | — | ❌ |
| `fastcgi_buffers` | — | ❌ |

## Upstream / Load Balancing

| nginx directive | tinyproxy | Status | Notes |
|---|---|---|---|
| `upstream { server … }` | `upstream { backend … }` | ✅ | |
| `ip_hash` | `upstream { strategy ip_hash }` | ✅ | |
| `least_conn` | `upstream { strategy least_conn }` | ✅ | |
| `random` | `upstream { strategy round_robin }` | ⚠️ | Mapped to round_robin |
| `server weight=N` | `backend … weight N` | ✅ | |
| `server backup` | — | ⚠️ | Backup flag dropped |
| `keepalive` | — | ⚠️ | Stubbed; keepalive not configurable |

## Caching

| nginx directive | tinyproxy | Status | Notes |
|---|---|---|---|
| `proxy_cache_path` | — | ❌ | Path-based cache not supported |
| `proxy_cache` | `cache { enabled true }` | ⚠️ | |
| `proxy_cache_valid` | `cache { default_ttl }` | ⚠️ | |

## URL Routing & Rewriting

| nginx directive | tinyproxy | Status |
|---|---|---|
| `location` | — | ❌ |
| `rewrite` | — | ❌ |
| `try_files` | — | ❌ |
| `return` | — | ❌ |
| `map` | — | ❌ |
| `if` | — | ❌ |

## Proxy Headers & Timeouts

| nginx directive | tinyproxy | Status |
|---|---|---|
| `proxy_set_header` | — | ❌ |
| `proxy_hide_header` | — | ❌ |
| `proxy_read_timeout` | — | ❌ |
| `proxy_send_timeout` | — | ❌ |
| `proxy_connect_timeout` | — | ❌ |

## Auth

| nginx directive | tinyproxy | Status |
|---|---|---|
| `auth_basic` | — | ❌ |
| `auth_basic_user_file` | — | ❌ |
| `auth_request` | — | ❌ |

## Logging

| nginx directive | tinyproxy | Status |
|---|---|---|
| `access_log` | — | ❌ |
| `error_log` | — | ❌ |

## nginx Plus Directives

| nginx Plus directive | tinyproxy | Status |
|---|---|---|
| `health_check` (active) | — | ❌ |
| `auth_jwt` | — | ❌ |
| `auth_jwt_key_file` | — | ❌ |
| `oidc` | — | ❌ |
| `resolver` | — | ❌ |
| `js_include` / `js_content` (njs) | — | ❌ |
| Lua / OpenResty | — | ❌ |

## Block-Level Directives (Unsupported)

| nginx directive | tinyproxy | Status |
|---|---|---|
| `stream { }` | — | ❌ |
| `mail { }` | — | ❌ |
| `geo` | — | ❌ |
| `sub_filter` | — | ❌ |
| `mirror` | — | ❌ |
| `error_page` | — | ❌ |
