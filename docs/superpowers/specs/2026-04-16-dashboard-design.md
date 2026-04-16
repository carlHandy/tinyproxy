# Dashboard Design Spec
**Date:** 2026-04-16  
**Status:** Approved

## Overview

An optional admin dashboard embedded in the `go-tinyproxy` binary. Disabled by default; enabled via `--enable-dashboard`. Provides config CRUD, live log streaming, and traffic analytics. Runs as a second `http.Server` inside the main process, completely isolated from the proxy handler chain.

---

## 1. CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--enable-dashboard` | off | Starts the dashboard server alongside the proxy |
| `--dashboard-port` | `9000` | Port the dashboard listens on |
| `--dashboard-host` | `127.0.0.1` | Bind address. Any value other than `127.0.0.1`, `localhost`, or `::1` requires `--dashboard-creds` |
| `--dashboard-creds` | — | Path to credentials file. Required when host is not localhost |
| `--dashboard-db` | `dashboard.db` | SQLite file for persisted request stats and log history |
| `--dashboard-cert` | — | TLS certificate for dashboard (optional override) |
| `--dashboard-key` | — | TLS private key for dashboard (optional override) |

### Startup enforcement

- If `--dashboard-host` is not a localhost address and `--dashboard-creds` is missing or unreadable → **refuse to start** with a clear error message.
- If `--dashboard-host` is not localhost and no TLS cert is available (neither `--dashboard-cert` nor a vhost cert) → **refuse to start**.
- No silent fallbacks.

### Credentials file format

One line:
```
username:$2a$12$<bcrypt_hash>
```

Helper subcommand to generate credentials:
```
go-tinyproxy dashboard passwd
```
Prompts interactively, prints the hashed line to stdout. Plaintext passwords are never stored.

---

## 2. Architecture

### New package: `internal/dashboard`

Three sub-components:

#### `stats.Collector`
- Receives a `RequestRecord` (timestamp, vhost, method, status, latency, bytes, remote IP, path) via a buffered channel after every request.
- `VHostHandler.ServeHTTP` sends to this channel non-blocking — proxy is never delayed.
- Flushes to SQLite in batches every 5 seconds.
- Exposes aggregated query methods: req/s over time, top vhosts, top paths, status code distribution, bandwidth.

#### `logring.Buffer`
- Installed via `log.SetOutput` at startup — captures all proxy log lines.
- In-memory ring buffer (10,000 lines default).
- Also persisted to SQLite `log_lines` table.
- Exposes a channel for SSE streaming to connected dashboard clients.

#### `dashboard.Server`
A standalone `http.Server` with its own ServeMux. Wrapped with:
- `middleware/recovery.go` — panics return 500, never propagate
- Basic Auth middleware (when host ≠ localhost)
- Rate limiter for auth failures (5 attempts/min per IP)

### API Routes

| Method | Route | Description |
|---|---|---|
| `GET` | `/` | Dashboard HTML shell |
| `GET` | `/api/stats` | Aggregated traffic stats; accepts `?window=1h\|6h\|24h\|7d` |
| `GET` | `/api/logs/stream` | SSE stream of live log lines; accepts `?vhost=` and `?level=` filters |
| `GET` | `/api/logs` | Historical log lines; accepts `?before=<unix_ts>` for pagination |
| `GET` | `/api/config` | Returns `{ raw: "<file contents>", parsed: { vhosts: [...] } }` |
| `PUT` | `/api/config` | Validate + atomic write + SIGHUP reload |
| `POST` | `/api/config/validate` | Dry-run parse; returns errors with line numbers, never writes |

### Config write flow (safe)
1. Parse submitted config with `config.NewParser` in memory → reject on any error, return line numbers.
2. Write to `vhosts.conf.tmp`.
3. `os.Rename` (atomic on Linux) to `vhosts.conf`.
4. Send SIGHUP to self — existing reload logic handles it.
5. If reload fails: log the error. The old config remains running. Return error to the UI.

---

## 3. Database Schema (SQLite)

```sql
CREATE TABLE requests (
    id       INTEGER PRIMARY KEY,
    ts       INTEGER NOT NULL,  -- unix ms
    vhost    TEXT NOT NULL,
    method   TEXT NOT NULL,
    path     TEXT NOT NULL,
    status   INTEGER NOT NULL,
    latency  INTEGER NOT NULL,  -- microseconds
    bytes    INTEGER NOT NULL,
    remote   TEXT NOT NULL
);
CREATE INDEX idx_requests_ts    ON requests(ts);
CREATE INDEX idx_requests_vhost ON requests(vhost, ts);

CREATE TABLE log_lines (
    id    INTEGER PRIMARY KEY,
    ts    INTEGER NOT NULL,
    level TEXT NOT NULL,
    body  TEXT NOT NULL
);
CREATE INDEX idx_log_lines_ts ON log_lines(ts);
```

**Retention:** Rows older than 30 days are pruned on startup.  
**Write pattern:** Batched every 5 seconds to avoid WAL pressure.

---

## 4. UI (HTMX + Tailwind)

Embedded in the binary via `go:embed`. No runtime build step.

**Tailwind:** Pre-built CSS file committed to the repo, regenerated with the Tailwind CLI when styles change. CDN used in development only.

**Chart.js:** Loaded from CDN for sparkline/bar charts.

### Layout
Left sidebar navigation + main content area.

### Sections

#### Overview
- Stats cards: total requests, error rate, avg latency, total bandwidth.
- Req/s sparkline over last 60 minutes (Chart.js).
- Auto-refreshes every 10s via `hx-trigger="every 10s"`.

#### Traffic
- Tabbed: top vhosts, top paths, status code distribution, top IPs.
- Time range selector: 1h / 6h / 24h / 7d.
- Pulls from `/api/stats` via HTMX.

#### Logs
- Live tail via SSE (`hx-ext="sse"`), auto-scroll toggle.
- Filter by level (info/error) and vhost.
- Scroll-up loads older history from `/api/logs?before=<ts>`.

#### Config
Two tabs:

**Visual editor:** One card per vhost. Fields for: domain, proxy_pass, SSL on/off, rate limit (requests/window), bot protection toggle, compression toggle, SOCKS5 address, root directory, FastCGI pass. Submit runs `POST /api/config/validate` first — inline errors shown before save is allowed.

**Raw editor:** `<textarea>` with monospace font. Same validate-before-save flow. Diff preview shown before confirming a save.

All destructive actions (save config, delete vhost) require an explicit confirmation step.

---

## 5. Security

- **Basic Auth:** `bcrypt.CompareHashAndPassword` — timing-safe. Brute force protection: 5 failed attempts/min per IP before 429.
- **TLS when public:** Uses `--dashboard-cert`/`--dashboard-key` if provided, otherwise falls back to the cert of the vhost named `default`, or the first vhost alphabetically if `default` is absent. No cert available + non-localhost host = startup refusal.
- **Dashboard isolation:** Runs in a separate goroutine with `recovery.go` middleware. A panic returns HTTP 500 and is logged; the proxy is unaffected.
- **Config atomicity:** Temp-file + rename prevents partial writes. Parse-before-write prevents invalid config from ever reaching disk.
- **No proxy interference:** Stats collection uses a non-blocking buffered channel send — a full channel drops the record and logs a warning rather than blocking the request path.

---

## 6. New Subcommands

| Subcommand | Description |
|---|---|
| `go-tinyproxy dashboard passwd` | Interactive bcrypt credential generator |

---

## 7. File Layout

```
internal/dashboard/
    server.go          — dashboard.Server, route registration, auth middleware
    stats/
        collector.go   — RequestRecord, Collector, aggregation queries
        db.go          — SQLite schema, batch writer, pruning
    logring/
        buffer.go      — ring buffer, log.SetOutput hook, SSE fan-out
    config/
        api.go         — GET/PUT /api/config handlers, validate+atomic write
cmd/tinyproxy/
    dashboard_flags.go — flag definitions, startup validation
static/dashboard/
    index.html         — HTMX + Tailwind shell
    dashboard.css      — pre-built Tailwind output
    dashboard.js       — minimal JS (SSE setup, diff preview, Chart.js init)
```
