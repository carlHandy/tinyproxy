# nginx Migration Guide & Tooling — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `tinyproxy migrate`, a Python standalone script, and a Docusaurus migration guide that converts nginx configs to tinyproxy format — converting what it can and emitting `# UNSUPPORTED` stubs for the rest.

**Architecture:** The Go CLI uses `github.com/nginxinc/nginx-go-crossplane` to parse nginx into an AST, walks each `server {}` block to produce a `vhostConf` struct, then renders tinyproxy config text with inline stubs. A Python standalone (`tools/nginx-migrate.py`) mirrors the logic using the `crossplane` PyPI package. Three Docusaurus pages document the migration, directive mapping, and gap analysis.

**Tech Stack:** Go 1.25, `github.com/nginxinc/nginx-go-crossplane` v0.4.88+, Python 3.8+ with `crossplane` PyPI package, Docusaurus (existing `website/` site).

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Modify | `internal/server/config/parser.go` | Add `max_body_size` directive |
| Create | `internal/server/config/parser_maxbody_test.go` | Test `max_body_size` parsing |
| Create | `cmd/tinyproxy/migrate.go` | All converter logic + CLI entry point |
| Create | `cmd/tinyproxy/migrate_test.go` | Unit + integration tests for converter |
| Modify | `cmd/tinyproxy/main.go` | Wire `case "migrate":` into CLI dispatch |
| Create | `tools/nginx-migrate.py` | Python standalone converter |
| Create | `website/docs/migration/nginx.md` | Main migration guide |
| Create | `website/docs/migration/nginx-directive-map.md` | Full directive reference table |
| Create | `website/docs/migration/nginx-gap-analysis.md` | Gap analysis + implementation roadmap |
| Modify | `website/sidebars.js` | Add Migration category |
| Modify | `go.mod` / `go.sum` | Add crossplane dependency |

---

## Task 1: Add `max_body_size` directive to the config parser

**Files:**
- Modify: `internal/server/config/parser.go` — add case in `parseLine`
- Create: `internal/server/config/parser_maxbody_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/server/config/parser_maxbody_test.go`:

```go
package config

import (
	"strings"
	"testing"
)

func TestParser_MaxBodySize(t *testing.T) {
	input := `
vhosts {
    example.com {
        port 80
        root /var/www
        max_body_size 20MB
    }
}`
	p := NewParser(strings.NewReader(input))
	cfg, err := p.Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	vh, ok := cfg.VHosts["example.com"]
	if !ok {
		t.Fatal("vhost not found")
	}
	const want = 20 << 20
	if vh.MaxBodySize != want {
		t.Errorf("MaxBodySize = %d, want %d", vh.MaxBodySize, want)
	}
}
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
go test ./internal/server/config/... -run TestParser_MaxBodySize -v
```

Expected: FAIL — `unknown directive "max_body_size"`

- [ ] **Step 3: Add the directive to `parseLine` in `internal/server/config/parser.go`**

In the `switch parts[0]` block in `parseLine`, add after the `"compression"` case:

```go
case "max_body_size":
    if len(parts) < 2 {
        return fmt.Errorf("max_body_size requires a value")
    }
    size, err := parseByteSize(parts[1])
    if err != nil {
        return fmt.Errorf("max_body_size: %w", err)
    }
    p.currentVHost.MaxBodySize = size
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/server/config/... -v
```

Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add internal/server/config/parser.go internal/server/config/parser_maxbody_test.go
git commit -m "feat(config): add max_body_size directive to vhost parser"
```

---

## Task 2: Add the nginx-go-crossplane Go dependency

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Fetch the module**

```bash
go get github.com/nginxinc/nginx-go-crossplane@latest
```

Expected output: line added to `go.mod` like `github.com/nginxinc/nginx-go-crossplane v0.4.88`

- [ ] **Step 2: Verify the build still compiles**

```bash
go build ./...
```

Expected: exits 0 with no output.

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore(deps): add nginx-go-crossplane for nginx config parsing"
```

---

## Task 3: Core converter — types and basic server block directives

Converts `server_name`, `listen`, `root`, `proxy_pass`, `ssl_certificate/key`, `gzip`, `client_max_body_size`.

**Files:**
- Create: `cmd/tinyproxy/migrate.go`
- Create: `cmd/tinyproxy/migrate_test.go`

- [ ] **Step 1: Write the failing tests**

Create `cmd/tinyproxy/migrate_test.go`:

```go
package main

import (
	"os"
	"strings"
	"testing"

	crossplane "github.com/nginxinc/nginx-go-crossplane"
)

// helpers

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "nginx-*.conf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	f.WriteString(content)
	f.Close()
	return f.Name()
}

// Task 3 tests

func TestConvertServerBlock_Basic(t *testing.T) {
	dirs := crossplane.Directives{
		{Directive: "server_name", Args: []string{"example.com"}},
		{Directive: "listen", Args: []string{"80"}},
		{Directive: "root", Args: []string{"/var/www/html"}},
	}
	mc := &migrateConf{report: reportConf{}}
	vh := mc.convertServerBlock(dirs, nil, nil, "")
	if vh.hostname != "example.com" {
		t.Errorf("hostname = %q, want %q", vh.hostname, "example.com")
	}
	if vh.port != 80 {
		t.Errorf("port = %d, want 80", vh.port)
	}
	if vh.root != "/var/www/html" {
		t.Errorf("root = %q, want %q", vh.root, "/var/www/html")
	}
}

func TestConvertServerBlock_SSL(t *testing.T) {
	dirs := crossplane.Directives{
		{Directive: "server_name", Args: []string{"example.com"}},
		{Directive: "listen", Args: []string{"443", "ssl"}},
		{Directive: "ssl_certificate", Args: []string{"/etc/ssl/cert.pem"}},
		{Directive: "ssl_certificate_key", Args: []string{"/etc/ssl/key.pem"}},
	}
	mc := &migrateConf{report: reportConf{}}
	vh := mc.convertServerBlock(dirs, nil, nil, "")
	if vh.port != 443 {
		t.Errorf("port = %d, want 443", vh.port)
	}
	if vh.ssl == nil {
		t.Fatal("ssl is nil")
	}
	if vh.ssl.cert != "/etc/ssl/cert.pem" {
		t.Errorf("ssl.cert = %q, want %q", vh.ssl.cert, "/etc/ssl/cert.pem")
	}
	if vh.ssl.key != "/etc/ssl/key.pem" {
		t.Errorf("ssl.key = %q, want %q", vh.ssl.key, "/etc/ssl/key.pem")
	}
}

func TestConvertNginxFile_Simple(t *testing.T) {
	conf := `
http {
    server {
        server_name example.com;
        listen 80;
        root /var/www/html;
    }
}`
	mc, err := convertNginxFile(writeTemp(t, conf))
	if err != nil {
		t.Fatalf("convertNginxFile: %v", err)
	}
	if len(mc.vhosts) != 1 {
		t.Fatalf("got %d vhosts, want 1", len(mc.vhosts))
	}
	if mc.vhosts[0].hostname != "example.com" {
		t.Errorf("hostname = %q", mc.vhosts[0].hostname)
	}
}

func TestParseListenArgs(t *testing.T) {
	cases := []struct {
		args      []string
		wantPort  int
		wantSSL   bool
	}{
		{[]string{"80"}, 80, false},
		{[]string{"443", "ssl"}, 443, true},
		{[]string{"443", "ssl", "http2"}, 443, true},
		{[]string{"0.0.0.0:8080"}, 8080, false},
		{[]string{"[::]:443", "ssl"}, 443, true},
	}
	for _, c := range cases {
		port, ssl := parseListenArgs(c.args)
		if port != c.wantPort || ssl != c.wantSSL {
			t.Errorf("parseListenArgs(%v) = (%d,%v), want (%d,%v)", c.args, port, ssl, c.wantPort, c.wantSSL)
		}
	}
}

func TestConvertBodySize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"20m", "20MB"},
		{"1g", "1GB"},
		{"512k", "512KB"},
		{"0", ""},
		{"1024", "1024B"},
	}
	for _, c := range cases {
		if got := convertBodySize(c.in); got != c.want {
			t.Errorf("convertBodySize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./cmd/tinyproxy/... -run "TestConvert|TestParse" -v 2>&1 | head -20
```

Expected: compilation error — types and functions don't exist yet.

- [ ] **Step 3: Create `cmd/tinyproxy/migrate.go` with types and basic converter**

```go
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	crossplane "github.com/nginxinc/nginx-go-crossplane"
)

// ── Types ─────────────────────────────────────────────────────────────────────

type migrateConf struct {
	vhosts []*vhostConf
	report reportConf
}

type vhostConf struct {
	hostname    string
	port        int
	root        string
	proxyPass   string
	ssl         *sslConf
	compression string // "on" | "off" | ""
	security    secConf
	fastcgi     *fastcgiConf
	upstream    *upstreamConf
	maxBodySize string // e.g. "20MB"; empty = not set
	stubs       []inlineStub
}

type sslConf struct{ cert, key string }

type secConf struct {
	frameOptions  string
	contentType   string
	xssProtection string
	csp           string
	hsts          string
	rateReqs      int
	rateWin       string
}

type fastcgiConf struct {
	pass   string
	index  string
	params []string // "KEY VALUE" pairs
}

type upstreamConf struct {
	strategy string
	backends []string // "http://host:port [weight N]"
	stubs    []inlineStub
}

type inlineStub struct {
	tag    string
	raw    string
	reason string
	anchor string
}

type rateLimitConf struct {
	requests int
	window   string
}

type reportConf struct {
	source    string
	generated time.Time
	converted int
	stubbed   int
	entries   []reportEntry
}

type reportEntry struct {
	vhost     string
	directive string
	file      string
	line      int
	reason    string
}

// ── Unsupported directive table ───────────────────────────────────────────────

var unsupportedDirectives = map[string][2]string{
	"location":              {"No URL routing in tinyproxy", "url-routing"},
	"rewrite":               {"URL rewriting not supported", "rewrites"},
	"map":                   {"map directive not supported", "map"},
	"if":                    {"if blocks not supported", "conditionals"},
	"try_files":             {"try_files not supported", "try-files"},
	"return":                {"Redirects (return) not supported", "redirects"},
	"error_page":            {"Custom error pages not supported", "error-pages"},
	"auth_basic":            {"HTTP basic auth not supported", "auth-basic"},
	"auth_basic_user_file":  {"HTTP basic auth not supported", "auth-basic"},
	"auth_request":          {"auth_request not supported", "auth-request"},
	"limit_conn":            {"Connection limiting not supported", "limit-conn"},
	"limit_conn_zone":       {"Connection limiting not supported", "limit-conn"},
	"proxy_set_header":      {"Request header manipulation not supported", "proxy-set-header"},
	"proxy_hide_header":     {"Response header manipulation not supported", "proxy-set-header"},
	"proxy_read_timeout":    {"Upstream timeouts not supported", "timeouts"},
	"proxy_send_timeout":    {"Upstream timeouts not supported", "timeouts"},
	"proxy_connect_timeout": {"Upstream timeouts not supported", "timeouts"},
	"access_log":            {"Per-vhost logging config not supported", "logging"},
	"error_log":             {"Per-vhost logging config not supported", "logging"},
	"geo":                   {"geo module not supported", "geo"},
	"sub_filter":            {"sub_filter not supported", "sub-filter"},
	"mirror":                {"mirror not supported", "mirror"},
	"stream":                {"stream blocks not supported", "stream"},
	"mail":                  {"mail blocks not supported", "mail"},
	"health_check":          {"nginx Plus active health_check not supported", "health-check-plus"},
	"auth_jwt":              {"nginx Plus JWT auth not supported", "jwt"},
	"auth_jwt_key_file":     {"nginx Plus JWT auth not supported", "jwt"},
	"js_include":            {"njs not supported", "njs"},
	"js_content":            {"njs not supported", "njs"},
}

// silently ignored directives that don't need a stub
var silentDirectives = map[string]bool{
	"server_name":          true,
	"listen":               true,
	"tcp_nopush":           true,
	"tcp_nodelay":          true,
	"keepalive_timeout":    true,
	"sendfile":             true,
	"types":                true,
	"include":              true,
	"default_type":         true,
	"worker_processes":     true,
	"worker_connections":   true,
	"events":               true,
	"pid":                  true,
	"user":                 true,
	"proxy_buffering":      true,
	"proxy_buffer_size":    true,
	"proxy_buffers":        true,
}

// ── Top-level converter ───────────────────────────────────────────────────────

func convertNginxFile(filename string) (*migrateConf, error) {
	payload, err := crossplane.Parse(filename, &crossplane.ParseOptions{
		CombineConfigs: true,
	})
	if err != nil {
		return nil, fmt.Errorf("parse nginx config: %w", err)
	}
	if len(payload.Config) == 0 {
		return nil, fmt.Errorf("no config found in %s", filename)
	}

	mc := &migrateConf{
		report: reportConf{source: filename, generated: time.Now()},
	}

	for _, d := range payload.Config[0].Parsed {
		switch d.Directive {
		case "http":
			mc.convertHTTPBlock(d.Block)
		case "events":
			// ignored
		default:
			if reason, ok := unsupportedDirectives[d.Directive]; ok {
				mc.report.entries = append(mc.report.entries, reportEntry{
					vhost:     "(global)",
					directive: d.Directive,
					line:      d.Line,
					reason:    reason[0],
				})
				mc.report.stubbed++
			}
		}
	}
	return mc, nil
}

func (mc *migrateConf) convertHTTPBlock(dirs crossplane.Directives) {
	upstreams := map[string]crossplane.Directives{}
	rateZones := map[string]rateLimitConf{}
	var httpGzip string

	for _, d := range dirs {
		switch d.Directive {
		case "upstream":
			if len(d.Args) > 0 {
				upstreams[d.Args[0]] = d.Block
			}
		case "limit_req_zone":
			if name, rl, ok := parseLimitReqZone(d.Args); ok {
				rateZones[name] = rl
			}
		case "gzip":
			if len(d.Args) > 0 {
				httpGzip = d.Args[0]
			}
		}
	}

	for _, d := range dirs {
		if d.Directive == "server" {
			vh := mc.convertServerBlock(d.Block, upstreams, rateZones, httpGzip)
			if vh != nil {
				mc.vhosts = append(mc.vhosts, vh)
			}
		}
	}
}

func (mc *migrateConf) convertServerBlock(
	dirs crossplane.Directives,
	upstreams map[string]crossplane.Directives,
	rateZones map[string]rateLimitConf,
	httpGzip string,
) *vhostConf {
	vh := &vhostConf{compression: httpGzip}

	// first pass: server_name + listen (needed for hostname/port/ssl before other directives)
	for _, d := range dirs {
		switch d.Directive {
		case "server_name":
			if len(d.Args) > 0 && vh.hostname == "" {
				vh.hostname = d.Args[0]
			}
		case "listen":
			port, ssl := parseListenArgs(d.Args)
			if vh.port == 0 {
				vh.port = port
			}
			if ssl && vh.ssl == nil {
				vh.ssl = &sslConf{}
			}
		}
	}
	if vh.hostname == "" {
		vh.hostname = "default"
	}

	// second pass: remaining directives
	for _, d := range dirs {
		switch d.Directive {
		case "server_name", "listen":
			mc.report.converted++

		case "root":
			if len(d.Args) > 0 {
				vh.root = d.Args[0]
				mc.report.converted++
			}

		case "proxy_pass":
			if len(d.Args) > 0 {
				target := d.Args[0]
				if name := upstreamName(target); name != "" {
					if uDirs, ok := upstreams[name]; ok {
						uc, stubs := convertUpstreamBlock(uDirs)
						vh.upstream = uc
						vh.stubs = append(vh.stubs, stubs...)
						mc.report.converted++
						break
					}
				}
				vh.proxyPass = target
				mc.report.converted++
			}

		case "ssl_certificate":
			if len(d.Args) > 0 {
				if vh.ssl == nil {
					vh.ssl = &sslConf{}
				}
				vh.ssl.cert = d.Args[0]
				mc.report.converted++
			}

		case "ssl_certificate_key":
			if len(d.Args) > 0 {
				if vh.ssl == nil {
					vh.ssl = &sslConf{}
				}
				vh.ssl.key = d.Args[0]
				mc.report.converted++
			}

		case "gzip":
			if len(d.Args) > 0 {
				vh.compression = d.Args[0]
				mc.report.converted++
			}

		case "client_max_body_size":
			if len(d.Args) > 0 {
				vh.maxBodySize = convertBodySize(d.Args[0])
				mc.report.converted++
			}

		default:
			if !silentDirectives[d.Directive] {
				if reason, ok := unsupportedDirectives[d.Directive]; ok {
					mc.addStub(vh, d, reason[0], reason[1])
				}
			}
		}
	}
	return vh
}

// ── Helper functions ──────────────────────────────────────────────────────────

func parseListenArgs(args []string) (port int, ssl bool) {
	if len(args) == 0 {
		return 80, false
	}
	for _, a := range args[1:] {
		if a == "ssl" {
			ssl = true
		}
	}
	addr := args[0]
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		addr = addr[idx+1:]
	}
	// strip trailing square bracket (IPv6: "[::]:443" → "443]")
	addr = strings.TrimRight(addr, "]")
	port, _ = strconv.Atoi(addr)
	if port == 0 {
		port = 80
	}
	return
}

func upstreamName(proxyPass string) string {
	u := strings.TrimPrefix(proxyPass, "http://")
	u = strings.TrimPrefix(u, "https://")
	if !strings.Contains(u, ":") && !strings.Contains(u, "/") && u != "" {
		return u
	}
	return ""
}

func convertBodySize(s string) string {
	if s == "0" {
		return ""
	}
	upper := strings.ToUpper(strings.TrimSpace(s))
	switch {
	case strings.HasSuffix(upper, "G"):
		return strings.TrimSuffix(upper, "G") + "GB"
	case strings.HasSuffix(upper, "M"):
		return strings.TrimSuffix(upper, "M") + "MB"
	case strings.HasSuffix(upper, "K"):
		return strings.TrimSuffix(upper, "K") + "KB"
	default:
		return upper + "B"
	}
}

func directiveToRaw(d crossplane.Directive) string {
	if len(d.Block) == 0 {
		return d.Directive + " " + strings.Join(d.Args, " ") + ";"
	}
	return d.Directive + " " + strings.Join(d.Args, " ") + " { ... }"
}

func (mc *migrateConf) addStub(vh *vhostConf, d crossplane.Directive, reason, anchor string) {
	s := inlineStub{
		tag:    d.Directive,
		raw:    directiveToRaw(d),
		reason: reason,
		anchor: anchor,
	}
	vh.stubs = append(vh.stubs, s)
	mc.report.stubbed++
	mc.report.entries = append(mc.report.entries, reportEntry{
		vhost:     vh.hostname,
		directive: d.Directive,
		line:      d.Line,
		reason:    reason,
	})
}

// placeholder — implemented in later tasks
func parseLimitReqZone(args []string) (string, rateLimitConf, bool) { return "", rateLimitConf{}, false }
func convertUpstreamBlock(dirs crossplane.Directives) (*upstreamConf, []inlineStub) {
	return &upstreamConf{strategy: "round_robin"}, nil
}

// runMigrate is implemented in Task 7
func runMigrate(args []string) {
	fmt.Fprintln(os.Stderr, "migrate: not yet implemented")
	os.Exit(1)
}
```

- [ ] **Step 4: Run the tests**

```bash
go test ./cmd/tinyproxy/... -run "TestConvert|TestParse" -v
```

Expected: `TestConvertServerBlock_Basic` PASS, `TestConvertServerBlock_SSL` PASS, `TestConvertNginxFile_Simple` PASS, `TestParseListenArgs` PASS, `TestConvertBodySize` PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/tinyproxy/migrate.go cmd/tinyproxy/migrate_test.go
git commit -m "feat(migrate): core types and basic server block conversion"
```

---

## Task 4: Security headers, FastCGI, and rate limiting conversion

Converts `add_header` → security headers, `limit_req_zone` + `limit_req` → rate_limit, `fastcgi_*`.

**Files:**
- Modify: `cmd/tinyproxy/migrate.go` — replace placeholder `parseLimitReqZone`, add `convertAddHeader`, add `fastcgi_*` cases to `convertServerBlock`
- Modify: `cmd/tinyproxy/migrate_test.go` — add tests

- [ ] **Step 1: Add tests**

Append to `cmd/tinyproxy/migrate_test.go`:

```go
// Task 4 tests

func TestConvertAddHeader_SecurityHeaders(t *testing.T) {
	dirs := crossplane.Directives{
		{Directive: "server_name", Args: []string{"example.com"}},
		{Directive: "listen", Args: []string{"80"}},
		{Directive: "add_header", Args: []string{"X-Frame-Options", "DENY"}},
		{Directive: "add_header", Args: []string{"X-Content-Type-Options", "nosniff"}},
		{Directive: "add_header", Args: []string{"X-XSS-Protection", "1; mode=block"}},
		{Directive: "add_header", Args: []string{"Content-Security-Policy", "default-src 'self'"}},
		{Directive: "add_header", Args: []string{"Strict-Transport-Security", "max-age=31536000; includeSubDomains"}},
	}
	mc := &migrateConf{report: reportConf{}}
	vh := mc.convertServerBlock(dirs, nil, nil, "")
	if vh.security.frameOptions != "DENY" {
		t.Errorf("frameOptions = %q, want DENY", vh.security.frameOptions)
	}
	if vh.security.contentType != "nosniff" {
		t.Errorf("contentType = %q, want nosniff", vh.security.contentType)
	}
	if vh.security.csp != "default-src 'self'" {
		t.Errorf("csp = %q", vh.security.csp)
	}
}

func TestConvertAddHeader_NonSecurity_Stubbed(t *testing.T) {
	dirs := crossplane.Directives{
		{Directive: "server_name", Args: []string{"example.com"}},
		{Directive: "listen", Args: []string{"80"}},
		{Directive: "add_header", Args: []string{"X-Custom-Header", "value"}},
	}
	mc := &migrateConf{report: reportConf{}}
	vh := mc.convertServerBlock(dirs, nil, nil, "")
	if len(vh.stubs) == 0 {
		t.Error("expected stub for non-security add_header")
	}
	if !strings.Contains(vh.stubs[0].tag, "add_header") {
		t.Errorf("stub tag = %q, want add_header", vh.stubs[0].tag)
	}
}

func TestParseLimitReqZone(t *testing.T) {
	args := []string{"$binary_remote_addr", "zone=api:10m", "rate=100r/m"}
	name, rl, ok := parseLimitReqZone(args)
	if !ok {
		t.Fatal("expected ok")
	}
	if name != "api" {
		t.Errorf("zone name = %q, want api", name)
	}
	if rl.requests != 100 {
		t.Errorf("requests = %d, want 100", rl.requests)
	}
	if rl.window != "1m" {
		t.Errorf("window = %q, want 1m", rl.window)
	}
}

func TestConvertServerBlock_RateLimit(t *testing.T) {
	dirs := crossplane.Directives{
		{Directive: "server_name", Args: []string{"example.com"}},
		{Directive: "listen", Args: []string{"80"}},
		{Directive: "limit_req", Args: []string{"zone=api", "burst=20"}},
	}
	zones := map[string]rateLimitConf{"api": {requests: 100, window: "1m"}}
	mc := &migrateConf{report: reportConf{}}
	vh := mc.convertServerBlock(dirs, nil, zones, "")
	if vh.security.rateReqs != 100 {
		t.Errorf("rateReqs = %d, want 100", vh.security.rateReqs)
	}
	if vh.security.rateWin != "1m" {
		t.Errorf("rateWin = %q, want 1m", vh.security.rateWin)
	}
}

func TestConvertServerBlock_FastCGI(t *testing.T) {
	dirs := crossplane.Directives{
		{Directive: "server_name", Args: []string{"php.example.com"}},
		{Directive: "listen", Args: []string{"80"}},
		{Directive: "root", Args: []string{"/var/www/html"}},
		{Directive: "fastcgi_pass", Args: []string{"127.0.0.1:9000"}},
		{Directive: "fastcgi_index", Args: []string{"index.php"}},
		{Directive: "fastcgi_param", Args: []string{"SCRIPT_FILENAME", "/var/www/html/$fastcgi_script_name"}},
	}
	mc := &migrateConf{report: reportConf{}}
	vh := mc.convertServerBlock(dirs, nil, nil, "")
	if vh.fastcgi == nil {
		t.Fatal("fastcgi is nil")
	}
	if vh.fastcgi.pass != "127.0.0.1:9000" {
		t.Errorf("fastcgi.pass = %q", vh.fastcgi.pass)
	}
	if len(vh.fastcgi.params) != 1 {
		t.Errorf("got %d fastcgi params, want 1", len(vh.fastcgi.params))
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./cmd/tinyproxy/... -run "TestConvertAddHeader|TestParseLimitReq|TestConvertServerBlock_RateLimit|TestConvertServerBlock_FastCGI" -v 2>&1 | head -30
```

Expected: failures — functions not yet complete.

- [ ] **Step 3: Replace the `parseLimitReqZone` placeholder and add `resolveLimitReq` in `migrate.go`**

Replace the placeholder `parseLimitReqZone` function:

```go
func parseLimitReqZone(args []string) (zoneName string, rl rateLimitConf, ok bool) {
	for _, a := range args {
		if strings.HasPrefix(a, "zone=") {
			val := strings.TrimPrefix(a, "zone=")
			parts := strings.SplitN(val, ":", 2)
			zoneName = parts[0]
		}
		if strings.HasPrefix(a, "rate=") {
			val := strings.TrimPrefix(a, "rate=")
			val = strings.ReplaceAll(val, "r/", "")
			if strings.HasSuffix(val, "m") {
				n, err := strconv.Atoi(strings.TrimSuffix(val, "m"))
				if err == nil {
					rl = rateLimitConf{requests: n, window: "1m"}
					ok = true
				}
			} else if strings.HasSuffix(val, "s") {
				n, err := strconv.Atoi(strings.TrimSuffix(val, "s"))
				if err == nil {
					rl = rateLimitConf{requests: n, window: "1s"}
					ok = true
				}
			}
		}
	}
	return
}

func resolveLimitReq(args []string, zones map[string]rateLimitConf) (rateLimitConf, bool) {
	for _, a := range args {
		if strings.HasPrefix(a, "zone=") {
			name := strings.TrimPrefix(a, "zone=")
			if rl, ok := zones[name]; ok {
				return rl, true
			}
		}
	}
	return rateLimitConf{}, false
}
```

- [ ] **Step 4: Add `convertAddHeader` function in `migrate.go`**

```go
func (mc *migrateConf) convertAddHeader(vh *vhostConf, d crossplane.Directive) bool {
	if len(d.Args) < 2 {
		return false
	}
	name := strings.ToLower(d.Args[0])
	val := strings.Trim(strings.Join(d.Args[1:], " "), "\"")
	switch name {
	case "x-frame-options":
		vh.security.frameOptions = val
	case "x-content-type-options":
		vh.security.contentType = val
	case "x-xss-protection":
		vh.security.xssProtection = val
	case "content-security-policy":
		vh.security.csp = val
	case "strict-transport-security":
		vh.security.hsts = val
	default:
		return false
	}
	return true
}
```

- [ ] **Step 5: Add `add_header`, `limit_req`, and `fastcgi_*` cases to `convertServerBlock` in `migrate.go`**

In the `default:` branch of the second-pass switch in `convertServerBlock`, add these cases before the `default:`:

```go
		case "add_header":
			if mc.convertAddHeader(vh, d) {
				mc.report.converted++
			} else {
				mc.addStub(vh, d, "Non-security add_header not supported", "add-header")
			}

		case "limit_req":
			if rateZones != nil {
				if rl, ok := resolveLimitReq(d.Args, rateZones); ok {
					vh.security.rateReqs = rl.requests
					vh.security.rateWin = rl.window
					mc.report.converted++
					break
				}
			}
			mc.addStub(vh, d, "Could not resolve rate limit zone", "rate-limiting")

		case "fastcgi_pass":
			if len(d.Args) > 0 {
				if vh.fastcgi == nil {
					vh.fastcgi = &fastcgiConf{}
				}
				vh.fastcgi.pass = d.Args[0]
				mc.report.converted++
			}

		case "fastcgi_index":
			if len(d.Args) > 0 {
				if vh.fastcgi == nil {
					vh.fastcgi = &fastcgiConf{}
				}
				vh.fastcgi.index = d.Args[0]
				mc.report.converted++
			}

		case "fastcgi_param":
			if len(d.Args) >= 2 {
				if vh.fastcgi == nil {
					vh.fastcgi = &fastcgiConf{params: []string{}}
				}
				vh.fastcgi.params = append(vh.fastcgi.params, d.Args[0]+" "+d.Args[1])
				mc.report.converted++
			}
```

- [ ] **Step 6: Run all tests**

```bash
go test ./cmd/tinyproxy/... -v
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add cmd/tinyproxy/migrate.go cmd/tinyproxy/migrate_test.go
git commit -m "feat(migrate): add security header, FastCGI, and rate limit conversion"
```

---

## Task 5: Upstream / load balancer conversion

Converts `upstream {}` blocks into tinyproxy `upstream { backend … }` config, with `ip_hash`/`least_conn` strategy mapping and stubs for unsupported directives (`keepalive`, `backup`).

**Files:**
- Modify: `cmd/tinyproxy/migrate.go` — replace `convertUpstreamBlock` placeholder
- Modify: `cmd/tinyproxy/migrate_test.go` — add tests

- [ ] **Step 1: Add tests**

Append to `cmd/tinyproxy/migrate_test.go`:

```go
// Task 5 tests

func TestConvertUpstreamBlock_RoundRobin(t *testing.T) {
	dirs := crossplane.Directives{
		{Directive: "server", Args: []string{"10.0.0.1:8080", "weight=3"}},
		{Directive: "server", Args: []string{"10.0.0.2:8080"}},
	}
	uc, stubs := convertUpstreamBlock(dirs)
	if uc.strategy != "round_robin" {
		t.Errorf("strategy = %q, want round_robin", uc.strategy)
	}
	if len(uc.backends) != 2 {
		t.Fatalf("got %d backends, want 2", len(uc.backends))
	}
	if uc.backends[0] != "http://10.0.0.1:8080 weight 3" {
		t.Errorf("backend[0] = %q", uc.backends[0])
	}
	if uc.backends[1] != "http://10.0.0.2:8080" {
		t.Errorf("backend[1] = %q", uc.backends[1])
	}
	if len(stubs) != 0 {
		t.Errorf("unexpected stubs: %v", stubs)
	}
}

func TestConvertUpstreamBlock_IpHash(t *testing.T) {
	dirs := crossplane.Directives{
		{Directive: "ip_hash"},
		{Directive: "server", Args: []string{"10.0.0.1:8080"}},
	}
	uc, _ := convertUpstreamBlock(dirs)
	if uc.strategy != "ip_hash" {
		t.Errorf("strategy = %q, want ip_hash", uc.strategy)
	}
}

func TestConvertUpstreamBlock_KeepaliveStubbed(t *testing.T) {
	dirs := crossplane.Directives{
		{Directive: "server", Args: []string{"10.0.0.1:8080"}},
		{Directive: "keepalive", Args: []string{"32"}},
	}
	_, stubs := convertUpstreamBlock(dirs)
	if len(stubs) != 1 {
		t.Fatalf("got %d stubs, want 1", len(stubs))
	}
	if stubs[0].tag != "keepalive" {
		t.Errorf("stub tag = %q, want keepalive", stubs[0].tag)
	}
}

func TestUpstreamName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://myapp", "myapp"},
		{"http://myapp:8080", ""},
		{"http://backend/api", ""},
		{"https://myapp", "myapp"},
	}
	for _, c := range cases {
		if got := upstreamName(c.in); got != c.want {
			t.Errorf("upstreamName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./cmd/tinyproxy/... -run "TestConvertUpstream|TestUpstreamName" -v 2>&1 | head -20
```

Expected: FAIL — `convertUpstreamBlock` returns empty struct.

- [ ] **Step 3: Replace `convertUpstreamBlock` placeholder in `migrate.go`**

```go
func convertUpstreamBlock(dirs crossplane.Directives) (*upstreamConf, []inlineStub) {
	uc := &upstreamConf{strategy: "round_robin"}
	var stubs []inlineStub

	for _, d := range dirs {
		switch d.Directive {
		case "server":
			if len(d.Args) == 0 {
				continue
			}
			addr := d.Args[0]
			if !strings.Contains(addr, "://") {
				addr = "http://" + addr
			}
			backend := addr
			for i := 1; i < len(d.Args); i++ {
				if strings.HasPrefix(d.Args[i], "weight=") {
					w := strings.TrimPrefix(d.Args[i], "weight=")
					backend += " weight " + w
				}
				// skip "backup", "down", "fail_timeout=", "max_fails="
			}
			uc.backends = append(uc.backends, backend)

		case "ip_hash":
			uc.strategy = "ip_hash"
		case "least_conn":
			uc.strategy = "least_conn"
		case "random":
			uc.strategy = "round_robin"

		case "keepalive", "keepalive_requests", "keepalive_time":
			stubs = append(stubs, inlineStub{
				tag:    d.Directive,
				raw:    directiveToRaw(d),
				reason: "Upstream keepalive not configurable in tinyproxy",
				anchor: "upstream-keepalive",
			})

		default:
			if reason, ok := unsupportedDirectives[d.Directive]; ok {
				stubs = append(stubs, inlineStub{
					tag:    d.Directive,
					raw:    directiveToRaw(d),
					reason: reason[0],
					anchor: reason[1],
				})
			}
		}
	}
	return uc, stubs
}
```

- [ ] **Step 4: Run all tests**

```bash
go test ./cmd/tinyproxy/... -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/tinyproxy/migrate.go cmd/tinyproxy/migrate_test.go
git commit -m "feat(migrate): upstream/load balancer block conversion"
```

---

## Task 6: Output rendering — vhosts.conf text + migration report

Converts the in-memory `migrateConf` into the two output files.

**Files:**
- Modify: `cmd/tinyproxy/migrate.go` — add `renderVhostConf` and `renderReport`
- Modify: `cmd/tinyproxy/migrate_test.go` — add render tests

- [ ] **Step 1: Add tests**

Append to `cmd/tinyproxy/migrate_test.go`:

```go
// Task 6 tests

func TestRenderVhostConf_Basic(t *testing.T) {
	mc := &migrateConf{
		vhosts: []*vhostConf{
			{
				hostname:    "example.com",
				port:        80,
				root:        "/var/www/html",
				compression: "on",
			},
		},
	}
	out := renderVhostConf(mc)
	if !strings.Contains(out, "example.com {") {
		t.Errorf("missing vhost block:\n%s", out)
	}
	if !strings.Contains(out, "port 80") {
		t.Errorf("missing port:\n%s", out)
	}
	if !strings.Contains(out, "root /var/www/html") {
		t.Errorf("missing root:\n%s", out)
	}
	if !strings.Contains(out, "compression on") {
		t.Errorf("missing compression:\n%s", out)
	}
}

func TestRenderVhostConf_InlineStubs(t *testing.T) {
	mc := &migrateConf{
		vhosts: []*vhostConf{
			{
				hostname: "example.com",
				port:     80,
				stubs: []inlineStub{
					{tag: "location", raw: "location / { ... }", reason: "No URL routing", anchor: "url-routing"},
				},
			},
		},
	}
	out := renderVhostConf(mc)
	if !strings.Contains(out, "# UNSUPPORTED[location]") {
		t.Errorf("missing stub comment:\n%s", out)
	}
	if !strings.Contains(out, "nginx-gap-analysis#url-routing") {
		t.Errorf("missing doc link in stub:\n%s", out)
	}
}

func TestRenderVhostConf_SSL(t *testing.T) {
	mc := &migrateConf{
		vhosts: []*vhostConf{
			{
				hostname: "example.com",
				port:     443,
				ssl:      &sslConf{cert: "/etc/ssl/cert.pem", key: "/etc/ssl/key.pem"},
			},
		},
	}
	out := renderVhostConf(mc)
	if !strings.Contains(out, "ssl {") {
		t.Errorf("missing ssl block:\n%s", out)
	}
	if !strings.Contains(out, "cert /etc/ssl/cert.pem") {
		t.Errorf("missing cert:\n%s", out)
	}
}

func TestRenderReport_Counts(t *testing.T) {
	mc := &migrateConf{
		report: reportConf{
			source:    "/etc/nginx/nginx.conf",
			generated: time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC),
			converted: 10,
			stubbed:   3,
			entries: []reportEntry{
				{vhost: "example.com", directive: "location", file: "nginx.conf", line: 42, reason: "No URL routing"},
			},
		},
	}
	rpt := renderReport(mc)
	if !strings.Contains(rpt, "Directives converted: 10") {
		t.Errorf("missing converted count:\n%s", rpt)
	}
	if !strings.Contains(rpt, "example.com") {
		t.Errorf("missing vhost in report:\n%s", rpt)
	}
	if !strings.Contains(rpt, "location") {
		t.Errorf("missing directive in report:\n%s", rpt)
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./cmd/tinyproxy/... -run "TestRender" -v 2>&1 | head -20
```

Expected: compilation error — `renderVhostConf` and `renderReport` not yet defined.

- [ ] **Step 3: Add `renderVhostConf` and `renderReport` to `migrate.go`**

```go
const docsBase = "https://tinyproxy.io/docs/migration/nginx-gap-analysis"

func renderVhostConf(mc *migrateConf) string {
	var sb strings.Builder
	sb.WriteString("vhosts {\n")
	for _, vh := range mc.vhosts {
		sb.WriteString("    " + vh.hostname + " {\n")

		if vh.port != 0 {
			fmt.Fprintf(&sb, "        port %d\n", vh.port)
		}
		if vh.root != "" {
			fmt.Fprintf(&sb, "        root %s\n", vh.root)
		}
		if vh.proxyPass != "" {
			fmt.Fprintf(&sb, "        proxy_pass %s\n", vh.proxyPass)
		}
		if vh.compression != "" {
			fmt.Fprintf(&sb, "        compression %s\n", vh.compression)
		}
		if vh.maxBodySize != "" {
			fmt.Fprintf(&sb, "        max_body_size %s\n", vh.maxBodySize)
		}

		if vh.ssl != nil && (vh.ssl.cert != "" || vh.ssl.key != "") {
			sb.WriteString("        ssl {\n")
			if vh.ssl.cert != "" {
				fmt.Fprintf(&sb, "            cert %s\n", vh.ssl.cert)
			}
			if vh.ssl.key != "" {
				fmt.Fprintf(&sb, "            key %s\n", vh.ssl.key)
			}
			sb.WriteString("        }\n")
		}

		if vh.security != (secConf{}) {
			sb.WriteString("        security {\n")
			if vh.security.frameOptions != "" {
				fmt.Fprintf(&sb, "            frame_options %s\n", vh.security.frameOptions)
			}
			if vh.security.contentType != "" {
				fmt.Fprintf(&sb, "            content_type %s\n", vh.security.contentType)
			}
			if vh.security.xssProtection != "" {
				fmt.Fprintf(&sb, "            xss_protection %q\n", vh.security.xssProtection)
			}
			if vh.security.csp != "" {
				fmt.Fprintf(&sb, "            csp %q\n", vh.security.csp)
			}
			if vh.security.hsts != "" {
				fmt.Fprintf(&sb, "            hsts %q\n", vh.security.hsts)
			}
			if vh.security.rateReqs > 0 {
				sb.WriteString("            rate_limit {\n")
				fmt.Fprintf(&sb, "                requests %d\n", vh.security.rateReqs)
				fmt.Fprintf(&sb, "                window %s\n", vh.security.rateWin)
				sb.WriteString("            }\n")
			}
			sb.WriteString("        }\n")
		}

		if vh.fastcgi != nil {
			sb.WriteString("        fastcgi {\n")
			if vh.fastcgi.pass != "" {
				fmt.Fprintf(&sb, "            pass %s\n", vh.fastcgi.pass)
			}
			if vh.fastcgi.index != "" {
				fmt.Fprintf(&sb, "            index %s\n", vh.fastcgi.index)
			}
			for _, p := range vh.fastcgi.params {
				fmt.Fprintf(&sb, "            param %s\n", p)
			}
			sb.WriteString("        }\n")
		}

		if vh.upstream != nil {
			sb.WriteString("        upstream {\n")
			fmt.Fprintf(&sb, "            strategy %s\n", vh.upstream.strategy)
			for _, b := range vh.upstream.backends {
				fmt.Fprintf(&sb, "            backend %s\n", b)
			}
			for _, s := range vh.upstream.stubs {
				fmt.Fprintf(&sb, "            # UNSUPPORTED[%s]: %s\n", s.tag, s.raw)
				fmt.Fprintf(&sb, "            # → %s\n", s.reason)
				fmt.Fprintf(&sb, "            # → See: %s#%s\n", docsBase, s.anchor)
				sb.WriteString("\n")
			}
			sb.WriteString("        }\n")
		}

		for _, s := range vh.stubs {
			sb.WriteString("\n")
			fmt.Fprintf(&sb, "        # UNSUPPORTED[%s]: %s\n", s.tag, s.raw)
			fmt.Fprintf(&sb, "        # → %s\n", s.reason)
			fmt.Fprintf(&sb, "        # → See: %s#%s\n", docsBase, s.anchor)
		}

		sb.WriteString("    }\n")
	}
	sb.WriteString("}\n")
	return sb.String()
}

func renderReport(mc *migrateConf) string {
	var sb strings.Builder
	r := mc.report
	fmt.Fprintf(&sb, "# Migration Report — nginx → tinyproxy\n\n")
	fmt.Fprintf(&sb, "Generated: %s\n\n", r.generated.UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&sb, "## Summary\n\n")
	fmt.Fprintf(&sb, "| | |\n|---|---|\n")
	fmt.Fprintf(&sb, "| Source | `%s` |\n", r.source)
	fmt.Fprintf(&sb, "| Virtual hosts converted | %d |\n", len(mc.vhosts))
	fmt.Fprintf(&sb, "| Directives converted | %d |\n", r.converted)
	fmt.Fprintf(&sb, "| Directives stubbed (unsupported) | %d |\n\n", r.stubbed)

	if len(r.entries) > 0 {
		fmt.Fprintf(&sb, "## Unsupported Directives\n\n")
		fmt.Fprintf(&sb, "| Virtual Host | Directive | File | Line | Reason |\n")
		fmt.Fprintf(&sb, "|---|---|---|---|---|\n")
		for _, e := range r.entries {
			fmt.Fprintf(&sb, "| %s | `%s` | %s | %d | %s |\n",
				e.vhost, e.directive, e.file, e.line, e.reason)
		}
		fmt.Fprintf(&sb, "\n")
	}

	fmt.Fprintf(&sb, "## Next Steps\n\n")
	fmt.Fprintf(&sb, "1. Review `# UNSUPPORTED` stubs in the generated `vhosts.conf`\n")
	fmt.Fprintf(&sb, "2. See [Gap Analysis & Roadmap](%s) for implementation plans\n", docsBase)
	fmt.Fprintf(&sb, "3. Test your config: `ENV=dev go run ./cmd/tinyproxy/`\n")
	return sb.String()
}
```

- [ ] **Step 4: Run all tests**

```bash
go test ./cmd/tinyproxy/... -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/tinyproxy/migrate.go cmd/tinyproxy/migrate_test.go
git commit -m "feat(migrate): output rendering for vhosts.conf and migration report"
```

---

## Task 7: CLI entry point and wire into `main.go`

**Files:**
- Modify: `cmd/tinyproxy/migrate.go` — replace `runMigrate` placeholder with real implementation
- Modify: `cmd/tinyproxy/main.go` — add `case "migrate":` to switch, update usage

- [ ] **Step 1: Replace `runMigrate` in `migrate.go`**

Replace the placeholder `runMigrate` function:

```go
func runMigrate(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	output := fs.String("output", "vhosts.conf", "write converted config to this file")
	report := fs.String("report", "migration-report.md", "write migration report to this file")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: tinyproxy migrate <nginx.conf> [--output vhosts.conf] [--report migration-report.md]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	filename := fs.Arg(0)
	mc, err := convertNginxFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		os.Exit(1)
	}

	conf := renderVhostConf(mc)
	if err := os.WriteFile(*output, []byte(conf), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: write %s: %v\n", *output, err)
		os.Exit(1)
	}

	rpt := renderReport(mc)
	if err := os.WriteFile(*report, []byte(rpt), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: write %s: %v\n", *report, err)
		os.Exit(1)
	}

	fmt.Printf("Converted %d vhost(s), %d directive(s) migrated, %d stubbed.\n",
		len(mc.vhosts), mc.report.converted, mc.report.stubbed)
	fmt.Printf("Config written to: %s\n", *output)
	fmt.Printf("Report written to: %s\n", *report)

	if mc.report.stubbed > 0 {
		fmt.Printf("\nReview %d unsupported directive(s) — see %s\n", mc.report.stubbed, docsBase)
	}
}
```

- [ ] **Step 2: Wire `migrate` into `main.go`**

In `cmd/tinyproxy/main.go`, in the `switch cmd` block, add after `case "ssl":`:

```go
	case "migrate":
		runMigrate(os.Args[2:])
```

Also update the default usage string on the line:
```go
		fmt.Fprintf(os.Stderr, "Usage: go-tinyproxy {serve|start|stop|restart|reload|status|config|logs|upgrade|ssl|dashboard|migrate}\n")
```

- [ ] **Step 3: Build and smoke-test**

```bash
go build -o /tmp/tinyproxy ./cmd/tinyproxy/
```

Create a minimal test config at `/tmp/test-nginx.conf`:

```nginx
http {
    server {
        server_name example.com;
        listen 80;
        root /var/www/html;

        location / {
            try_files $uri $uri/ =404;
        }
    }
}
```

Run:
```bash
/tmp/tinyproxy migrate /tmp/test-nginx.conf --output /tmp/out.conf --report /tmp/report.md
cat /tmp/out.conf
cat /tmp/report.md
```

Expected output:
```
Converted 1 vhost(s), 3 directive(s) migrated, 2 stubbed.
Config written to: /tmp/out.conf
Report written to: /tmp/report.md

Review 2 unsupported directive(s) — see https://tinyproxy.io/docs/migration/nginx-gap-analysis
```

`/tmp/out.conf` should contain `example.com {`, `port 80`, `root /var/www/html`, and `# UNSUPPORTED[location]` and `# UNSUPPORTED[try_files]` stubs.

- [ ] **Step 4: Run all tests**

```bash
go test ./... -v 2>&1 | tail -20
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/tinyproxy/migrate.go cmd/tinyproxy/main.go
git commit -m "feat(migrate): wire migrate subcommand into CLI"
```

---

## Task 8: Python standalone script

**Files:**
- Create: `tools/nginx-migrate.py`

- [ ] **Step 1: Create `tools/nginx-migrate.py`**

```python
#!/usr/bin/env python3
"""nginx → tinyproxy config converter (standalone, no tinyproxy install required).

Usage:
    pip install crossplane
    python nginx-migrate.py nginx.conf [--output vhosts.conf] [--report migration-report.md]
"""

import argparse
import sys
import os
from datetime import datetime, timezone

try:
    import crossplane
except ImportError:
    print("error: crossplane not installed. Run: pip install crossplane", file=sys.stderr)
    sys.exit(1)

DOCS_BASE = "https://tinyproxy.io/docs/migration/nginx-gap-analysis"

UNSUPPORTED = {
    "location":              ("No URL routing in tinyproxy", "url-routing"),
    "rewrite":               ("URL rewriting not supported", "rewrites"),
    "map":                   ("map directive not supported", "map"),
    "if":                    ("if blocks not supported", "conditionals"),
    "try_files":             ("try_files not supported", "try-files"),
    "return":                ("Redirects (return) not supported", "redirects"),
    "error_page":            ("Custom error pages not supported", "error-pages"),
    "auth_basic":            ("HTTP basic auth not supported", "auth-basic"),
    "auth_basic_user_file":  ("HTTP basic auth not supported", "auth-basic"),
    "auth_request":          ("auth_request not supported", "auth-request"),
    "limit_conn":            ("Connection limiting not supported", "limit-conn"),
    "limit_conn_zone":       ("Connection limiting not supported", "limit-conn"),
    "proxy_set_header":      ("Request header manipulation not supported", "proxy-set-header"),
    "proxy_hide_header":     ("Response header manipulation not supported", "proxy-set-header"),
    "proxy_read_timeout":    ("Upstream timeouts not supported", "timeouts"),
    "proxy_send_timeout":    ("Upstream timeouts not supported", "timeouts"),
    "proxy_connect_timeout": ("Upstream timeouts not supported", "timeouts"),
    "access_log":            ("Per-vhost logging config not supported", "logging"),
    "error_log":             ("Per-vhost logging config not supported", "logging"),
    "geo":                   ("geo module not supported", "geo"),
    "sub_filter":            ("sub_filter not supported", "sub-filter"),
    "mirror":                ("mirror not supported", "mirror"),
    "stream":                ("stream blocks not supported", "stream"),
    "mail":                  ("mail blocks not supported", "mail"),
    "health_check":          ("nginx Plus active health_check not supported", "health-check-plus"),
    "auth_jwt":              ("nginx Plus JWT auth not supported", "jwt"),
    "js_include":            ("njs not supported", "njs"),
    "js_content":            ("njs not supported", "njs"),
}

SILENT = {
    "server_name", "listen", "tcp_nopush", "tcp_nodelay", "keepalive_timeout",
    "sendfile", "types", "include", "default_type", "worker_processes",
    "worker_connections", "events", "pid", "user", "proxy_buffering",
    "proxy_buffer_size", "proxy_buffers",
}

SECURITY_HEADERS = {
    "x-frame-options":         "frame_options",
    "x-content-type-options":  "content_type",
    "x-xss-protection":        "xss_protection",
    "content-security-policy": "csp",
    "strict-transport-security": "hsts",
}


def parse_listen_args(args):
    port, ssl = 80, False
    if not args:
        return port, ssl
    for a in args[1:]:
        if a == "ssl":
            ssl = True
    addr = args[0]
    if ":" in addr:
        addr = addr.rsplit(":", 1)[-1].rstrip("]")
    try:
        port = int(addr)
    except ValueError:
        port = 80
    return port, ssl


def upstream_name(proxy_pass):
    u = proxy_pass
    for prefix in ("http://", "https://"):
        if u.startswith(prefix):
            u = u[len(prefix):]
            break
    if ":" not in u and "/" not in u and u:
        return u
    return ""


def convert_body_size(s):
    if s == "0":
        return ""
    u = s.upper().strip()
    if u.endswith("G"):
        return u[:-1] + "GB"
    if u.endswith("M"):
        return u[:-1] + "MB"
    if u.endswith("K"):
        return u[:-1] + "KB"
    return u + "B"


def parse_limit_req_zone(args):
    zone_name, requests, window = None, None, None
    for a in args:
        if a.startswith("zone="):
            zone_name = a[5:].split(":")[0]
        if a.startswith("rate="):
            val = a[5:].replace("r/", "")
            if val.endswith("m"):
                requests, window = int(val[:-1]), "1m"
            elif val.endswith("s"):
                requests, window = int(val[:-1]), "1s"
    if zone_name and requests is not None:
        return zone_name, {"requests": requests, "window": window}
    return None, None


def resolve_limit_req(args, zones):
    for a in args:
        if a.startswith("zone="):
            name = a[5:]
            if name in zones:
                return zones[name]
    return None


def directive_to_raw(d):
    args_str = " ".join(d.get("args", []))
    if d.get("block") is not None:
        return f"{d['directive']} {args_str} {{ ... }}"
    return f"{d['directive']} {args_str};"


def convert_upstream_block(block):
    uc = {"strategy": "round_robin", "backends": [], "stubs": []}
    for d in block:
        name = d["directive"]
        args = d.get("args", [])
        if name == "server" and args:
            addr = args[0]
            if "://" not in addr:
                addr = "http://" + addr
            backend = addr
            for a in args[1:]:
                if a.startswith("weight="):
                    backend += " weight " + a[7:]
            uc["backends"].append(backend)
        elif name in ("ip_hash",):
            uc["strategy"] = "ip_hash"
        elif name in ("least_conn",):
            uc["strategy"] = "least_conn"
        elif name in ("keepalive", "keepalive_requests", "keepalive_time"):
            uc["stubs"].append({
                "tag": name, "raw": directive_to_raw(d),
                "reason": "Upstream keepalive not configurable in tinyproxy",
                "anchor": "upstream-keepalive",
            })
        elif name in UNSUPPORTED:
            reason, anchor = UNSUPPORTED[name]
            uc["stubs"].append({"tag": name, "raw": directive_to_raw(d), "reason": reason, "anchor": anchor})
    return uc


def convert_server_block(block, upstreams, rate_zones, http_gzip, report):
    vh = {
        "hostname": "default", "port": 0, "root": "", "proxy_pass": "",
        "ssl": None, "compression": http_gzip, "security": {},
        "fastcgi": None, "upstream": None, "max_body_size": "",
        "stubs": [],
    }

    def add_stub(d, reason, anchor):
        vh["stubs"].append({"tag": d["directive"], "raw": directive_to_raw(d), "reason": reason, "anchor": anchor})
        report["stubbed"] += 1
        report["entries"].append({
            "vhost": vh["hostname"], "directive": d["directive"],
            "file": d.get("file", ""), "line": d.get("line", 0), "reason": reason,
        })

    # first pass: server_name + listen
    for d in block:
        n, args = d["directive"], d.get("args", [])
        if n == "server_name" and args and vh["hostname"] == "default":
            vh["hostname"] = args[0]
        elif n == "listen":
            port, ssl = parse_listen_args(args)
            if vh["port"] == 0:
                vh["port"] = port
            if ssl and vh["ssl"] is None:
                vh["ssl"] = {"cert": "", "key": ""}

    # second pass
    for d in block:
        n, args = d["directive"], d.get("args", [])
        if n in ("server_name", "listen"):
            report["converted"] += 1
        elif n == "root" and args:
            vh["root"] = args[0]
            report["converted"] += 1
        elif n == "proxy_pass" and args:
            target = args[0]
            name = upstream_name(target)
            if name and name in upstreams:
                vh["upstream"] = convert_upstream_block(upstreams[name])
                vh["stubs"].extend(vh["upstream"].pop("stubs", []))
            else:
                vh["proxy_pass"] = target
            report["converted"] += 1
        elif n == "ssl_certificate" and args:
            if vh["ssl"] is None:
                vh["ssl"] = {"cert": "", "key": ""}
            vh["ssl"]["cert"] = args[0]
            report["converted"] += 1
        elif n == "ssl_certificate_key" and args:
            if vh["ssl"] is None:
                vh["ssl"] = {"cert": "", "key": ""}
            vh["ssl"]["key"] = args[0]
            report["converted"] += 1
        elif n == "gzip" and args:
            vh["compression"] = args[0]
            report["converted"] += 1
        elif n == "client_max_body_size" and args:
            vh["max_body_size"] = convert_body_size(args[0])
            report["converted"] += 1
        elif n == "add_header" and len(args) >= 2:
            hdr = args[0].lower()
            val = " ".join(args[1:]).strip('"')
            if hdr in SECURITY_HEADERS:
                vh["security"][SECURITY_HEADERS[hdr]] = val
                report["converted"] += 1
            else:
                add_stub(d, "Non-security add_header not supported", "add-header")
        elif n == "limit_req":
            rl = resolve_limit_req(args, rate_zones)
            if rl:
                vh["security"]["rate_requests"] = rl["requests"]
                vh["security"]["rate_window"] = rl["window"]
                report["converted"] += 1
            else:
                add_stub(d, "Could not resolve rate limit zone", "rate-limiting")
        elif n == "fastcgi_pass" and args:
            vh.setdefault("fastcgi", {"pass": "", "index": "", "params": []})
            if vh["fastcgi"] is None:
                vh["fastcgi"] = {"pass": "", "index": "", "params": []}
            vh["fastcgi"]["pass"] = args[0]
            report["converted"] += 1
        elif n == "fastcgi_index" and args:
            if vh["fastcgi"] is None:
                vh["fastcgi"] = {"pass": "", "index": "", "params": []}
            vh["fastcgi"]["index"] = args[0]
            report["converted"] += 1
        elif n == "fastcgi_param" and len(args) >= 2:
            if vh["fastcgi"] is None:
                vh["fastcgi"] = {"pass": "", "index": "", "params": []}
            vh["fastcgi"]["params"].append(f"{args[0]} {args[1]}")
            report["converted"] += 1
        elif n not in SILENT:
            if n in UNSUPPORTED:
                reason, anchor = UNSUPPORTED[n]
                add_stub(d, reason, anchor)

    return vh


def convert_nginx_file(filename):
    try:
        payload = crossplane.parse(filename, combine=True)
    except Exception as e:
        raise RuntimeError(f"parse error: {e}")

    if not payload.get("config"):
        raise RuntimeError(f"no config found in {filename}")

    report = {
        "source": filename,
        "generated": datetime.now(timezone.utc),
        "converted": 0,
        "stubbed": 0,
        "entries": [],
    }
    vhosts = []
    parsed = payload["config"][0].get("parsed", [])

    upstreams = {}
    rate_zones = {}
    http_gzip = ""
    http_block = []

    for d in parsed:
        if d["directive"] == "http":
            http_block = d.get("block", [])

    for d in http_block:
        n = d["directive"]
        if n == "upstream" and d.get("args"):
            upstreams[d["args"][0]] = d.get("block", [])
        elif n == "limit_req_zone":
            name, rl = parse_limit_req_zone(d.get("args", []))
            if name:
                rate_zones[name] = rl
        elif n == "gzip" and d.get("args"):
            http_gzip = d["args"][0]

    for d in http_block:
        if d["directive"] == "server":
            vh = convert_server_block(d.get("block", []), upstreams, rate_zones, http_gzip, report)
            vhosts.append(vh)

    return vhosts, report


def render_vhost_conf(vhosts):
    lines = ["vhosts {"]
    for vh in vhosts:
        lines.append(f"    {vh['hostname']} {{")
        if vh["port"]:
            lines.append(f"        port {vh['port']}")
        if vh["root"]:
            lines.append(f"        root {vh['root']}")
        if vh["proxy_pass"]:
            lines.append(f"        proxy_pass {vh['proxy_pass']}")
        if vh["compression"]:
            lines.append(f"        compression {vh['compression']}")
        if vh["max_body_size"]:
            lines.append(f"        max_body_size {vh['max_body_size']}")
        if vh["ssl"] and (vh["ssl"]["cert"] or vh["ssl"]["key"]):
            lines.append("        ssl {")
            if vh["ssl"]["cert"]:
                lines.append(f"            cert {vh['ssl']['cert']}")
            if vh["ssl"]["key"]:
                lines.append(f"            key {vh['ssl']['key']}")
            lines.append("        }")
        sec = vh.get("security", {})
        if sec:
            lines.append("        security {")
            for k, v in [
                ("frame_options", sec.get("frame_options")),
                ("content_type", sec.get("content_type")),
            ]:
                if v:
                    lines.append(f"            {k} {v}")
            for k, v in [
                ("xss_protection", sec.get("xss_protection")),
                ("csp", sec.get("csp")),
                ("hsts", sec.get("hsts")),
            ]:
                if v:
                    lines.append(f'            {k} "{v}"')
            if sec.get("rate_requests"):
                lines.append("            rate_limit {")
                lines.append(f"                requests {sec['rate_requests']}")
                lines.append(f"                window {sec['rate_window']}")
                lines.append("            }")
            lines.append("        }")
        fc = vh.get("fastcgi")
        if fc:
            lines.append("        fastcgi {")
            if fc["pass"]:
                lines.append(f"            pass {fc['pass']}")
            if fc["index"]:
                lines.append(f"            index {fc['index']}")
            for p in fc["params"]:
                lines.append(f"            param {p}")
            lines.append("        }")
        uc = vh.get("upstream")
        if uc:
            lines.append("        upstream {")
            lines.append(f"            strategy {uc['strategy']}")
            for b in uc["backends"]:
                lines.append(f"            backend {b}")
            lines.append("        }")
        for s in vh.get("stubs", []):
            lines.append("")
            lines.append(f"        # UNSUPPORTED[{s['tag']}]: {s['raw']}")
            lines.append(f"        # → {s['reason']}")
            lines.append(f"        # → See: {DOCS_BASE}#{s['anchor']}")
        lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_report(vhosts, report):
    lines = [
        "# Migration Report — nginx → tinyproxy",
        "",
        f"Generated: {report['generated'].strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Summary",
        "",
        "| | |",
        "|---|---|",
        f"| Source | `{report['source']}` |",
        f"| Virtual hosts converted | {len(vhosts)} |",
        f"| Directives converted | {report['converted']} |",
        f"| Directives stubbed (unsupported) | {report['stubbed']} |",
        "",
    ]
    if report["entries"]:
        lines += [
            "## Unsupported Directives",
            "",
            "| Virtual Host | Directive | File | Line | Reason |",
            "|---|---|---|---|---|",
        ]
        for e in report["entries"]:
            lines.append(f"| {e['vhost']} | `{e['directive']}` | {e['file']} | {e['line']} | {e['reason']} |")
        lines.append("")
    lines += [
        "## Next Steps",
        "",
        "1. Review `# UNSUPPORTED` stubs in the generated `vhosts.conf`",
        f"2. See [Gap Analysis & Roadmap]({DOCS_BASE}) for implementation plans",
        "3. Test your config: `ENV=dev go run ./cmd/tinyproxy/`",
    ]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Convert nginx config to tinyproxy vhosts.conf",
        epilog=f"Requires: pip install crossplane",
    )
    parser.add_argument("nginx_conf", help="Path to nginx.conf")
    parser.add_argument("--output", default="vhosts.conf", help="Output vhosts.conf path (default: vhosts.conf)")
    parser.add_argument("--report", default="migration-report.md", help="Output report path (default: migration-report.md)")
    args = parser.parse_args()

    try:
        vhosts, report = convert_nginx_file(args.nginx_conf)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    conf = render_vhost_conf(vhosts)
    with open(args.output, "w") as f:
        f.write(conf)

    rpt = render_report(vhosts, report)
    with open(args.report, "w") as f:
        f.write(rpt)

    print(f"Converted {len(vhosts)} vhost(s), {report['converted']} directive(s) migrated, {report['stubbed']} stubbed.")
    print(f"Config written to: {args.output}")
    print(f"Report written to: {args.report}")
    if report["stubbed"] > 0:
        print(f"\nReview {report['stubbed']} unsupported directive(s) — see {DOCS_BASE}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Smoke-test the Python script**

```bash
pip install crossplane --quiet
python tools/nginx-migrate.py /tmp/test-nginx.conf --output /tmp/py-out.conf --report /tmp/py-report.md
cat /tmp/py-out.conf
```

Expected: same output format as the Go CLI — `example.com {`, `port 80`, `# UNSUPPORTED[location]`.

- [ ] **Step 3: Commit**

```bash
git add tools/nginx-migrate.py
git commit -m "feat(migrate): Python standalone nginx converter script"
```

---

## Task 9: Docusaurus migration docs and sidebar

**Files:**
- Create: `website/docs/migration/nginx.md`
- Create: `website/docs/migration/nginx-directive-map.md`
- Create: `website/docs/migration/nginx-gap-analysis.md`
- Modify: `website/sidebars.js`

- [ ] **Step 1: Add Migration category to `website/sidebars.js`**

In `website/sidebars.js`, add the Migration category after the Features category. The full updated file:

```js
// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  tutorialSidebar: [
    'intro',
    {
      type: 'category',
      label: 'Getting Started',
      items: [
        'getting-started/installation',
        'getting-started/quick-start',
        'getting-started/docker',
      ],
    },
    {
      type: 'category',
      label: 'Configuration',
      items: ['configuration/vhosts'],
    },
    {
      type: 'category',
      label: 'Features',
      items: [
        'features/automatic-tls',
        'features/bot-protection',
        'features/dashboard',
        'features/security',
      ],
    },
    {
      type: 'category',
      label: 'Migration',
      items: [
        'migration/nginx',
        'migration/nginx-directive-map',
        'migration/nginx-gap-analysis',
      ],
    },
    'deployment',
    'development',
  ],
};

export default sidebars;
```

- [ ] **Step 2: Create `website/docs/migration/nginx.md`**

```markdown
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
```

- [ ] **Step 3: Create `website/docs/migration/nginx-directive-map.md`**

```markdown
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
```

- [ ] **Step 4: Create `website/docs/migration/nginx-gap-analysis.md`**

```markdown
---
sidebar_position: 3
---

# Gap Analysis & Roadmap

This page documents nginx features that tinyproxy does not yet support, grouped by implementation priority. Each item includes a brief rationale for why it blocks real-world migrations.

Directives in this list are emitted as `# UNSUPPORTED` stubs by the migration tool so you know exactly what to revisit when support is added.

---

## P1 — Blocks majority of real-world migrations {#url-routing}

### URL Routing (`location` blocks) {#url-routing}

**nginx:**
```nginx
location /api/ {
    proxy_pass http://api-backend:3000;
}
location / {
    root /var/www/html;
    try_files $uri $uri/ =404;
}
```

**Status:** Not supported. tinyproxy operates at the virtual host level — all requests for a vhost go to the same backend or root. Every nginx config that splits traffic by path requires `location` blocks.

**Planned:** Prefix, exact (`=`), and regex matching with per-location `proxy_pass`/`root`/`redirect`.

---

### Redirects (`return 301`) {#redirects}

**nginx:**
```nginx
return 301 https://example.com$request_uri;
```

**Status:** Not supported.

**Planned:** `redirect` directive at the vhost level and (once location routing lands) per-location redirects.

---

### `try_files` {#try-files}

**nginx:**
```nginx
try_files $uri $uri/ /index.html;
```

**Status:** Not supported. Used in almost every SPA and WordPress config to serve static files before falling back to a backend.

**Planned:** `try_files` directive on the static file handler.

---

## P2 — Common production patterns {#proxy-set-header}

### Header Manipulation (`proxy_set_header`, `add_header`) {#proxy-set-header}

**nginx:**
```nginx
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
add_header X-Custom-Header "value";
```

**Status:** Not supported for arbitrary headers. Security-specific `add_header` directives (X-Frame-Options, CSP, HSTS, etc.) are fully supported via the `security` block.

**Planned:** `proxy_set_header` and `add_header` directives for arbitrary request/response header manipulation.

---

### HTTP Basic Auth (`auth_basic`) {#auth-basic}

**nginx:**
```nginx
auth_basic "Restricted";
auth_basic_user_file /etc/nginx/.htpasswd;
```

**Status:** Not supported.

**Planned:** `auth_basic` block per vhost backed by an htpasswd file.

---

### Connection Limiting (`limit_conn`) {#limit-conn}

**nginx:**
```nginx
limit_conn_zone $binary_remote_addr zone=conn:10m;
limit_conn conn 10;
```

**Status:** Not supported. Rate limiting (`limit_req`) is fully supported.

**Planned:** `security { limit_conn N }` directive alongside the existing `rate_limit` block.

---

### Custom Error Pages (`error_page`) {#error-pages}

**nginx:**
```nginx
error_page 404 /404.html;
error_page 500 502 503 504 /50x.html;
```

**Status:** Not supported.

**Planned:** `error_page` directive mapping HTTP status codes to static files or backend paths.

---

### Per-Upstream Timeouts {#timeouts}

**nginx:**
```nginx
proxy_connect_timeout 5s;
proxy_read_timeout    30s;
proxy_send_timeout    30s;
```

**Status:** Not supported. Defaults are used.

**Planned:** `connect_timeout`, `read_timeout`, `send_timeout` directives inside the `upstream` block.

---

## P3 — Advanced / niche {#rewrites}

### URL Rewriting (`rewrite`) {#rewrites}

**nginx:**
```nginx
rewrite ^/old/(.*)$ /new/$1 permanent;
```

**Status:** Not supported. Requires location routing (P1) as a foundation.

**Planned:** After P1 lands — `rewrite` directive with regex and capture group support.

---

### `map` Directive {#map}

**nginx:**
```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}
```

**Status:** Not supported.

---

### `geo` Module {#geo}

**nginx:**
```nginx
geo $country {
    default ZZ;
    1.2.3.0/24 US;
}
```

**Status:** Not supported.

---

### Per-Vhost Logging Configuration {#logging}

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

### JWT Authentication {#jwt}

nginx Plus `auth_jwt` / `auth_jwt_key_file` directives for JSON Web Token validation. Not planned.

### OIDC / OAuth2 {#oidc}

nginx Plus OIDC integration. Not planned. Use an upstream identity-aware proxy.

### njs (JavaScript module) {#njs}

`js_include`, `js_content`, and related njs directives. Not planned.

### Lua / OpenResty {#lua}

Lua-based request/response scripting. Not planned.

### nginx Plus Active Health Check {#health-check-plus}

The `health_check` directive in nginx Plus runs active probes configured as a location directive, distinct from tinyproxy's built-in `health_check` block in `upstream`. nginx Plus configs that use `health_check` inside `location` blocks will be stubbed.

---

## Contributing

If you need any of the P1–P3 features, please [open an issue](https://github.com/carlHandy/go-tinyproxy/issues) or submit a pull request. P1 items (URL routing, redirects, `try_files`) are the highest leverage and will unlock the most migrations.
```

- [ ] **Step 5: Verify Docusaurus builds without error**

```bash
cd website && npm install && npm run build 2>&1 | tail -20
```

Expected: `Success! Generated static files in "build".` with no errors.

- [ ] **Step 6: Commit**

```bash
git add website/docs/migration/ website/sidebars.js
git commit -m "docs: add nginx migration guide, directive map, and gap analysis"
```

---

## Self-Review Against Spec

All spec requirements covered:

| Spec item | Task |
|---|---|
| `tinyproxy migrate` Go CLI subcommand | Tasks 3–7 |
| `--output` / `--report` flags | Task 7 |
| `nginx-go-crossplane` parser | Task 2 |
| `# UNSUPPORTED[tag]` inline stubs | Tasks 4–6 |
| Migration report markdown | Task 6 |
| Python standalone (`tools/nginx-migrate.py`) | Task 8 |
| `website/docs/migration/nginx.md` | Task 9 |
| `website/docs/migration/nginx-directive-map.md` | Task 9 |
| `website/docs/migration/nginx-gap-analysis.md` | Task 9 |
| `website/sidebars.js` Migration category | Task 9 |
| `max_body_size` config parser directive | Task 1 |
| Directive mapping: fully converted | Tasks 3–5 |
| Directive mapping: partial (keepalive, backup) | Task 5 |
| Directive mapping: stubbed (location, rewrite, etc.) | Tasks 3–4 |
| nginx Plus directives stubbed | Tasks 3–4 |
| P1–P4 roadmap in gap analysis | Task 9 |
