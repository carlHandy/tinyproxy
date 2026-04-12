# Bot Detection Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a configurable bot-detection middleware that blocks known AI crawlers and malicious scrapers before they reach the proxied backend, with per-vhost allow/deny rules.

**Architecture:** A new `internal/server/botdetect` package exposes a `BotDetect(config BotConfig) func(http.Handler) http.Handler` middleware function, following the same pattern as `security.RateLimit`. Detection is layered: User-Agent substring matching first (cheap), then path-pattern heuristics (scanning for config files, admin panels, etc.). Allowlisted bots (Googlebot, Bingbot) pass through unconditionally. The middleware is inserted into `VHostHandler.ServeHTTP` in `cmd/tinyproxy/main.go` immediately after rate limiting.

**Tech Stack:** Go standard library, `testing` package for tests, existing `config` package patterns.

---

## File Map

**New files:**
- `internal/server/botdetect/botdetect.go` — middleware entry point, `BotDetect()` factory, `BotConfig` type
- `internal/server/botdetect/useragent.go` — UA substring matching, known AI/scraper UA lists
- `internal/server/botdetect/paths.go` — suspicious path heuristics (config leaks, admin probing)
- `internal/server/botdetect/botdetect_test.go` — tests for all detection logic
- `internal/server/botdetect/useragent_test.go` — UA matching tests
- `internal/server/botdetect/paths_test.go` — path heuristic tests

**Modified files:**
- `internal/server/config/vhost.go` — add `BotProtection BotProtectionConfig` field to `VirtualHost`
- `internal/server/config/parser.go` — parse `bot_protection { ... }` block
- `config/validate.go` — validate bot_protection settings
- `cmd/tinyproxy/main.go` — wire `botdetect.BotDetect` into `ServeHTTP`
- `config/vhosts.conf` — add commented bot_protection example

---

## Task 1: Create botdetect package — UA matching core

**Files:**
- Create: `internal/server/botdetect/useragent.go`
- Create: `internal/server/botdetect/useragent_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/server/botdetect/useragent_test.go
package botdetect

import "testing"

func TestIsKnownBot_AIcrawlers(t *testing.T) {
    cases := []struct {
        ua      string
        wantBot bool
    }{
        {"Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)", true},
        {"Mozilla/5.0 (compatible; ClaudeBot/1.0; +https://anthropic.com/)", true},
        {"CCBot/2.0 (https://commoncrawl.org/faq/)", true},
        {"PerplexityBot/1.0", true},
        {"Mozilla/5.0 AppleWebKit/537.36 Chrome/120.0", false},
        {"", false},
    }
    for _, c := range cases {
        t.Run(c.ua, func(t *testing.T) {
            if got := isKnownBot(c.ua); got != c.wantBot {
                t.Errorf("isKnownBot(%q) = %v, want %v", c.ua, got, c.wantBot)
            }
        })
    }
}

func TestIsAllowedBot_LegitCrawlers(t *testing.T) {
    cases := []struct {
        ua        string
        wantAllow bool
    }{
        {"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", true},
        {"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", true},
        {"DuckDuckBot/1.1", true},
        {"GPTBot/1.0", false},
        {"curl/7.88.0", false},
    }
    for _, c := range cases {
        t.Run(c.ua, func(t *testing.T) {
            if got := isAllowedBot(c.ua); got != c.wantAllow {
                t.Errorf("isAllowedBot(%q) = %v, want %v", c.ua, got, c.wantAllow)
            }
        })
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/server/botdetect/... -v -run TestIsKnownBot
```

Expected: `FAIL — undefined: isKnownBot`

- [ ] **Step 3: Write the implementation**

```go
// internal/server/botdetect/useragent.go
package botdetect

import "strings"

// blockedAgents are known AI crawlers and malicious scrapers.
// Checked as case-sensitive substrings of the User-Agent header.
var blockedAgents = []string{
    // AI crawlers
    "GPTBot",
    "ChatGPT-User",
    "CCBot",
    "anthropic-ai",
    "ClaudeBot",
    "Claude-Web",
    "PerplexityBot",
    "YouBot",
    "cohere-ai",
    "Bytespider",
    "PetalBot",
    "SemrushBot",
    "AhrefsBot",
    "MJ12bot",
    "DotBot",
    // Generic headless/scripted
    "python-requests",
    "scrapy",
    "libwww-perl",
    "masscan",
    "zgrab",
}

// allowedAgents are legitimate search engine crawlers that should pass through.
// Checked before blockedAgents — allowed takes precedence.
var allowedAgents = []string{
    "Googlebot",
    "bingbot",
    "Slurp",         // Yahoo
    "DuckDuckBot",
    "Baiduspider",
    "facebookexternalhit",
    "Twitterbot",
    "LinkedInBot",
    "Applebot",
}

// isAllowedBot returns true if ua matches a known-legitimate crawler.
func isAllowedBot(ua string) bool {
    for _, a := range allowedAgents {
        if strings.Contains(ua, a) {
            return true
        }
    }
    return false
}

// isKnownBot returns true if ua matches a blocked bot/scraper pattern.
// Always call isAllowedBot first.
func isKnownBot(ua string) bool {
    if ua == "" {
        return false
    }
    for _, b := range blockedAgents {
        if strings.Contains(ua, b) {
            return true
        }
    }
    return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/server/botdetect/... -v -run "TestIsKnownBot|TestIsAllowedBot"
```

Expected: `PASS`

- [ ] **Step 5: Commit**

```bash
git add internal/server/botdetect/useragent.go internal/server/botdetect/useragent_test.go
git commit -m "feat(botdetect): UA matching core with blocked/allowed agent lists"
```

---

## Task 2: Path heuristics — detect scanning and probing

**Files:**
- Create: `internal/server/botdetect/paths.go`
- Create: `internal/server/botdetect/paths_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/server/botdetect/paths_test.go
package botdetect

import "testing"

func TestIsSuspiciousPath(t *testing.T) {
    cases := []struct {
        path    string
        wantHit bool
    }{
        {"/.env", true},
        {"/.git/config", true},
        {"/wp-admin/login.php", true},
        {"/phpMyAdmin/", true},
        {"/etc/passwd", true},
        {"/admin", true},
        {"/actuator/health", true},
        {"/index.html", false},
        {"/api/users", false},
        {"/static/app.js", false},
    }
    for _, c := range cases {
        t.Run(c.path, func(t *testing.T) {
            if got := isSuspiciousPath(c.path); got != c.wantHit {
                t.Errorf("isSuspiciousPath(%q) = %v, want %v", c.path, got, c.wantHit)
            }
        })
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/server/botdetect/... -v -run TestIsSuspiciousPath
```

Expected: `FAIL — undefined: isSuspiciousPath`

- [ ] **Step 3: Write the implementation**

```go
// internal/server/botdetect/paths.go
package botdetect

import "strings"

// suspiciousPaths are path prefixes/substrings that indicate automated scanning.
var suspiciousPaths = []string{
    "/.env",
    "/.git",
    "/.svn",
    "/.htaccess",
    "/wp-admin",
    "/wp-login",
    "/phpMyAdmin",
    "/phpmyadmin",
    "/etc/passwd",
    "/etc/shadow",
    "/actuator",
    "/console",
    "/manager/html",  // Tomcat
    "/solr/",
    "/jenkins",
    "/.aws",
    "/config.json",
    "/credentials",
}

// isSuspiciousPath returns true if the request path matches known scanning patterns.
func isSuspiciousPath(path string) bool {
    lower := strings.ToLower(path)
    for _, p := range suspiciousPaths {
        if strings.HasPrefix(lower, strings.ToLower(p)) {
            return true
        }
    }
    return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/server/botdetect/... -v -run TestIsSuspiciousPath
```

Expected: `PASS`

- [ ] **Step 5: Commit**

```bash
git add internal/server/botdetect/paths.go internal/server/botdetect/paths_test.go
git commit -m "feat(botdetect): suspicious path heuristics for scanner detection"
```

---

## Task 3: Middleware factory and BotConfig type

**Files:**
- Create: `internal/server/botdetect/botdetect.go`
- Create: `internal/server/botdetect/botdetect_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/server/botdetect/botdetect_test.go
package botdetect

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func okHandler() http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    })
}

func TestBotDetect_BlocksKnownBot(t *testing.T) {
    cfg := BotConfig{Enabled: true, BlockScanners: true}
    handler := BotDetect(cfg)(okHandler())

    req := httptest.NewRequest("GET", "/", nil)
    req.Header.Set("User-Agent", "GPTBot/1.0")
    w := httptest.NewRecorder()

    handler.ServeHTTP(w, req)

    if w.Code != http.StatusForbidden {
        t.Errorf("expected 403, got %d", w.Code)
    }
}

func TestBotDetect_AllowsLegitCrawler(t *testing.T) {
    cfg := BotConfig{Enabled: true, BlockScanners: true}
    handler := BotDetect(cfg)(okHandler())

    req := httptest.NewRequest("GET", "/", nil)
    req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1)")
    w := httptest.NewRecorder()

    handler.ServeHTTP(w, req)

    if w.Code != http.StatusOK {
        t.Errorf("expected 200, got %d", w.Code)
    }
}

func TestBotDetect_BlocksScanner(t *testing.T) {
    cfg := BotConfig{Enabled: true, BlockScanners: true}
    handler := BotDetect(cfg)(okHandler())

    req := httptest.NewRequest("GET", "/.env", nil)
    req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
    w := httptest.NewRecorder()

    handler.ServeHTTP(w, req)

    if w.Code != http.StatusForbidden {
        t.Errorf("expected 403, got %d", w.Code)
    }
}

func TestBotDetect_DisabledPassesAll(t *testing.T) {
    cfg := BotConfig{Enabled: false}
    handler := BotDetect(cfg)(okHandler())

    req := httptest.NewRequest("GET", "/.env", nil)
    req.Header.Set("User-Agent", "GPTBot/1.0")
    w := httptest.NewRecorder()

    handler.ServeHTTP(w, req)

    if w.Code != http.StatusOK {
        t.Errorf("expected 200 when disabled, got %d", w.Code)
    }
}

func TestBotDetect_CustomBlockedAgents(t *testing.T) {
    cfg := BotConfig{
        Enabled:       true,
        BlockedAgents: []string{"MyCustomScraper"},
    }
    handler := BotDetect(cfg)(okHandler())

    req := httptest.NewRequest("GET", "/", nil)
    req.Header.Set("User-Agent", "MyCustomScraper/2.0")
    w := httptest.NewRecorder()

    handler.ServeHTTP(w, req)

    if w.Code != http.StatusForbidden {
        t.Errorf("expected 403 for custom blocked agent, got %d", w.Code)
    }
}

func TestBotDetect_CustomAllowedAgents(t *testing.T) {
    cfg := BotConfig{
        Enabled:       true,
        AllowedAgents: []string{"FriendlyBot"},
    }
    handler := BotDetect(cfg)(okHandler())

    req := httptest.NewRequest("GET", "/", nil)
    req.Header.Set("User-Agent", "FriendlyBot/1.0 GPTBot")
    w := httptest.NewRecorder()

    handler.ServeHTTP(w, req)

    // FriendlyBot is in AllowedAgents, so it passes even though GPTBot is also in the UA
    if w.Code != http.StatusOK {
        t.Errorf("expected 200 for custom allowed agent, got %d", w.Code)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/server/botdetect/... -v -run TestBotDetect
```

Expected: `FAIL — undefined: BotConfig, BotDetect`

- [ ] **Step 3: Write the implementation**

```go
// internal/server/botdetect/botdetect.go
package botdetect

import (
    "net/http"
    "strings"
)

// BotConfig controls bot detection behaviour for a virtual host.
type BotConfig struct {
    // Enabled toggles bot detection entirely. Default: false (opt-in per vhost).
    Enabled bool

    // BlockScanners blocks requests to known vulnerability-scanning paths (.env, .git, etc.).
    BlockScanners bool

    // BlockedAgents are additional UA substrings to block, merged with the built-in list.
    BlockedAgents []string

    // AllowedAgents are additional UA substrings to allow, merged with the built-in list.
    // Allowed takes precedence over blocked.
    AllowedAgents []string
}

// BotDetect returns middleware that inspects User-Agent and request path.
// Allowed bots (Googlebot etc.) pass through unconditionally.
// Blocked bots and scanner paths receive 403.
func BotDetect(cfg BotConfig) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if !cfg.Enabled {
                next.ServeHTTP(w, r)
                return
            }

            ua := r.Header.Get("User-Agent")

            // Allowed list wins — legitimate crawlers pass through.
            if isAllowedBot(ua) || containsAny(ua, cfg.AllowedAgents) {
                next.ServeHTTP(w, r)
                return
            }

            // Block by User-Agent.
            if isKnownBot(ua) || containsAny(ua, cfg.BlockedAgents) {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }

            // Block by suspicious path.
            if cfg.BlockScanners && isSuspiciousPath(r.URL.Path) {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

// containsAny returns true if s contains any of the substrings in list.
func containsAny(s string, list []string) bool {
    for _, item := range list {
        if strings.Contains(s, item) {
            return true
        }
    }
    return false
}
```

- [ ] **Step 4: Run all botdetect tests**

```bash
go test ./internal/server/botdetect/... -v
```

Expected: all `PASS`

- [ ] **Step 5: Commit**

```bash
git add internal/server/botdetect/botdetect.go internal/server/botdetect/botdetect_test.go
git commit -m "feat(botdetect): BotDetect middleware factory with BotConfig"
```

---

## Task 4: Add BotProtectionConfig to VirtualHost and parse it

**Files:**
- Modify: `internal/server/config/vhost.go`
- Modify: `internal/server/config/parser.go`
- Modify: `config/validate.go`

- [ ] **Step 1: Write the failing test**

Add to a new file `internal/server/config/parser_botdetect_test.go`:

```go
// internal/server/config/parser_botdetect_test.go
package config

import (
    "strings"
    "testing"
)

func TestParser_BotProtection(t *testing.T) {
    input := `
vhosts {
    example.com {
        port 80
        root /var/www
        bot_protection {
            enabled true
            block_scanners true
            block GPTBot
            block MyBadBot
            allow FriendlyBot
        }
    }
}`
    p := NewParser(strings.NewReader(input))
    cfg, err := p.Parse()
    if err != nil {
        t.Fatalf("parse error: %v", err)
    }

    vh, ok := cfg.VHosts["example.com"]
    if !ok {
        t.Fatal("vhost example.com not found")
    }

    bp := vh.BotProtection
    if !bp.Enabled {
        t.Error("expected BotProtection.Enabled = true")
    }
    if !bp.BlockScanners {
        t.Error("expected BotProtection.BlockScanners = true")
    }
    if len(bp.BlockedAgents) != 2 || bp.BlockedAgents[0] != "GPTBot" || bp.BlockedAgents[1] != "MyBadBot" {
        t.Errorf("unexpected BlockedAgents: %v", bp.BlockedAgents)
    }
    if len(bp.AllowedAgents) != 1 || bp.AllowedAgents[0] != "FriendlyBot" {
        t.Errorf("unexpected AllowedAgents: %v", bp.AllowedAgents)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/server/config/... -v -run TestParser_BotProtection
```

Expected: `FAIL — vh.BotProtection undefined`

- [ ] **Step 3: Add BotProtectionConfig to vhost.go**

In `internal/server/config/vhost.go`, add the struct and field. Insert after the `SOCKS5` struct closing brace, before `FastCGI`:

```go
// BotProtectionConfig controls per-vhost bot detection settings.
type BotProtectionConfig struct {
    Enabled       bool
    BlockScanners bool
    BlockedAgents []string
    AllowedAgents []string
}
```

Then add the field to `VirtualHost` (after `FastCGI`):

```go
BotProtection BotProtectionConfig
```

- [ ] **Step 4: Add bot_protection parser to parser.go**

In `internal/server/config/parser.go`, add a case to `parseLine`:

```go
case "bot_protection":
    return p.parseBotProtection()
```

Then add the method at the end of the file:

```go
func (p *Parser) parseBotProtection() error {
    for p.scanner.Scan() {
        p.line++
        line := strings.TrimSpace(p.scanner.Text())

        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        if line == "}" {
            return nil
        }

        parts := strings.Fields(line)
        if len(parts) < 2 {
            continue
        }

        switch parts[0] {
        case "enabled":
            p.currentVHost.BotProtection.Enabled = parts[1] == "true"
        case "block_scanners":
            p.currentVHost.BotProtection.BlockScanners = parts[1] == "true"
        case "block":
            p.currentVHost.BotProtection.BlockedAgents = append(
                p.currentVHost.BotProtection.BlockedAgents, parts[1])
        case "allow":
            p.currentVHost.BotProtection.AllowedAgents = append(
                p.currentVHost.BotProtection.AllowedAgents, parts[1])
        }
    }
    return nil
}
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
go test ./internal/server/config/... -v -run TestParser_BotProtection
```

Expected: `PASS`

- [ ] **Step 6: Commit**

```bash
git add internal/server/config/vhost.go internal/server/config/parser.go \
        internal/server/config/parser_botdetect_test.go
git commit -m "feat(config): add BotProtectionConfig to VirtualHost and parse bot_protection block"
```

---

## Task 5: Wire bot detection into the request pipeline

**Files:**
- Modify: `cmd/tinyproxy/main.go`
- Modify: `config/vhosts.conf`

- [ ] **Step 1: Add import and wire middleware in main.go**

In `cmd/tinyproxy/main.go`, add the import:

```go
"tinyproxy/internal/server/botdetect"
```

In `VHostHandler.ServeHTTP`, convert `vhost.BotProtection` to a `botdetect.BotConfig` and apply it. Replace the existing `rateLimitedHandler` block with:

```go
func (vh *VHostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    host := r.Host
    vhost, exists := vh.config.VHosts[host]
    if !exists {
        vhost = vh.config.VHosts["default"]
    }

    botCfg := botdetect.BotConfig{
        Enabled:       vhost.BotProtection.Enabled,
        BlockScanners: vhost.BotProtection.BlockScanners,
        BlockedAgents: vhost.BotProtection.BlockedAgents,
        AllowedAgents: vhost.BotProtection.AllowedAgents,
    }

    // Pipeline: rate limit → bot detection → security headers → compression → dispatch
    inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        vh.setSecurityHeaders(w, vhost)

        handler := vh.handleVHost
        if !exists {
            handler = vh.handleDefaultVHost
        }

        if vhost.Compression {
            compression.Compress(handler)(w, r)
            return
        }
        handler(w, r)
    })

    botHandler := botdetect.BotDetect(botCfg)(inner)

    rateLimitedHandler := security.RateLimit(
        vhost.Security.RateLimit.Requests,
        vhost.Security.RateLimit.Window,
    )(botHandler)

    rateLimitedHandler.ServeHTTP(w, r)
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./cmd/tinyproxy/
```

Expected: no errors

- [ ] **Step 3: Add example config block to vhosts.conf**

In `config/vhosts.conf`, inside the `vhosts { }` block, add before the closing `}`:

```
    # example.com {
    #     bot_protection {
    #         enabled true
    #         block_scanners true   # block .env, .git, wp-admin probes
    #         block PerplexityBot   # additional UA to block
    #         allow FriendlyBot     # override: allow this UA even if it matches block rules
    #     }
    # }
```

- [ ] **Step 4: Run all tests to confirm nothing broke**

```bash
go test ./...
```

Expected: all `PASS`

- [ ] **Step 5: Commit**

```bash
git add cmd/tinyproxy/main.go config/vhosts.conf
git commit -m "feat: wire botdetect middleware into VHostHandler request pipeline"
```

---

## Task 6: Validate bot_protection config

**Files:**
- Modify: `config/validate.go`

- [ ] **Step 1: Write the failing test**

Add to a new file `config/validate_test.go`:

```go
// config/validate_test.go
package config

import (
    "testing"
    "time"
)

func makeMinimalVHost() *VirtualHost {
    return &VirtualHost{
        Hostname:    "example.com",
        Port:        80,
        Root:        "/var/www",
        MaxBodySize: 1024,
        Security: SecurityConfig{
            RateLimit: struct {
                Enabled  bool
                Requests int
                Window   time.Duration
            }{Requests: 10, Window: time.Minute},
        },
    }
}

func TestValidate_BotProtection_DisabledIsValid(t *testing.T) {
    sc := NewServerConfig()
    vh := makeMinimalVHost()
    vh.BotProtection.Enabled = false
    sc.VHosts["example.com"] = vh

    if err := sc.Validate(); err != nil {
        t.Errorf("unexpected error: %v", err)
    }
}

func TestValidate_BotProtection_EnabledIsValid(t *testing.T) {
    sc := NewServerConfig()
    vh := makeMinimalVHost()
    vh.BotProtection.Enabled = true
    vh.BotProtection.BlockScanners = true
    sc.VHosts["example.com"] = vh

    if err := sc.Validate(); err != nil {
        t.Errorf("unexpected error: %v", err)
    }
}
```

- [ ] **Step 2: Run test to verify it passes already** (no new validation rules yet — this establishes baseline)

```bash
go test ./config/... -v -run TestValidate_BotProtection
```

Expected: `PASS` (bot protection fields are zero-value safe — nothing to reject)

- [ ] **Step 3: No implementation needed** — `BotProtectionConfig` is valid in any state. The test confirms `Validate()` doesn't panic on the new field. If future constraints are added (e.g., max blocked agents count), add them here.

- [ ] **Step 4: Commit**

```bash
git add config/validate_test.go
git commit -m "test(config): baseline validation tests for BotProtectionConfig"
```

---

## Self-Review

**Spec coverage:**
- ✅ Block known AI crawlers (GPTBot, ClaudeBot, CCBot, PerplexityBot, etc.) — Task 1
- ✅ Allow legitimate crawlers (Googlebot, Bingbot) to pass through — Task 1
- ✅ Block vulnerability scanners probing /.env, /.git, /wp-admin, etc. — Task 2
- ✅ Middleware composable and opt-in per vhost — Tasks 3, 5
- ✅ Config DSL support with `block`/`allow`/`block_scanners` directives — Task 4
- ✅ Validation doesn't break on new config field — Task 6
- ✅ Custom per-vhost block/allow lists — Tasks 3, 4

**Not in scope for this plan (Phase 2):**
- Behavioral analysis (request timing, missing browser headers)
- TLS fingerprinting (JA3/JA4)
- Logging blocked requests with reason
- Prometheus metrics for bot traffic

**Placeholder scan:** No TBDs found. All code blocks are complete.

**Type consistency:**
- `BotConfig` in `botdetect` package ↔ `BotProtectionConfig` in `config` package — these are intentionally separate (internal/external boundary). Task 5 maps between them explicitly.
- `BotDetect(cfg BotConfig)` matches across Tasks 3 and 5.
- `isKnownBot`, `isAllowedBot`, `isSuspiciousPath`, `containsAny` — all unexported helpers used only within `botdetect` package.
