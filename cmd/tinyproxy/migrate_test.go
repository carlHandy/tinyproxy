package main

import (
	"os"
	"strings"
	"testing"
	"time"

	crossplane "github.com/nginxinc/nginx-go-crossplane"
)

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
		t.Errorf("ssl.cert = %q", vh.ssl.cert)
	}
	if vh.ssl.key != "/etc/ssl/key.pem" {
		t.Errorf("ssl.key = %q", vh.ssl.key)
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
		args     []string
		wantPort int
		wantSSL  bool
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

func TestParseLimitReqZone_MissingZone(t *testing.T) {
	_, _, ok := parseLimitReqZone([]string{"$binary_remote_addr", "rate=10r/s"})
	if ok {
		t.Error("expected ok=false when zone= is absent")
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

func TestConvertUpstreamBlock_BackupServerStubbed(t *testing.T) {
	dirs := crossplane.Directives{
		{Directive: "server", Args: []string{"10.0.0.1:8080"}},
		{Directive: "server", Args: []string{"10.0.0.2:8080", "backup"}},
	}
	uc, stubs := convertUpstreamBlock(dirs)
	if len(uc.backends) != 1 {
		t.Fatalf("got %d backends, want 1 (backup server must be excluded)", len(uc.backends))
	}
	if uc.backends[0] != "http://10.0.0.1:8080" {
		t.Errorf("backend[0] = %q", uc.backends[0])
	}
	if len(stubs) != 1 {
		t.Fatalf("got %d stubs, want 1 for backup server", len(stubs))
	}
	if stubs[0].tag != "server(backup)" {
		t.Errorf("stub tag = %q, want server(backup)", stubs[0].tag)
	}
}

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
	if !strings.Contains(rpt, "Directives converted | 10") {
		t.Errorf("missing converted count:\n%s", rpt)
	}
	if !strings.Contains(rpt, "example.com") {
		t.Errorf("missing vhost in report:\n%s", rpt)
	}
	if !strings.Contains(rpt, "location") {
		t.Errorf("missing directive in report:\n%s", rpt)
	}
}
