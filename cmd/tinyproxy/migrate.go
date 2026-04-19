package main

import (
	"flag"
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

var silentDirectives = map[string]bool{
	"server_name":        true,
	"listen":             true,
	"tcp_nopush":         true,
	"tcp_nodelay":        true,
	"keepalive_timeout":  true,
	"sendfile":           true,
	"types":              true,
	"include":            true,
	"default_type":       true,
	"worker_processes":   true,
	"worker_connections": true,
	"events":             true,
	"pid":                true,
	"user":               true,
	"proxy_buffering":    true,
	"proxy_buffer_size":  true,
	"proxy_buffers":      true,
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
					vh.fastcgi = &fastcgiConf{}
				}
				vh.fastcgi.params = append(vh.fastcgi.params, d.Args[0]+" "+strings.Join(d.Args[1:], " "))
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

func directiveToRaw(d *crossplane.Directive) string {
	if len(d.Block) == 0 {
		return d.Directive + " " + strings.Join(d.Args, " ") + ";"
	}
	return d.Directive + " " + strings.Join(d.Args, " ") + " { ... }"
}

func (mc *migrateConf) convertAddHeader(vh *vhostConf, d *crossplane.Directive) bool {
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

func (mc *migrateConf) addStub(vh *vhostConf, d *crossplane.Directive, reason, anchor string) {
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

// ── Output rendering ──────────────────────────────────────────────────────────

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

// ── Placeholders for later tasks ──────────────────────────────────────────────

func parseLimitReqZone(args []string) (zoneName string, rl rateLimitConf, ok bool) {
	var rateOk bool
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
					rateOk = true
				}
			} else if strings.HasSuffix(val, "s") {
				n, err := strconv.Atoi(strings.TrimSuffix(val, "s"))
				if err == nil {
					rl = rateLimitConf{requests: n, window: "1s"}
					rateOk = true
				}
			}
		}
	}
	ok = zoneName != "" && rateOk
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

func convertUpstreamBlock(dirs crossplane.Directives) (*upstreamConf, []inlineStub) {
	uc := &upstreamConf{strategy: "round_robin"}
	var stubs []inlineStub

	for _, d := range dirs {
		switch d.Directive {
		case "server":
			if len(d.Args) == 0 {
				continue
			}
			isBackup := false
			for _, arg := range d.Args[1:] {
				if arg == "backup" {
					isBackup = true
				}
			}
			if isBackup {
				stubs = append(stubs, inlineStub{
					tag:    "server(backup)",
					raw:    directiveToRaw(d),
					reason: "Backup servers not supported; promote to primary or remove",
					anchor: "upstream-backup",
				})
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
					if _, err := strconv.Atoi(w); err == nil {
						backend += " weight " + w
					}
				}
				// skip "down", "fail_timeout=", "max_fails="
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

func runMigrate(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	output := fs.String("output", "vhosts.conf", "write converted config to this file")
	report := fs.String("report", "migration-report.md", "write migration report to this file")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: tinyproxy migrate <nginx.conf> [--output vhosts.conf] [--report migration-report.md]")
		fs.PrintDefaults()
	}
	if len(args) == 0 {
		fs.Usage()
		os.Exit(1)
	}

	// Extract the positional nginx.conf argument (may be first non-flag arg).
	// Parse flags from all remaining args after it to support:
	//   migrate nginx.conf --output foo.conf
	filename := ""
	flagArgs := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		filename = args[0]
		flagArgs = args[1:]
	}
	if err := fs.Parse(flagArgs); err != nil {
		os.Exit(1)
	}
	if filename == "" {
		if fs.NArg() < 1 {
			fs.Usage()
			os.Exit(1)
		}
		filename = fs.Arg(0)
	}
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
