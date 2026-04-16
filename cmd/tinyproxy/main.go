package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
	"tinyproxy/internal/cache"
	"tinyproxy/internal/dashboard"
	"tinyproxy/internal/dashboard/logring"
	dashstats "tinyproxy/internal/dashboard/stats"
	"tinyproxy/internal/fastcgi"
	"tinyproxy/internal/loadbalancer"
	"tinyproxy/internal/server/botdetect"
	"tinyproxy/internal/server/compression"
	"tinyproxy/internal/server/config"
	"tinyproxy/internal/server/fingerprint"
	"tinyproxy/internal/server/proxy"
	"tinyproxy/internal/server/security"
	"tinyproxy/internal/server/security/certmanager"
)

// maxTLSRecordBody is the maximum TLS record payload size per RFC 5246 §6.2.1.
const maxTLSRecordBody = 16384

// fingerprintConn replays buffered bytes before delegating reads to the underlying conn.
// For TLS connections it holds the full ClientHello record so that both the TLS
// handshake and the fingerprint computation receive the same bytes.
type fingerprintConn struct {
	net.Conn
	buf []byte
	pos int
	fp  fingerprint.Fingerprints
}

func (c *fingerprintConn) Read(b []byte) (int, error) {
	if c.pos < len(c.buf) {
		n := copy(b, c.buf[c.pos:])
		c.pos += n
		return n, nil
	}
	return c.Conn.Read(b)
}

// sniffingListener accepts TCP connections and dispatches them based on the first byte:
// TLS ClientHello (0x16) → upgrade to TLS; anything else → HTTP redirect response.
type sniffingListener struct {
	inner  net.Listener
	tlsCfg *tls.Config
}

func (l *sniffingListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}

		// Read the 5-byte TLS record header.
		hdr := make([]byte, 5)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = io.ReadFull(conn, hdr)
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			log.Printf("fingerprint: failed to read TLS header from %s: %v", conn.RemoteAddr(), err)
			conn.Close()
			continue
		}

		if hdr[0] != 0x16 {
			// Plain HTTP — send redirect and loop.
			fmt.Fprint(conn, "HTTP/1.1 301 Moved Permanently\r\nLocation: https://localhost:8080\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			conn.Close()
			continue
		}

		// TLS — read the rest of the record body.
		recordLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		if recordLen > maxTLSRecordBody {
			conn.Close()
			continue
		}
		body := make([]byte, recordLen)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = io.ReadFull(conn, body)
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			log.Printf("fingerprint: failed to read TLS record body from %s: %v", conn.RemoteAddr(), err)
			conn.Close()
			continue
		}

		buf := make([]byte, 5+recordLen)
		copy(buf, hdr)
		copy(buf[5:], body)
		fc := &fingerprintConn{
			Conn: conn,
			buf:  buf,
			fp:   fingerprint.Compute(buf),
		}
		return tls.Server(fc, l.tlsCfg), nil
	}
}

func (l *sniffingListener) Close() error   { return l.inner.Close() }
func (l *sniffingListener) Addr() net.Addr { return l.inner.Addr() }

// responseWriter wraps http.ResponseWriter to capture status code and bytes written.
type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if rw.status == 0 {
		rw.status = http.StatusOK
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytes += int64(n)
	return n, err
}

type VHostHandler struct {
	mu        sync.RWMutex
	config    *config.ServerConfig
	blocklist map[string]struct{}
	caches    map[string]*cache.Cache
	balancers map[string]*loadbalancer.LoadBalancer
	stats     *dashstats.Collector // nil when dashboard is disabled
}

// initSubsystems builds per-vhost caches and load balancers from the current config.
func (vh *VHostHandler) initSubsystems() {
	vh.caches = make(map[string]*cache.Cache)
	vh.balancers = make(map[string]*loadbalancer.LoadBalancer)

	for name, vhost := range vh.config.VHosts {
		if vhost.Cache.Enabled {
			vh.caches[name] = cache.New(vhost.Cache.MaxSize)
			log.Printf("cache enabled for vhost %q (max %d bytes, TTL %s)",
				name, vhost.Cache.MaxSize, vhost.Cache.DefaultTTL)
		}
		if len(vhost.Upstream.Backends) > 0 {
			lb, err := loadbalancer.New(vhost.Upstream)
			if err != nil {
				log.Printf("WARNING: failed to init load balancer for vhost %q: %v", name, err)
				continue
			}
			vh.balancers[name] = lb
			log.Printf("load balancer enabled for vhost %q (strategy %s, %d backends)",
				name, vhost.Upstream.Strategy, len(vhost.Upstream.Backends))
		}
	}
}

// stopSubsystems shuts down health checkers for all active load balancers.
func (vh *VHostHandler) stopSubsystems() {
	for _, lb := range vh.balancers {
		lb.Stop()
	}
}

func (vh *VHostHandler) reload(configPath string) error {
	f, err := os.Open(configPath)
	if err != nil {
		return err
	}
	defer f.Close()
	newCfg, err := config.NewParser(f).Parse()
	if err != nil {
		return err
	}
	vh.mu.Lock()
	vh.stopSubsystems()
	vh.config = newCfg
	vh.initSubsystems()
	vh.mu.Unlock()
	return nil
}

func (vh *VHostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rw := &responseWriter{ResponseWriter: w}

	vh.mu.RLock()
	cfg := vh.config
	bl := vh.blocklist
	caches := vh.caches
	balancers := vh.balancers
	collector := vh.stats
	vh.mu.RUnlock()

	host := r.Host
	vhost, exists := cfg.VHosts[host]
	if !exists {
		vhost = cfg.VHosts["default"]
	}

	fp := fingerprint.FromContext(r.Context())
	if fingerprint.IsBlocked(bl, fp) {
		log.Printf("BLOCKING TLS fingerprint: %s %s JA3=%s JA4=%s", r.Method, r.URL.Path, fp.JA3, fp.JA4)
		botdetect.Block(rw, r, vhost.BotProtection.Honeypot)
		return
	}

	botCfg := botdetect.BotConfig{
		Enabled:       vhost.BotProtection.Enabled,
		BlockScanners: vhost.BotProtection.BlockScanners,
		Honeypot:      vhost.BotProtection.Honeypot,
		BlockedAgents: vhost.BotProtection.BlockedAgents,
		AllowedAgents: vhost.BotProtection.AllowedAgents,
		BlockedPaths:  vhost.BotProtection.BlockedPaths,
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vh.setSecurityHeaders(w, vhost)
		if fp.JA3 != "" {
			log.Printf("%s %s JA3=%s JA4=%s", r.Method, r.URL.Path, fp.JA3, fp.JA4)
		}

		if !exists {
			vh.handleDefaultVHost(w, r)
			return
		}

		// Build the core handler (compression wrapping handleVHost)
		var coreHandler http.Handler
		if vhost.Compression {
			coreHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				compression.Compress(func(w http.ResponseWriter, r *http.Request) {
					vh.handleVHost(w, r, vhost, balancers[host])
				})(w, r)
			})
		} else {
			coreHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				vh.handleVHost(w, r, vhost, balancers[host])
			})
		}

		// Wrap with cache middleware if enabled
		if c, ok := caches[host]; ok {
			coreHandler = cache.Handler(vhost.Cache, c)(coreHandler)
		}

		coreHandler.ServeHTTP(w, r)
	})

	botHandler := botdetect.BotDetect(botCfg)(inner)

	security.RateLimit(
		vhost.Security.RateLimit.Requests,
		vhost.Security.RateLimit.Window,
	)(botHandler).ServeHTTP(rw, r)

	if collector != nil {
		host := r.Host
		if i := strings.LastIndex(host, ":"); i > 0 {
			host = host[:i]
		}
		collector.Record(dashstats.RequestRecord{
			TS:      time.Now().UnixMilli(),
			VHost:   host,
			Method:  r.Method,
			Path:    r.URL.Path,
			Status:  rw.status,
			Latency: time.Since(start).Microseconds(),
			Bytes:   rw.bytes,
			Remote:  r.RemoteAddr,
		})
	}
}

func (vh *VHostHandler) setSecurityHeaders(w http.ResponseWriter, vhost *config.VirtualHost) {
	w.Header().Set("X-Frame-Options", vhost.Security.Headers.FrameOptions)
	w.Header().Set("X-Content-Type-Options", vhost.Security.Headers.ContentType)
	w.Header().Set("X-XSS-Protection", vhost.Security.Headers.XSSProtection)
	w.Header().Set("Content-Security-Policy", vhost.Security.Headers.CSP)
	w.Header().Set("Strict-Transport-Security", vhost.Security.Headers.HSTS)
}

func (vh *VHostHandler) handleVHost(w http.ResponseWriter, r *http.Request, vhost *config.VirtualHost, lb *loadbalancer.LoadBalancer) {
	if vhost.FastCGI.Pass != "" {
		fastcgi.Handler(w, r, vhost.FastCGI.Pass, vhost.Root, vhost.FastCGI.Index)
		return
	}

	// Load-balanced upstream: pick a backend and proxy to it
	if lb != nil {
		backend, err := lb.Next(r)
		if err != nil {
			log.Printf("load balancer error: %v", err)
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		lb.MarkActive(backend)
		defer lb.MarkDone(backend)

		// Set sticky-session cookie if strategy requires it
		lb.SetAffinityCookie(w, backend)

		backendProxy, err := proxy.NewSingleBackendProxy(backend.URL)
		if err != nil {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		backendProxy.ServeHTTP(w, r)
		return
	}

	// Single proxy_pass backend
	if vhost.ProxyPass != "" {
		vhosts := []proxy.VHost{
			{
				Domain:     r.Host,
				TargetURL:  vhost.ProxyPass,
				Socks5Addr: vhost.SOCKS5.Address,
			},
		}
		reverseProxy, err := proxy.NewReverseProxy(vhosts)
		if err != nil {
			http.Error(w, "Proxy configuration error", http.StatusInternalServerError)
			return
		}
		reverseProxy.ServeHTTP(w, r)
		return
	}
	http.FileServer(http.Dir(vhost.Root)).ServeHTTP(w, r)
}

func (vh *VHostHandler) handleDefaultVHost(w http.ResponseWriter, r *http.Request) {
	http.FileServer(http.Dir(staticRoot())).ServeHTTP(w, r)
}

// staticRoot returns the directory containing the bundled static files.
// It prefers a local "static/" directory (dev/source), falling back to the
// system-wide path used by the installed package.
func staticRoot() string {
	if _, err := os.Stat("static"); err == nil {
		return "static"
	}
	return "/usr/share/go-tinyproxy/static"
}

// certCacheDir returns the directory autocert uses to persist certificates.
// Uses a local "certs/" directory in dev, and an absolute system path when
// installed — relative paths break under systemd's working directory.
func certCacheDir() string {
	if _, err := os.Stat("certs"); err == nil {
		return "certs"
	}
	return "/var/cache/go-tinyproxy/certs"
}

const systemCertCacheDir = "/var/cache/go-tinyproxy/certs"

// configPath returns the active config file path: local first, then system.
func configPath() string {
	if _, err := os.Stat("config/vhosts.conf"); err == nil {
		return "config/vhosts.conf"
	}
	return "/etc/go-tinyproxy/vhosts.conf"
}

// fingerprintsPath returns the active fingerprints config path: local first, then system.
func fingerprintsPath() string {
	if _, err := os.Stat("config/fingerprints.conf"); err == nil {
		return "config/fingerprints.conf"
	}
	return "/etc/go-tinyproxy/fingerprints.conf"
}

// loadFingerprintBlocklist loads config/fingerprints.conf (or system path).
// Returns an empty blocklist without error if the file does not exist.
func loadFingerprintBlocklist(path string) map[string]struct{} {
	f, err := os.Open(path)
	if err != nil {
		return make(map[string]struct{})
	}
	defer f.Close()
	return fingerprint.LoadBlocklist(f)
}

func loadConfig(path string) (*config.ServerConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, err := config.NewParser(f).Parse()
	if err != nil {
		return nil, err
	}
	// Fix the root path for built-in default vhosts so file serving works
	// regardless of working directory (local dev vs. installed package).
	root := staticRoot()
	for _, key := range []string{"default", "default_ssl"} {
		if dv, ok := cfg.VHosts[key]; ok && dv.Root == "static" {
			dv.Root = root
		}
	}
	return cfg, nil
}

// runServer is the actual server process (used by the systemd service via "go-tinyproxy serve").
func runServer() {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var dc DashboardConfig
	registerDashboardFlags(fs, &dc)
	if len(os.Args) > 2 {
		fs.Parse(os.Args[2:])
	}

	path := configPath()
	cfg, err := loadConfig(path)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	if err := validateDashboardConfig(dc, cfg); err != nil {
		log.Fatalf("dashboard: %v", err)
	}

	handler := &VHostHandler{config: cfg}
	handler.initSubsystems()
	handler.blocklist = loadFingerprintBlocklist(fingerprintsPath())

	var dashSrv *dashboard.Server
	if dc.Enabled {
		db, err := dashstats.Open(dc.DBPath)
		if err != nil {
			log.Fatalf("dashboard: failed to open database: %v", err)
		}
		logbuf := logring.New(10000, os.Stderr)
		log.SetOutput(logbuf)

		collector := dashstats.NewCollector(4096)
		handler.stats = collector

		batchCtx, batchCancel := context.WithCancel(context.Background())
		defer batchCancel()
		go db.RunBatchWriter(batchCtx, collector.Chan())

		logSub := logbuf.Subscribe()
		go func() {
			for line := range logSub {
				db.WriteLogLine(line.TS, line.Level, line.Body)
			}
		}()

		dashCfg := dashboard.Config{
			Host: dc.Host, Port: dc.Port, CredsFile: dc.Creds,
			DBPath: dc.DBPath, TLSCert: dc.TLSCert, TLSKey: dc.TLSKey,
			ConfigPath: path,
		}
		dashSrv, err = dashboard.New(dashCfg, db, logbuf)
		if err != nil {
			log.Fatalf("dashboard: %v", err)
		}
		dashSrv.Start()
	}

	// SIGHUP → reload config without restarting
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)
	go func() {
		for range sigs {
			if err := handler.reload(path); err != nil {
				log.Printf("reload failed: %v", err)
			} else {
				log.Println("config reloaded")
			}
			handler.mu.Lock()
			handler.blocklist = loadFingerprintBlocklist(fingerprintsPath())
			handler.mu.Unlock()
		}
	}()

	server := &http.Server{
		Handler: handler,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc, ok := c.(*tls.Conn); ok {
				if fc, ok := tc.NetConn().(*fingerprintConn); ok {
					return fingerprint.WithFingerprints(ctx, fc.fp)
				}
			}
			return ctx
		},
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	if os.Getenv("ENV") == "dev" {
		tlsCfg := security.SecureTLSConfig()
		cert, err := tls.LoadX509KeyPair("certs/localhost+2.pem", "certs/localhost+2-key.pem")
		if err != nil {
			log.Fatal(err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
		server.TLSConfig = tlsCfg

		tcpLn, err := net.Listen("tcp", ":8080")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Development mode: Listening on :8080 (HTTP redirects to HTTPS automatically)")
		go func() {
			if err := server.Serve(&sniffingListener{inner: tcpLn, tlsCfg: tlsCfg}); err != nil && err != http.ErrServerClosed {
				log.Println("Dev server error:", err)
			}
		}()
	} else {
		// Production — one shared cert manager so HTTP-01 challenge tokens are visible
		// to both the port-80 handler and the port-443 TLS handshake.
		mgr := certmanager.NewManager(cfg, certCacheDir())
		server.Addr = ":443"
		server.TLSConfig = mgr.TLSConfig()

		go func() {
			if err := http.ListenAndServe(":80", mgr.HTTPHandler(nil)); err != nil {
				log.Printf("HTTP listener: %v", err)
			}
		}()

		fmt.Printf("Production mode: Listening on %s\n", server.Addr)
		go func() {
			if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Println("Prod server error:", err)
			}
		}()
	}

	// Graceful shutdown
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if dashSrv != nil {
		dashSrv.Shutdown(ctx)
	}
	server.Shutdown(ctx)
}

func runSystemctl(action string) {
	cmd := exec.Command("systemctl", action, "go-tinyproxy")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
}

func runOpenConfig() {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "nano"
	}
	path, err := exec.LookPath(editor)
	if err != nil {
		log.Fatalf("editor %q not found: %v", editor, err)
	}
	if err := syscall.Exec(path, []string{editor, "/etc/go-tinyproxy/vhosts.conf"}, os.Environ()); err != nil {
		log.Fatal(err)
	}
}

func runLogs() {
	cmd := exec.Command("journalctl", "-u", "go-tinyproxy", "-f", "--no-pager")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func runUpgrade() {
	const repo = "carlHandy/tinyproxy"

	log.Println("Checking for latest release...")
	resp, err := http.Get("https://api.github.com/repos/" + repo + "/releases/latest")
	if err != nil {
		log.Fatalf("failed to check for updates: %v", err)
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		log.Fatalf("failed to parse release info: %v", err)
	}
	log.Printf("Latest version: %s", release.TagName)

	goos := runtime.GOOS
	goarch := runtime.GOARCH
	version := strings.TrimPrefix(release.TagName, "v")

	// Determine installer format based on available package manager.
	ext := "tar.gz"
	installFn := func(path string) {
		log.Fatalf("binary upgrade not supported on this platform; download manually from https://github.com/%s/releases", repo)
	}
	switch {
	case goos == "linux" && hasBin("dpkg"):
		ext = "deb"
		installFn = func(path string) { mustRun("dpkg", "-i", path) }
	case goos == "linux" && hasBin("rpm"):
		ext = "rpm"
		installFn = func(path string) { mustRun("rpm", "-U", path) }
	case goos == "windows":
		ext = "zip"
		installFn = func(_ string) {
			log.Fatalf("automatic upgrade not supported on Windows; download manually from https://github.com/%s/releases", repo)
		}
	}

	assetName := fmt.Sprintf("go-tinyproxy_%s_%s_%s.%s", version, goos, goarch, ext)
	var downloadURL string
	for _, a := range release.Assets {
		if a.Name == assetName {
			downloadURL = a.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		log.Fatalf("no release asset found for this platform (%s); expected %q", goos+"/"+goarch, assetName)
	}

	log.Printf("Downloading %s...", assetName)
	dlResp, err := http.Get(downloadURL)
	if err != nil {
		log.Fatalf("download failed: %v", err)
	}
	defer dlResp.Body.Close()

	tmp, err := os.CreateTemp("", "go-tinyproxy-upgrade-*."+ext)
	if err != nil {
		log.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := io.Copy(tmp, dlResp.Body); err != nil {
		log.Fatalf("failed to write download: %v", err)
	}
	tmp.Close()

	log.Println("Installing...")
	installFn(tmp.Name())

	log.Println("Restarting service...")
	mustRun("systemctl", "restart", "go-tinyproxy")
	log.Println("Upgrade complete.")
}

func runSSL() {
	sub := "regenerate"
	if len(os.Args) > 2 {
		sub = os.Args[2]
	}
	switch sub {
	case "regenerate":
		runSSLRegenerate()
	default:
		fmt.Fprintf(os.Stderr, "Usage: go-tinyproxy ssl regenerate\n")
		os.Exit(1)
	}
}

func runSSLRegenerate() {
	log.Println("Stopping go-tinyproxy...")
	mustRun("systemctl", "stop", "go-tinyproxy")

	log.Printf("Clearing certificate cache at %s...", systemCertCacheDir)
	entries, err := os.ReadDir(systemCertCacheDir)
	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("failed to read cert cache: %v", err)
	}
	for _, e := range entries {
		path := systemCertCacheDir + "/" + e.Name()
		if err := os.Remove(path); err != nil {
			log.Printf("warning: could not remove %s: %v", path, err)
		}
	}

	log.Println("Starting go-tinyproxy...")
	mustRun("systemctl", "start", "go-tinyproxy")
	log.Println("Done. New certificates will be obtained automatically on the next HTTPS connection.")
}

func hasBin(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func mustRun(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("%s failed: %v", name, err)
	}
}

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "serve":
		runServer()
	case "start":
		runSystemctl("start")
	case "stop":
		runSystemctl("stop")
	case "restart":
		runSystemctl("restart")
	case "reload":
		runSystemctl("reload")
	case "status":
		runSystemctl("status")
	case "config":
		runOpenConfig()
	case "logs":
		runLogs()
	case "upgrade":
		runUpgrade()
	case "ssl":
		runSSL()
	case "dashboard":
		sub := ""
		if len(os.Args) > 2 {
			sub = os.Args[2]
		}
		switch sub {
		case "passwd":
			runDashboardPasswd()
		default:
			fmt.Fprintf(os.Stderr, "Usage: go-tinyproxy dashboard passwd\n")
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Usage: go-tinyproxy {serve|start|stop|restart|reload|status|config|logs|upgrade|ssl|dashboard}\n")
		os.Exit(1)
	}
}

func runDashboardPasswd() {
	fmt.Print("Username: ")
	var username string
	fmt.Scanln(&username)
	if username == "" {
		log.Fatal("username cannot be empty")
	}

	fmt.Print("Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		log.Fatalf("failed to read password: %v", err)
	}
	if len(pw) == 0 {
		log.Fatal("password cannot be empty")
	}

	hash, err := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("failed to hash password: %v", err)
	}
	fmt.Printf("%s:%s\n", username, hash)
}
