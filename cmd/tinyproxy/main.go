package main

import (
	"crypto/tls"
	"encoding/json"
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
	"tinyproxy/internal/server/botdetect"
	"tinyproxy/internal/server/compression"
	"tinyproxy/internal/server/config"
	"tinyproxy/internal/server/proxy"
	"tinyproxy/internal/server/security"
	"tinyproxy/internal/server/security/certmanager"
	"tinyproxy/internal/fastcgi"
)

// peekedConn replays a single already-read byte before delegating to the real connection.
type peekedConn struct {
	net.Conn
	b    []byte
	done bool
}

func (c *peekedConn) Read(buf []byte) (int, error) {
	if !c.done && len(c.b) > 0 {
		c.done = true
		n := copy(buf, c.b)
		return n, nil
	}
	return c.Conn.Read(buf)
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

		b := make([]byte, 1)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Read(b)
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			conn.Close()
			continue
		}

		peeked := &peekedConn{Conn: conn, b: b}

		if b[0] == 0x16 {
			return tls.Server(peeked, l.tlsCfg), nil
		}

		// Plain HTTP — send a redirect and loop to accept the next connection.
		fmt.Fprint(peeked, "HTTP/1.1 301 Moved Permanently\r\nLocation: https://localhost:8080\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		peeked.Close()
	}
}

func (l *sniffingListener) Close() error   { return l.inner.Close() }
func (l *sniffingListener) Addr() net.Addr { return l.inner.Addr() }

type VHostHandler struct {
	mu     sync.RWMutex
	config *config.ServerConfig
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
	vh.config = newCfg
	vh.mu.Unlock()
	return nil
}

func (vh *VHostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	vh.mu.RLock()
	cfg := vh.config
	vh.mu.RUnlock()

	host := r.Host
	vhost, exists := cfg.VHosts[host]
	if !exists {
		vhost = cfg.VHosts["default"]
	}

	botCfg := botdetect.BotConfig{
		Enabled:       vhost.BotProtection.Enabled,
		BlockScanners: vhost.BotProtection.BlockScanners,
		BlockedAgents: vhost.BotProtection.BlockedAgents,
		AllowedAgents: vhost.BotProtection.AllowedAgents,
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vh.setSecurityHeaders(w, vhost)

		if !exists {
			vh.handleDefaultVHost(w, r)
			return
		}

		if vhost.Compression {
			compression.Compress(func(w http.ResponseWriter, r *http.Request) {
				vh.handleVHost(w, r, vhost)
			})(w, r)
			return
		}
		vh.handleVHost(w, r, vhost)
	})

	botHandler := botdetect.BotDetect(botCfg)(inner)

	security.RateLimit(
		vhost.Security.RateLimit.Requests,
		vhost.Security.RateLimit.Window,
	)(botHandler).ServeHTTP(w, r)
}

func (vh *VHostHandler) setSecurityHeaders(w http.ResponseWriter, vhost *config.VirtualHost) {
	w.Header().Set("X-Frame-Options", vhost.Security.Headers.FrameOptions)
	w.Header().Set("X-Content-Type-Options", vhost.Security.Headers.ContentType)
	w.Header().Set("X-XSS-Protection", vhost.Security.Headers.XSSProtection)
	w.Header().Set("Content-Security-Policy", vhost.Security.Headers.CSP)
	w.Header().Set("Strict-Transport-Security", vhost.Security.Headers.HSTS)
}

func (vh *VHostHandler) handleVHost(w http.ResponseWriter, r *http.Request, vhost *config.VirtualHost) {
	if vhost.FastCGI.Pass != "" {
		fastcgi.Handler(w, r, vhost.FastCGI.Pass, vhost.Root, vhost.FastCGI.Index)
		return
	}
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
	return "/usr/share/tinyproxy/static"
}

// configPath returns the active config file path: local first, then system.
func configPath() string {
	if _, err := os.Stat("config/vhosts.conf"); err == nil {
		return "config/vhosts.conf"
	}
	return "/etc/tinyproxy/vhosts.conf"
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

// runServer is the actual server process (used by the systemd service via "tinyproxy serve").
func runServer() {
	path := configPath()
	cfg, err := loadConfig(path)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	handler := &VHostHandler{config: cfg}

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
		}
	}()

	server := &http.Server{Handler: handler}

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
		if err := server.Serve(&sniffingListener{inner: tcpLn, tlsCfg: tlsCfg}); err != nil {
			log.Fatal(err)
		}
		return
	}

	// Production — one shared cert manager so HTTP-01 challenge tokens are visible
	// to both the port-80 handler and the port-443 TLS handshake.
	mgr := certmanager.NewManager(cfg)
	server.Addr = ":443"
	server.TLSConfig = mgr.TLSConfig()

	go func() {
		if err := http.ListenAndServe(":80", mgr.HTTPHandler(nil)); err != nil {
			log.Printf("HTTP listener: %v", err)
		}
	}()

	fmt.Printf("Production mode: Listening on %s\n", server.Addr)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}

func runSystemctl(action string) {
	cmd := exec.Command("systemctl", action, "tinyproxy")
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
	if err := syscall.Exec(path, []string{editor, "/etc/tinyproxy/vhosts.conf"}, os.Environ()); err != nil {
		log.Fatal(err)
	}
}

func runLogs() {
	cmd := exec.Command("journalctl", "-u", "tinyproxy", "-f", "--no-pager")
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

	assetName := fmt.Sprintf("tinyproxy_%s_%s_%s.%s", version, goos, goarch, ext)
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

	tmp, err := os.CreateTemp("", "tinyproxy-upgrade-*."+ext)
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
	mustRun("systemctl", "restart", "tinyproxy")
	log.Println("Upgrade complete.")
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
	default:
		fmt.Fprintf(os.Stderr, "Usage: tinyproxy {start|stop|restart|reload|status|config|logs|upgrade}\n")
		os.Exit(1)
	}
}
