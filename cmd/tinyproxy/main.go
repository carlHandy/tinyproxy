package main

import (
    "crypto/tls"
    "fmt"
    "net"
    "net/http"
    "os"
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
            // TLS ClientHello — wrap in TLS and let net/http handle the handshake.
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
    config *config.ServerConfig
}

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
func (vh *VHostHandler) setSecurityHeaders(w http.ResponseWriter, vhost *config.VirtualHost) {
    w.Header().Set("X-Frame-Options", vhost.Security.Headers.FrameOptions)
    w.Header().Set("X-Content-Type-Options", vhost.Security.Headers.ContentType)
    w.Header().Set("X-XSS-Protection", vhost.Security.Headers.XSSProtection)
    w.Header().Set("Content-Security-Policy", vhost.Security.Headers.CSP)
    w.Header().Set("Strict-Transport-Security", vhost.Security.Headers.HSTS)
}

func (vh *VHostHandler) handleVHost(w http.ResponseWriter, r *http.Request) {
    vhost := vh.config.VHosts[r.Host]
    
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
    w.Header().Set("Content-Type", "text/html")
    http.ServeFile(w, r, "static/index.html")
}

func main() {
    configFile, err := os.Open("config/vhosts.conf")
    if err != nil {
        panic(err)
    }
    defer configFile.Close()

    parser := config.NewParser(configFile)
    config, err := parser.Parse()
    if err != nil {
        panic(err)
    }

    handler := &VHostHandler{config: config}

    // Base server config
    server := &http.Server{
        Handler: handler,
    }

    if os.Getenv("ENV") == "dev" {
        tlsCfg := security.SecureTLSConfig()
        cert, err := tls.LoadX509KeyPair("certs/localhost+2.pem", "certs/localhost+2-key.pem")
        if err != nil {
            panic(err)
        }
        tlsCfg.Certificates = []tls.Certificate{cert}
        server.TLSConfig = tlsCfg

        tcpLn, err := net.Listen("tcp", ":8080")
        if err != nil {
            panic(err)
        }
        fmt.Println("Development mode: Listening on :8080 (HTTP redirects to HTTPS automatically)")
        if err := server.Serve(&sniffingListener{inner: tcpLn, tlsCfg: tlsCfg}); err != nil {
            panic(err)
        }
        return
    }

    // Production settings
    server.Addr = ":443"
    server.TLSConfig = certmanager.GetTLSConfig(config)
    
    // HTTP to HTTPS redirect
    go http.ListenAndServe(":80", certmanager.GetHTTPHandler(config))

    fmt.Printf("Production mode: Listening on %s\n", server.Addr)
    if err := server.ListenAndServeTLS("", ""); err != nil {
        panic(err)
    }
}
