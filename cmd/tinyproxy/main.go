package main

import (
    "fmt"
    "os"
    "net/http"
    "tinyproxy/internal/server/compression"
    "tinyproxy/internal/server/config"
    "tinyproxy/internal/server/proxy"
    "tinyproxy/internal/server/security"
    "tinyproxy/internal/server/security/certmanager"
)

type VHostHandler struct {
    config *config.ServerConfig
}

func (vh *VHostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    host := r.Host
    vhost, exists := vh.config.VHosts[host]
    if !exists {
        vhost = vh.config.VHosts["default"]
    }

    // Create rate limiter specific to this vhost
    rateLimitedHandler := security.RateLimit(
        vhost.Security.RateLimit.Requests,
        vhost.Security.RateLimit.Window,
    )(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Set security headers
        vh.setSecurityHeaders(w, vhost)

        // Select handler based on host
        handler := vh.handleVHost
        if !exists {
            handler = vh.handleDefaultVHost
        }

        // Apply compression if enabled
        if vhost.Compression {
            compression.Compress(handler)(w, r)
            return
        }
        handler(w, r)
    }))

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
        http.Handle("/", reverseProxy)
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
    rateLimitedHandler := security.RateLimit(
        config.VHosts["default"].Security.RateLimit.Requests,
        config.VHosts["default"].Security.RateLimit.Window,
    )(handler)
    
    // Base server config
    server := &http.Server{
        Handler: rateLimitedHandler,
    }

    if os.Getenv("ENV") == "dev" {
        server.Addr = ":8080"
        server.TLSConfig = security.SecureTLSConfig()
        fmt.Printf("Development mode: Listening on %s\n", server.Addr)
        if err := server.ListenAndServeTLS("certs/localhost+2.pem", "certs/localhost+2-key.pem"); err != nil {
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
