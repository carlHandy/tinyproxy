package main

import (
    "fmt"
    "net"
    "net/http"
    "tinyproxy/internal/server/compression"
    "tinyproxy/internal/server/config"
    "tinyproxy/internal/server/proxy"
)

type VHostHandler struct {
    config *config.ServerConfig
}

func (vh *VHostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    host := r.Host
    vhost, exists := vh.config.VHosts[host]
    if !exists {
        // Use default vhost for unmatched domains
        vhost = vh.config.VHosts["default"]
        w.Header().Set("Content-Type", "text/html")
        fmt.Fprintf(w, "<h1>Welcome to TinyProxy</h1><p>Your server is running successfully!</p>")
        return
    }
    
    if vhost.Compression {
        compression.Compress(vh.handleVHost)(w, r)
        return
    }
    vh.handleVHost(w, r)
}
func (vh *VHostHandler) handleVHost(w http.ResponseWriter, r *http.Request) {
    vhost := vh.config.VHosts[r.Host]
    if vhost.ProxyPass != "" {
        proxy, err := proxy.NewReverseProxy(vhost.ProxyPass)
        if err != nil {
            http.Error(w, "Proxy configuration error", http.StatusInternalServerError)
            return
        }
        proxy.ServeHTTP(w, r)
        return
    }
    http.FileServer(http.Dir(vhost.Root)).ServeHTTP(w, r)
}

func main() {
    config, err := config.LoadConfig("config/vhosts.yaml")
    if err != nil {
        panic(err)
    }

    handler := &VHostHandler{config: config}
    server := &http.Server{
        Addr:    ":8080",
        Handler: handler,
    }

    ln, err := net.Listen("tcp", server.Addr)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Listening on %s\n", server.Addr)
    server.Serve(ln)
}
