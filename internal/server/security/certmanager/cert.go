package certmanager

import (
    "net"
    "net/http"
    "crypto/tls"
    "golang.org/x/crypto/acme/autocert"
    "tinyproxy/internal/server/config"
)

func getServerIP() string {
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        return ""
    }
    for _, addr := range addrs {
        if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                return ipnet.IP.String()
            }
        }
    }
    return ""
}

func NewCertManager(config *config.ServerConfig) *autocert.Manager {
    domains := []string{getServerIP()}
    
    // Add configured domains from vhosts if any
    for domain := range config.VHosts {
        if domain != "default" {
            domains = append(domains, domain)
        }
    }

    return &autocert.Manager{
        Prompt:     autocert.AcceptTOS,
        Cache:      autocert.DirCache("certs"),
        HostPolicy: autocert.HostWhitelist(domains...),
    }
}

func GetHTTPHandler(config *config.ServerConfig) http.Handler {
    return NewCertManager(config).HTTPHandler(nil)
}

func GetTLSConfig(config *config.ServerConfig) *tls.Config {
    return NewCertManager(config).TLSConfig()
}
