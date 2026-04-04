package certmanager

import (
	"crypto/tls"
	"net"
	"net/http"
 
	"golang.org/x/crypto/acme/autocert"
	"tinyproxy/internal/server/config"
	"tinyproxy/internal/server/security"
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

func NewCertManager(cfg *config.ServerConfig) *autocert.Manager {
	var domains []string
	if ip := getServerIP(); ip != "" {
		domains = append(domains, ip)
	}
 
	for domain := range cfg.VHosts {
		if domain != "default" && domain != "default_ssl" {
			domains = append(domains, domain)
		}
	}
 
	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache("certs"),
		HostPolicy: autocert.HostWhitelist(domains...),
	}
}

func GetHTTPHandler(cfg *config.ServerConfig) http.Handler {
	return NewCertManager(cfg).HTTPHandler(nil)
}

// GetTLSConfig returns a TLS config that combines autocert with hardened cipher/protocol settings.
func GetTLSConfig(cfg *config.ServerConfig) *tls.Config {
	certManager := NewCertManager(cfg)
	tlsCfg := security.SecureTLSConfig()
	tlsCfg.GetCertificate = certManager.GetCertificate
	return tlsCfg
}
