package certmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"tinyproxy/internal/server/config"
	"tinyproxy/internal/server/security"
)

// Manager holds a single autocert.Manager shared between the HTTP challenge
// handler and the TLS config so they operate on the same token store.
type Manager struct {
	acm *autocert.Manager
}

func NewManager(cfg *config.ServerConfig, cacheDir string) *Manager {
	var domains []string
	for domain := range cfg.VHosts {
		if domain == "default" || domain == "default_ssl" {
			continue
		}
		// Strip any port suffix (e.g. "example.com:443" → "example.com")
		host := domain
		if i := strings.LastIndex(domain, ":"); i != -1 {
			host = domain[:i]
		}
		domains = append(domains, host)
	}

	acm := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(domains...),
	}
	return &Manager{acm: acm}
}

// HTTPHandler returns the ACME HTTP-01 challenge handler for port 80.
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return m.acm.HTTPHandler(fallback)
}

// TLSConfig returns a hardened TLS config wired to this manager's GetCertificate.
// A self-signed certificate is included as a fallback so that direct IP access
// (which ACME cannot provision a cert for) still negotiates TLS and serves the
// default page, albeit with a browser security warning.
func (m *Manager) TLSConfig() *tls.Config {
	tlsCfg := security.SecureTLSConfig()
	tlsCfg.GetCertificate = m.acm.GetCertificate

	if fallback, err := generateSelfSignedCert(); err == nil {
		tlsCfg.Certificates = []tls.Certificate{fallback}
	}

	return tlsCfg
}

// generateSelfSignedCert creates an in-memory ECDSA certificate covering
// localhost, 127.0.0.1, ::1, and all non-loopback IPs on this host.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				ips = append(ips, ipnet.IP)
			}
		}
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"tinyproxy"},
			CommonName:   "tinyproxy default",
		},
		DNSNames:              []string{"localhost"},
		IPAddresses:           ips,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
