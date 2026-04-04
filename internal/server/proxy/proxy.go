package proxy
 
import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
 
	"golang.org/x/net/proxy"
)
 
type VHost struct {
	Domain        string
	TargetURL     string
	Socks5Addr    string
	Socks5User    string
	Socks5Pass    string
}
 
type ReverseProxy struct {
	vhosts map[string]*httputil.ReverseProxy
}
 
// NewReverseProxy creates cached reverse proxy instances with production-grade transport settings.
// Inspired by nginx upstream keepalive and Traefik's forwardingTimeouts.
func NewReverseProxy(vhosts []VHost) (*ReverseProxy, error) {
	proxyMap := make(map[string]*httputil.ReverseProxy)
 
	for _, vh := range vhosts {
		target, err := url.Parse(vh.TargetURL)
		if err != nil {
			return nil, err
		}
 
		transport, err := buildTransport(vh)
		if err != nil {
			return nil, err
		}
 
		p := httputil.NewSingleHostReverseProxy(target)
		p.Transport = transport
		p.ErrorHandler = proxyErrorHandler
 
		// Rewrite request headers like nginx proxy_set_header
		originalDirector := p.Director
		p.Director = func(req *http.Request) {
			originalDirector(req)
			// Preserve original host for backends that need it
			req.Header.Set("X-Forwarded-Host", req.Host)
			req.Header.Set("X-Forwarded-Proto", schemeFromRequest(req))
			if ip, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
				req.Header.Set("X-Real-IP", ip)
			}
		}
 
		proxyMap[vh.Domain] = p
	}
 
	return &ReverseProxy{vhosts: proxyMap}, nil
}
 
func buildTransport(vh VHost) (http.RoundTripper, error) {
	// Connection pool and timeout settings mirroring nginx/traefik defaults
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
 
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:  10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ForceAttemptHTTP2:     true,
	}
 
	// Wire SOCKS5 transport if configured
	if vh.Socks5Addr != "" {
		var auth *proxy.Auth
		if vh.Socks5User != "" {
			auth = &proxy.Auth{
				User:     vh.Socks5User,
				Password: vh.Socks5Pass,
			}
		}
		socksDialer, err := proxy.SOCKS5("tcp", vh.Socks5Addr, auth, proxy.Direct)
		if err != nil {
			return nil, err
		}
		if ctxDialer, ok := socksDialer.(proxy.ContextDialer); ok {
			transport.DialContext = ctxDialer.DialContext
		} else {
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return socksDialer.Dial(network, addr)
			}
		}
	}
 
	return transport, nil
}
 
func proxyErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("proxy error",
		"host", r.Host,
		"path", r.URL.Path,
		"error", err,
	)
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
}
 
func schemeFromRequest(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
 
// ServeHTTP implements the http.Handler interface.
func (rp *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
 
	p, exists := rp.vhosts[host]
	if !exists {
		http.Error(w, "Virtual host not found", http.StatusNotFound)
		return
	}
 
	p.ServeHTTP(w, r)
}