package proxy

import (
    "net/http"
    "net/http/httputil"
    "net/url"
)

type VHost struct {
    Domain     string
    TargetURL  string
    Socks5Addr string
}

type ReverseProxy struct {
    vhosts map[string]*httputil.ReverseProxy
}

func NewReverseProxy(vhosts []VHost) (*ReverseProxy, error) {
    proxyMap := make(map[string]*httputil.ReverseProxy)
    
    for _, vh := range vhosts {
        target, err := url.Parse(vh.TargetURL)
        if err != nil {
            return nil, err
        }
        
        proxy := httputil.NewSingleHostReverseProxy(target)
        proxyMap[vh.Domain] = proxy
    }

    return &ReverseProxy{
        vhosts: proxyMap,
    }, nil
}

// ServeHTTP implements the http.Handler interface
func (rp *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    host := r.Host
    
    proxy, exists := rp.vhosts[host]
    if !exists {
        http.Error(w, "Virtual host not found", http.StatusNotFound)
        return
    }

    proxy.ServeHTTP(w, r)
}
