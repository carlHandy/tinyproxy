package proxy

import (
    "net/http"
    "net/http/httputil"
    "net/url"
)

type ReverseProxy struct {
    target *url.URL
    proxy  *httputil.ReverseProxy
}

func NewReverseProxy(targetURL string) (*ReverseProxy, error) {
    target, err := url.Parse(targetURL)
    if err != nil {
        return nil, err
    }

    return &ReverseProxy{
        target: target,
        proxy:  httputil.NewSingleHostReverseProxy(target),
    }, nil
}

func (rp *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    r.URL.Host = rp.target.Host
    r.URL.Scheme = rp.target.Scheme
    r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
    r.Host = rp.target.Host

    rp.proxy.ServeHTTP(w, r)
}
