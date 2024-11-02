package fastcgi

import (
    "net/http"
    "path/filepath"
    "io"
    fcgi "github.com/tomasen/fcgi_client"
)

func Handler(w http.ResponseWriter, r *http.Request, pass string, root string, index string) {
    fcgiClient, err := fcgi.Dial("tcp", pass)
    if err != nil {
        http.Error(w, "FastCGI connection error", http.StatusBadGateway)
        return
    }
    defer fcgiClient.Close()

    env := map[string]string{
        "SCRIPT_FILENAME": filepath.Join(root, index),
        "DOCUMENT_ROOT":   root,
        "REQUEST_METHOD":  r.Method,
        "QUERY_STRING":    r.URL.RawQuery,
    }

    resp, err := fcgiClient.Get(env)
    if err != nil {
        http.Error(w, "FastCGI processing error", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()

    io.Copy(w, resp.Body)
}
