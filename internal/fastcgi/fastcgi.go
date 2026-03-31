package fastcgi
 
import (
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
 
	fcgi "github.com/tomasen/fcgi_client"
)
 
// Handler connects to a FastCGI backend and proxies the request.
func Handler(w http.ResponseWriter, r *http.Request, pass string, root string, index string) {
	fcgiClient, err := fcgi.Dial("tcp", pass)
	if err != nil {
		slog.Error("fastcgi dial failed", "address", pass, "error", err)
		http.Error(w, "FastCGI connection error", http.StatusBadGateway)
		return
	}
	defer fcgiClient.Close()
 
	scriptName := r.URL.Path
	if scriptName == "/" || scriptName == "" {
		scriptName = "/" + index
	}
 
	env := map[string]string{
		"SCRIPT_FILENAME": filepath.Join(root, scriptName),
		"SCRIPT_NAME":     scriptName,
		"DOCUMENT_ROOT":   root,
		"REQUEST_METHOD":  r.Method,
		"QUERY_STRING":    r.URL.RawQuery,
		"REQUEST_URI":     r.RequestURI,
		"SERVER_PROTOCOL": r.Proto,
		"CONTENT_TYPE":    r.Header.Get("Content-Type"),
		"CONTENT_LENGTH":  strconv.FormatInt(r.ContentLength, 10),
		"REMOTE_ADDR":     r.RemoteAddr,
		"SERVER_NAME":     r.Host,
		"HTTP_HOST":       r.Host,
	}
 
	var resp *http.Response
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		resp, err = fcgiClient.Post(env, r.Header.Get("Content-Type"), r.Body, int(r.ContentLength))
	default:
		resp, err = fcgiClient.Get(env)
	}
	if err != nil {
		slog.Error("fastcgi request failed", "address", pass, "error", err)
		http.Error(w, "FastCGI processing error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
 
	// Copy response headers from FastCGI
	for key, vals := range resp.Header {
		for _, val := range vals {
			w.Header().Add(key, val)
		}
	}
	if resp.StatusCode != 0 && resp.StatusCode != http.StatusOK {
		w.WriteHeader(resp.StatusCode)
	}
 
	// Stream body
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return
			}
		}
		if readErr != nil {
			break
		}
	}
}