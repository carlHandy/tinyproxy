package dashboard

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	dashconfig "tinyproxy/internal/dashboard/config"
	"tinyproxy/internal/dashboard/logring"
	"tinyproxy/internal/dashboard/stats"
	"tinyproxy/internal/server/middleware"
)



// AuthMiddleware enforces HTTP Basic Auth with bcrypt password comparison.
type AuthMiddleware struct {
	username string
	hash     []byte
	limiter  *AuthLimiter
}

// NewAuthMiddleware creates an AuthMiddleware for the given username and bcrypt hash.
func NewAuthMiddleware(username string, hash []byte) *AuthMiddleware {
	return &AuthMiddleware{
		username: username,
		hash:     hash,
		limiter:  NewAuthLimiter(5),
	}
}

// Wrap returns next wrapped with Basic Auth enforcement.
func (a *AuthMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := remoteIP(r)
		if !a.limiter.Allow(ip) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != a.username || bcrypt.CompareHashAndPassword(a.hash, []byte(pass)) != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="tinyproxy dashboard"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func remoteIP(r *http.Request) string {
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}

// AuthLimiter tracks failed auth attempts per IP.
type AuthLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

// NewAuthLimiter creates a limiter allowing max failed attempts per minute per IP.
func NewAuthLimiter(max int) *AuthLimiter {
	return &AuthLimiter{
		hits:   make(map[string][]time.Time),
		max:    max,
		window: time.Minute,
	}
}

// Allow records a failed attempt for ip and returns false if the limit is exceeded.
func (l *AuthLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-l.window)
	hits := l.hits[ip]
	i := 0
	for ; i < len(hits) && hits[i].Before(cutoff); i++ {
	}
	hits = hits[i:]
	if len(hits) >= l.max {
		l.hits[ip] = hits
		return false
	}
	l.hits[ip] = append(hits, now)
	return true
}

// NewStatsHandler returns an http.Handler for GET /api/stats.
func NewStatsHandler(db *stats.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		window := time.Hour
		switch r.URL.Query().Get("window") {
		case "6h":
			window = 6 * time.Hour
		case "24h":
			window = 24 * time.Hour
		case "7d":
			window = 7 * 24 * time.Hour
		}
		result, err := db.QueryStats(window)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
}

// NewLogsHandler returns an http.Handler for GET /api/logs.
func NewLogsHandler(db *stats.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 || limit > 500 {
			limit = 100
		}
		lines, err := db.QueryLogs(before, limit, q.Get("vhost"), q.Get("level"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(lines)
	})
}

// NewLogsStreamHandler returns an http.Handler for GET /api/logs/stream (SSE).
func NewLogsStreamHandler(buf *logring.Buffer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "SSE not supported", http.StatusInternalServerError)
			return
		}
		levelFilter := r.URL.Query().Get("level")

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		sub := buf.Subscribe()
		defer buf.Unsubscribe(sub)

		for {
			select {
			case line, ok := <-sub:
				if !ok {
					return
				}
				if levelFilter != "" && line.Level != levelFilter {
					continue
				}
				data, _ := json.Marshal(line)
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
}

// Config holds dashboard runtime configuration.
type Config struct {
	Host       string
	Port       int
	CredsFile  string
	DBPath     string
	TLSCert    string
	TLSKey     string
	ConfigPath string
}

// Server is a self-contained admin dashboard HTTP server.
type Server struct {
	cfg    Config
	srv    *http.Server
	cancel context.CancelFunc
}

// New creates a Server. Returns an error if credentials cannot be loaded.
func New(cfg Config, db *stats.DB, logbuf *logring.Buffer, reloadCh chan<- struct{}) (*Server, error) {
    mux := http.NewServeMux()

    // Create a non-blocking helper function to trigger the reload.
    // The select with a default case ensures that if the channel is full 
    // or nothing is actively listening, the HTTP request won't hang forever.
    triggerReload := func() {
        if reloadCh != nil {
            select {
            case reloadCh <- struct{}{}:
            default:
            }
        }
    }

    mux.Handle("/api/stats", NewStatsHandler(db))
    mux.Handle("/api/logs", NewLogsHandler(db))
    mux.Handle("/api/logs/stream", NewLogsStreamHandler(logbuf))
    mux.Handle("/api/config", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case http.MethodGet:
            dashconfig.HandleGet(cfg.ConfigPath)(w, r)
        case http.MethodPut:
            // Pass the trigger function here instead of syscall.Kill
            dashconfig.HandlePut(cfg.ConfigPath, triggerReload)(w, r)
        default:
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        }
    }))
    mux.Handle("/api/config/validate", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        dashconfig.HandleValidate(cfg.ConfigPath)(w, r)
    }))

    // Pass the trigger function here as well
    RegisterUIHandlers(mux, cfg.ConfigPath, db, triggerReload)

	var handler http.Handler = middleware.Recovery(mux)

	if cfg.CredsFile != "" {
		username, hash, err := loadCreds(cfg.CredsFile)
		if err != nil {
			return nil, fmt.Errorf("dashboard: failed to load credentials: %w", err)
		}
		am := NewAuthMiddleware(username, hash)
		handler = am.Wrap(handler)
	}

	s := &Server{cfg: cfg}
	s.srv = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler: handler,
	}

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("dashboard: failed to load TLS cert: %w", err)
		}
		s.srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}
	return s, nil
}

// Start launches the dashboard server in a background goroutine.
func (s *Server) Start() {
	go func() {
		log.Printf("dashboard: listening on %s", s.srv.Addr)
		var err error
		if s.srv.TLSConfig != nil {
			err = s.srv.ListenAndServeTLS("", "")
		} else {
			err = s.srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Printf("dashboard: server error: %v", err)
		}
	}()
}

// Shutdown gracefully stops the dashboard server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

func loadCreds(path string) (username string, hash []byte, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	line := strings.TrimSpace(string(data))
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("invalid credentials file: expected username:bcrypt_hash on one line")
	}
	return parts[0], []byte(parts[1]), nil
}
