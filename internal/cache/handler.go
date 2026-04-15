package cache

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// CacheStatus describes how the cache handled a request.
type CacheStatus string

const (
	CacheHit     CacheStatus = "HIT"
	CacheMiss    CacheStatus = "MISS"
	CacheBypass  CacheStatus = "BYPASS"
	CacheExpired CacheStatus = "EXPIRED"
	CacheRevalidated CacheStatus = "REVALIDATED"
)

// Handler returns HTTP middleware that provides transparent response caching.
// Only responses to cacheable methods with cacheable status codes are stored.
func Handler(cfg CacheConfig, c *Cache) func(http.Handler) http.Handler {
	methodSet := make(map[string]bool, len(cfg.Methods))
	for _, m := range cfg.Methods {
		methodSet[strings.ToUpper(m)] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only cache configured methods
			if !methodSet[r.Method] {
				next.ServeHTTP(w, r)
				return
			}

			// Check bypass header
			if cfg.BypassHeader != "" && r.Header.Get(cfg.BypassHeader) != "" {
				w.Header().Set("X-Cache", string(CacheBypass))
				next.ServeHTTP(w, r)
				return
			}

			// Client-directed no-cache
			if cc := r.Header.Get("Cache-Control"); strings.Contains(cc, "no-cache") || strings.Contains(cc, "no-store") {
				w.Header().Set("X-Cache", string(CacheBypass))
				next.ServeHTTP(w, r)
				return
			}

			key := cacheKey(r)

			// --- Try cache lookup ---
			entry, hit := c.Get(key)
			if hit {
				// Conditional request negotiation
				if handled := handleConditional(w, r, entry); handled {
					return
				}
				writeEntry(w, entry, CacheHit)
				return
			}

			// Stale-while-revalidate: serve stale and refresh in background
			if entry != nil && entry.IsExpired() && entry.IsStaleRevalidatable(cfg.StaleWhileRevalidate) {
				go revalidate(cfg, c, key, next, r)
				writeEntry(w, entry, CacheExpired)
				return
			}

			// --- Cache MISS: capture response from upstream ---
			rec := &responseRecorder{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
				body:           &bytes.Buffer{},
			}
			next.ServeHTTP(rec, r)

			// Store in cache if the response is cacheable
			if isCacheableStatus(rec.statusCode) {
				ttl := extractTTL(rec.Header(), cfg.DefaultTTL)
				if ttl > 0 && !hasNoCacheDirective(rec.Header()) {
					now := time.Now()
					ce := &CacheEntry{
						StatusCode: rec.statusCode,
						Header:     rec.Header().Clone(),
						Body:       rec.body.Bytes(),
						StoredAt:   now,
						ExpiresAt:  now.Add(ttl),
						ETag:       rec.Header().Get("ETag"),
						LastMod:    rec.Header().Get("Last-Modified"),
					}
					c.Set(key, ce)
				}
			}
			w.Header().Set("X-Cache", string(CacheMiss))
		})
	}
}

// cacheKey builds a deterministic cache key from the request.
func cacheKey(r *http.Request) string {
	return fmt.Sprintf("%s:%s:%s:%s", r.Method, r.Host, r.URL.Path, r.URL.RawQuery)
}

// handleConditional checks If-None-Match and If-Modified-Since headers.
// Returns true if a 304 was sent.
func handleConditional(w http.ResponseWriter, r *http.Request, entry *CacheEntry) bool {
	if inm := r.Header.Get("If-None-Match"); inm != "" && entry.ETag != "" {
		if inm == entry.ETag || inm == "*" {
			w.Header().Set("ETag", entry.ETag)
			w.Header().Set("X-Cache", string(CacheRevalidated))
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}
	if ims := r.Header.Get("If-Modified-Since"); ims != "" && entry.LastMod != "" {
		imsTime, err := http.ParseTime(ims)
		if err == nil {
			lmTime, lmErr := http.ParseTime(entry.LastMod)
			if lmErr == nil && !lmTime.After(imsTime) {
				w.Header().Set("Last-Modified", entry.LastMod)
				w.Header().Set("X-Cache", string(CacheRevalidated))
				w.WriteHeader(http.StatusNotModified)
				return true
			}
		}
	}
	return false
}

// writeEntry writes a cached entry to the response.
func writeEntry(w http.ResponseWriter, entry *CacheEntry, status CacheStatus) {
	for k, vals := range entry.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-Cache", string(status))
	age := int(time.Since(entry.StoredAt).Seconds())
	w.Header().Set("Age", strconv.Itoa(age))
	w.WriteHeader(entry.StatusCode)
	w.Write(entry.Body)
}

// revalidate fetches a fresh response in the background and updates the cache.
func revalidate(cfg CacheConfig, c *Cache, key string, next http.Handler, origReq *http.Request) {
	// Build a synthetic request (we can't reuse the original after the handler returns)
	req := origReq.Clone(origReq.Context())
	rec := &responseRecorder{
		ResponseWriter: &discardResponseWriter{header: make(http.Header)},
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
	}
	next.ServeHTTP(rec, req)
	if isCacheableStatus(rec.statusCode) {
		ttl := extractTTL(rec.Header(), cfg.DefaultTTL)
		if ttl > 0 {
			now := time.Now()
			c.Set(key, &CacheEntry{
				StatusCode: rec.statusCode,
				Header:     rec.Header().Clone(),
				Body:       rec.body.Bytes(),
				StoredAt:   now,
				ExpiresAt:  now.Add(ttl),
				ETag:       rec.Header().Get("ETag"),
				LastMod:    rec.Header().Get("Last-Modified"),
			})
			slog.Debug("cache revalidated", "key", key)
		}
	}
}

// extractTTL parses Cache-Control max-age / s-maxage, falling back to Expires
// header, then to defaultTTL.
func extractTTL(h http.Header, defaultTTL time.Duration) time.Duration {
	if cc := h.Get("Cache-Control"); cc != "" {
		// Prefer s-maxage (shared cache), then max-age
		if ttl := parseCCDirective(cc, "s-maxage"); ttl > 0 {
			return ttl
		}
		if ttl := parseCCDirective(cc, "max-age"); ttl > 0 {
			return ttl
		}
	}
	if exp := h.Get("Expires"); exp != "" {
		t, err := http.ParseTime(exp)
		if err == nil {
			ttl := time.Until(t)
			if ttl > 0 {
				return ttl
			}
		}
	}
	return defaultTTL
}

// parseCCDirective extracts a duration from a Cache-Control directive like
// "max-age=300" or "s-maxage=600".
func parseCCDirective(cc, directive string) time.Duration {
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), directive+"=") {
			valStr := strings.TrimPrefix(part, directive+"=")
			// Handle case-insensitive prefix
			if strings.Contains(valStr, "=") {
				valStr = part[len(directive)+1:]
			}
			secs, err := strconv.Atoi(strings.TrimSpace(valStr))
			if err == nil && secs > 0 {
				return time.Duration(secs) * time.Second
			}
		}
	}
	return 0
}

// hasNoCacheDirective returns true if the response must not be cached.
func hasNoCacheDirective(h http.Header) bool {
	cc := strings.ToLower(h.Get("Cache-Control"))
	return strings.Contains(cc, "no-store") || strings.Contains(cc, "private")
}

// isCacheableStatus returns true for status codes that are safe to cache.
func isCacheableStatus(code int) bool {
	switch code {
	case 200, 203, 204, 206, 300, 301, 304, 404, 410:
		return true
	}
	return false
}

// --- Response recorder ---

// responseRecorder captures the upstream response so we can store it in cache
// while simultaneously writing it to the client.
type responseRecorder struct {
	http.ResponseWriter
	statusCode  int
	body        *bytes.Buffer
	wroteHeader bool
}

func (r *responseRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

// discardResponseWriter is used during background revalidation where we
// don't have a real client connection.
type discardResponseWriter struct {
	header http.Header
}

func (d *discardResponseWriter) Header() http.Header         { return d.header }
func (d *discardResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardResponseWriter) WriteHeader(int)              {}
