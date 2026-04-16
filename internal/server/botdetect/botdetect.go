package botdetect

import (
	"net/http"
	"strings"
)

// BotConfig controls bot detection behaviour for a virtual host.
type BotConfig struct {
	Enabled       bool
	BlockScanners bool
	Honeypot      bool // serve convincing fake content instead of 403
	BlockedAgents []string
	AllowedAgents []string
	BlockedPaths  []string // operator-defined paths to block in addition to built-ins
}

// BotDetect returns middleware that inspects User-Agent and request path.
// Allowed bots (Googlebot etc.) pass through unconditionally.
// Blocked bots and scanner paths receive either a honeypot response (when
// cfg.Honeypot is true) or a plain 403.
func BotDetect(cfg BotConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			ua := r.Header.Get("User-Agent")

			// Allowed list wins — legitimate crawlers pass through.
			if isAllowedBot(ua) || containsAny(ua, cfg.AllowedAgents) {
				next.ServeHTTP(w, r)
				return
			}

			// Block by User-Agent.
			if isKnownBot(ua) || containsAny(ua, cfg.BlockedAgents) {
				Block(w, r, cfg.Honeypot)
				return
			}

			// Block by suspicious path.
			// r.URL.RawPath holds the original percent-encoded path (set only when
			// encoding is present); r.URL.Path is already decoded by the HTTP parser.
			// isSuspiciousPath calls url.PathUnescape internally, so it must receive
			// the raw (encoded) form to avoid double-decoding.
			rawPath := r.URL.RawPath
			if rawPath == "" {
				rawPath = r.URL.Path
			}
			if cfg.BlockScanners && isSuspiciousPath(rawPath) {
				Block(w, r, cfg.Honeypot)
				return
			}

			if isBlockedPath(rawPath, cfg.BlockedPaths) {
				Block(w, r, cfg.Honeypot)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Block either serves a honeypot response or a plain 403.
func Block(w http.ResponseWriter, r *http.Request, honeypot bool) {
	if honeypot {
		serveHoneypot(w, r)
		return
	}
	http.Error(w, "Forbidden", http.StatusForbidden)
}

// containsAny returns true if s contains any of the substrings in list (case-insensitive).
func containsAny(s string, list []string) bool {
	lower := strings.ToLower(s)
	for _, item := range list {
		if strings.Contains(lower, strings.ToLower(item)) {
			return true
		}
	}
	return false
}
