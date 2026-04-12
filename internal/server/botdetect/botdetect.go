package botdetect

import (
	"net/http"
	"strings"
)

// BotConfig controls bot detection behaviour for a virtual host.
type BotConfig struct {
	Enabled       bool
	BlockScanners bool
	BlockedAgents []string
	AllowedAgents []string
}

// BotDetect returns middleware that inspects User-Agent and request path.
// Allowed bots (Googlebot etc.) pass through unconditionally.
// Blocked bots and scanner paths receive 403.
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
				http.Error(w, "Forbidden", http.StatusForbidden)
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
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
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
