package security

import (
    "net"
    "net/http"
    "sync"
    "time"
    "golang.org/x/time/rate"
)

// ipLimiter tracks per-IP rate limiters with automatic cleanup of stale entries.
type ipLimiter struct {
	mu       sync.Mutex
	limiters map[string]*limiterEntry
	rate     rate.Limit
	burst    int
}
 
type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPLimiter(requests int, window time.Duration) *ipLimiter {
	ipl := &ipLimiter{
		limiters: make(map[string]*limiterEntry),
		rate:     rate.Every(window / time.Duration(requests)),
		burst:    requests,
	}
	// Evict stale entries every 3 minutes to prevent memory leak
	go ipl.cleanup(3 * time.Minute)
	return ipl
}
 
func (ipl *ipLimiter) getLimiter(ip string) *rate.Limiter {
	ipl.mu.Lock()
	defer ipl.mu.Unlock()
 
	entry, exists := ipl.limiters[ip]
	if !exists {
		limiter := rate.NewLimiter(ipl.rate, ipl.burst)
		ipl.limiters[ip] = &limiterEntry{limiter: limiter, lastSeen: time.Now()}
		return limiter
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}
 
func (ipl *ipLimiter) cleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		ipl.mu.Lock()
		for ip, entry := range ipl.limiters {
			if time.Since(entry.lastSeen) > 5*time.Minute {
				delete(ipl.limiters, ip)
			}
		}
		ipl.mu.Unlock()
	}
}

// RateLimit returns middleware that enforces per-IP rate limiting.
func RateLimit(requests int, window time.Duration) func(http.Handler) http.Handler {
	ipl := newIPLimiter(requests, window)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}
			// Trust X-Forwarded-For if behind a reverse proxy
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				ip = forwarded
			}
			if !ipl.getLimiter(ip).Allow() {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
