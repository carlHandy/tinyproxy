package loadbalancer

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
)

var (
	ErrNoBackends         = errors.New("no backends configured")
	ErrNoHealthyBackends  = errors.New("no healthy backends available")
)

// Backend represents a single upstream server.
type Backend struct {
	URL               string
	Weight            int
	alive             atomic.Bool
	activeConns       atomic.Int64
	consecutiveFails  atomic.Int32
	consecutivePasses atomic.Int32
}

// IsAlive reports whether the backend is considered healthy.
func (b *Backend) IsAlive() bool { return b.alive.Load() }

// SetAlive marks the backend as alive or dead.
func (b *Backend) SetAlive(v bool) { b.alive.Store(v) }

// ActiveConns returns the number of in-flight requests.
func (b *Backend) ActiveConns() int64 { return b.activeConns.Load() }

// LoadBalancer distributes requests across backends using a configurable strategy.
type LoadBalancer struct {
	mu          sync.RWMutex
	backends    []*Backend
	strategy    string
	cookieName  string
	roundRobinIdx uint64
	healthChecker *HealthChecker
}

// New creates a LoadBalancer from the given config and starts health checking.
func New(cfg LBConfig) (*LoadBalancer, error) {
	if len(cfg.Backends) == 0 {
		return nil, ErrNoBackends
	}

	backends := make([]*Backend, len(cfg.Backends))
	for i, bc := range cfg.Backends {
		w := bc.Weight
		if w <= 0 {
			w = 1
		}
		b := &Backend{URL: bc.URL, Weight: w}
		b.SetAlive(true)
		backends[i] = b
	}

	cookieName := cfg.CookieName
	if cookieName == "" {
		cookieName = "_tp_backend"
	}

	lb := &LoadBalancer{
		backends:   backends,
		strategy:   cfg.Strategy,
		cookieName: cookieName,
	}

	if cfg.HealthCheck.Enabled {
		lb.healthChecker = NewHealthChecker(backends, cfg.HealthCheck)
		lb.healthChecker.Start()
	}

	return lb, nil
}

// Next selects the next backend based on the configured strategy.
// For cookie-based affinity, it checks the request for an existing affinity cookie.
func (lb *LoadBalancer) Next(r *http.Request) (*Backend, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	alive := lb.aliveBackends()
	if len(alive) == 0 {
		return nil, ErrNoHealthyBackends
	}

	// Cookie-based sticky sessions: check for existing affinity cookie
	if lb.strategy == "cookie" || lb.strategy == "ip_hash" {
		if cookie, err := r.Cookie(lb.cookieName); err == nil {
			for _, b := range alive {
				if hashBackend(b.URL) == cookie.Value {
					return b, nil
				}
			}
			// Cookie pointed to a dead backend; fall through to re-assign
		}
	}

	switch lb.strategy {
	case "least_conn":
		return lb.leastConn(alive), nil
	case "ip_hash":
		return lb.ipHash(alive, clientIP(r)), nil
	case "weighted":
		return lb.weightedRoundRobin(alive), nil
	case "cookie":
		// First request (no cookie) → use round-robin to assign
		return lb.roundRobin(alive), nil
	default: // round_robin
		return lb.roundRobin(alive), nil
	}
}

// SetAffinityCookie writes the sticky-session cookie to the response.
// Should be called after Next() when using cookie strategy.
func (lb *LoadBalancer) SetAffinityCookie(w http.ResponseWriter, backend *Backend) {
	if lb.strategy != "cookie" && lb.strategy != "ip_hash" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     lb.cookieName,
		Value:    hashBackend(backend.URL),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400, // 24 hours
	})
}

// MarkDone decrements the active connection count for a backend.
func (lb *LoadBalancer) MarkDone(b *Backend) {
	b.activeConns.Add(-1)
}

// MarkActive increments the active connection count for a backend.
func (lb *LoadBalancer) MarkActive(b *Backend) {
	b.activeConns.Add(1)
}

// Stop shuts down the health checker.
func (lb *LoadBalancer) Stop() {
	if lb.healthChecker != nil {
		lb.healthChecker.Stop()
	}
}

// Backends returns a snapshot of the current backends for observability.
func (lb *LoadBalancer) Backends() []*Backend {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	out := make([]*Backend, len(lb.backends))
	copy(out, lb.backends)
	return out
}

// --- Strategy implementations ---

func (lb *LoadBalancer) roundRobin(alive []*Backend) *Backend {
	idx := atomic.AddUint64(&lb.roundRobinIdx, 1)
	return alive[idx%uint64(len(alive))]
}

func (lb *LoadBalancer) leastConn(alive []*Backend) *Backend {
	min := alive[0]
	for _, b := range alive[1:] {
		if b.ActiveConns() < min.ActiveConns() {
			min = b
		}
	}
	return min
}

func (lb *LoadBalancer) ipHash(alive []*Backend, ip string) *Backend {
	h := sha256.Sum256([]byte(ip))
	idx := binary.BigEndian.Uint64(h[:8]) % uint64(len(alive))
	return alive[idx]
}

func (lb *LoadBalancer) weightedRoundRobin(alive []*Backend) *Backend {
	totalWeight := 0
	for _, b := range alive {
		totalWeight += b.Weight
	}
	if totalWeight == 0 {
		return alive[0]
	}
	r := rand.Intn(totalWeight)
	for _, b := range alive {
		r -= b.Weight
		if r < 0 {
			return b
		}
	}
	return alive[len(alive)-1]
}

func (lb *LoadBalancer) aliveBackends() []*Backend {
	alive := make([]*Backend, 0, len(lb.backends))
	for _, b := range lb.backends {
		if b.IsAlive() {
			alive = append(alive, b)
		}
	}
	return alive
}

// hashBackend produces a short deterministic hash of a backend URL for cookie values.
func hashBackend(url string) string {
	h := sha256.Sum256([]byte(url))
	return fmt.Sprintf("%x", h[:8])
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}
