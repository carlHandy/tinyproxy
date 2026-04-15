package loadbalancer

import "time"

// LBConfig holds per-vhost upstream load balancing settings.
type LBConfig struct {
	Backends    []BackendConfig
	Strategy    string // "round_robin", "least_conn", "ip_hash", "weighted", "cookie"
	CookieName  string // session-affinity cookie name (default "_tp_backend")
	HealthCheck HealthCheckConfig
}

// BackendConfig describes a single upstream backend server.
type BackendConfig struct {
	URL    string
	Weight int // relative weight for weighted round-robin (default 1)
}

// HealthCheckConfig controls active health probing of backends.
type HealthCheckConfig struct {
	Enabled       bool
	Path          string        // HTTP path to probe (default "/")
	Interval      time.Duration // time between probes (default 10s)
	Timeout       time.Duration // per-probe timeout (default 5s)
	FailThreshold int           // consecutive failures before marking down (default 3)
	PassThreshold int           // consecutive passes before marking up (default 2)
}

// DefaultLBConfig returns an LBConfig with sensible defaults.
func DefaultLBConfig() LBConfig {
	return LBConfig{
		Strategy:   "round_robin",
		CookieName: "_tp_backend",
		HealthCheck: HealthCheckConfig{
			Enabled:       true,
			Path:          "/",
			Interval:      10 * time.Second,
			Timeout:       5 * time.Second,
			FailThreshold: 3,
			PassThreshold: 2,
		},
	}
}
