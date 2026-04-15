package cache

import "time"

// CacheConfig holds per-vhost caching settings parsed from the config DSL.
type CacheConfig struct {
	Enabled              bool
	MaxSize              int64         // maximum cache size in bytes (default 256 MB)
	DefaultTTL           time.Duration // fallback TTL when response has no Cache-Control (default 5m)
	Methods              []string      // cacheable HTTP methods (default GET, HEAD)
	BypassHeader         string        // if this request header is set, skip cache (e.g. "X-Cache-Bypass")
	StaleWhileRevalidate time.Duration // serve stale content while refreshing in background
}

// DefaultCacheConfig returns a CacheConfig with sensible production defaults.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		Enabled:              false,
		MaxSize:              256 << 20, // 256 MB
		DefaultTTL:           5 * time.Minute,
		Methods:              []string{"GET", "HEAD"},
		BypassHeader:         "",
		StaleWhileRevalidate: 0,
	}
}
