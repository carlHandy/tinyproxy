package config

import (
	"fmt"
	"net/url"
	"time"
)

// validStrategies enumerates the supported load-balancing strategies.
var validStrategies = map[string]bool{
	"round_robin": true,
	"least_conn":  true,
	"ip_hash":     true,
	"weighted":    true,
	"cookie":      true,
}

// Validate checks the parsed config for invalid or dangerous settings.
func (sc *ServerConfig) Validate() error {
	if len(sc.VHosts) == 0 {
		return fmt.Errorf("no virtual hosts configured")
	}

	for name, vh := range sc.VHosts {
		if name == "default" || name == "default_ssl" {
			continue
		}

		if vh.ProxyPass != "" {
			if _, err := url.Parse(vh.ProxyPass); err != nil {
				return fmt.Errorf("vhost %q: invalid proxy_pass URL: %w", name, err)
			}
		}

		if vh.Port < 0 || vh.Port > 65535 {
			return fmt.Errorf("vhost %q: invalid port %d", name, vh.Port)
		}

		if vh.Security.RateLimit.Requests < 0 {
			return fmt.Errorf("vhost %q: rate_limit requests must be >= 0", name)
		}

		if vh.Security.RateLimit.Window < 0 {
			return fmt.Errorf("vhost %q: rate_limit window must be >= 0", name)
		}

		if vh.Security.RateLimit.Requests > 0 && vh.Security.RateLimit.Window == 0 {
			vh.Security.RateLimit.Window = time.Minute
		}

		if vh.MaxBodySize < 0 {
			return fmt.Errorf("vhost %q: max_body_size must be >= 0", name)
		}

		if vh.SSL && (vh.CertFile == "" || vh.KeyFile == "") {
			return fmt.Errorf("vhost %q: SSL enabled but cert or key file missing", name)
		}

		// --- Cache validation ---
		if vh.Cache.Enabled {
			if vh.Cache.MaxSize <= 0 {
				return fmt.Errorf("vhost %q: cache max_size must be > 0", name)
			}
			if vh.Cache.DefaultTTL < 0 {
				return fmt.Errorf("vhost %q: cache default_ttl must be >= 0", name)
			}
		}

		// --- Upstream validation ---
		if len(vh.Upstream.Backends) > 0 {
			// proxy_pass and upstream are mutually exclusive
			if vh.ProxyPass != "" {
				return fmt.Errorf("vhost %q: proxy_pass and upstream are mutually exclusive", name)
			}

			if !validStrategies[vh.Upstream.Strategy] {
				return fmt.Errorf("vhost %q: unknown upstream strategy %q", name, vh.Upstream.Strategy)
			}

			for i, bc := range vh.Upstream.Backends {
				if _, err := url.Parse(bc.URL); err != nil {
					return fmt.Errorf("vhost %q: upstream backend[%d] invalid URL: %w", name, i, err)
				}
				if bc.Weight < 0 {
					return fmt.Errorf("vhost %q: upstream backend[%d] weight must be >= 0", name, i)
				}
			}

			hc := vh.Upstream.HealthCheck
			if hc.Enabled {
				if hc.Timeout >= hc.Interval {
					return fmt.Errorf("vhost %q: health_check timeout must be < interval", name)
				}
				if hc.FailThreshold <= 0 {
					return fmt.Errorf("vhost %q: health_check fail_threshold must be > 0", name)
				}
				if hc.PassThreshold <= 0 {
					return fmt.Errorf("vhost %q: health_check pass_threshold must be > 0", name)
				}
			}
		}
	}

	return nil
}

