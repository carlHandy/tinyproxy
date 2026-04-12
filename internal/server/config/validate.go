package config

import (
	"fmt"
	"net/url"
	"time"
)

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
	}

	return nil
}
