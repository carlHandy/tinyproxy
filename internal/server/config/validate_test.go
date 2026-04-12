package config

import (
	"testing"
	"time"
)

func makeMinimalVHost() *VirtualHost {
	return &VirtualHost{
		Hostname:    "example.com",
		Port:        80,
		Root:        "/var/www",
		MaxBodySize: 1024,
		Security: SecurityConfig{
			RateLimit: struct {
				Enabled  bool
				Requests int
				Window   time.Duration
			}{Requests: 10, Window: time.Minute},
		},
	}
}

func TestValidate_BotProtection_DisabledIsValid(t *testing.T) {
	sc := NewServerConfig()
	vh := makeMinimalVHost()
	vh.BotProtection.Enabled = false
	sc.VHosts["example.com"] = vh

	if err := sc.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_BotProtection_EnabledIsValid(t *testing.T) {
	sc := NewServerConfig()
	vh := makeMinimalVHost()
	vh.BotProtection.Enabled = true
	vh.BotProtection.BlockScanners = true
	vh.BotProtection.BlockedAgents = []string{"GPTBot", "MyBot"}
	vh.BotProtection.AllowedAgents = []string{"Googlebot"}
	sc.VHosts["example.com"] = vh

	if err := sc.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
