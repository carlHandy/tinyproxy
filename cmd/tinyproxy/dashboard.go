package main

import (
	"flag"
	"fmt"

	"tinyproxy/internal/server/config"
)

// DashboardConfig holds the CLI flags for the admin dashboard.
type DashboardConfig struct {
	Enabled bool
	Host    string
	Port    int
	Creds   string
	DBPath  string
	TLSCert string
	TLSKey  string
}

// registerDashboardFlags binds dashboard flags to fs.
func registerDashboardFlags(fs *flag.FlagSet, dc *DashboardConfig) {
	fs.BoolVar(&dc.Enabled, "enable-dashboard", false, "enable the admin dashboard")
	fs.StringVar(&dc.Host, "dashboard-host", "127.0.0.1", "dashboard listen address")
	fs.IntVar(&dc.Port, "dashboard-port", 9000, "dashboard listen port")
	fs.StringVar(&dc.Creds, "dashboard-creds", "", "path to credentials file (username:bcrypt_hash)")
	fs.StringVar(&dc.DBPath, "dashboard-db", "dashboard.db", "path to the dashboard SQLite database")
	fs.StringVar(&dc.TLSCert, "dashboard-cert", "", "TLS certificate for the dashboard (optional)")
	fs.StringVar(&dc.TLSKey, "dashboard-key", "", "TLS key for the dashboard (optional)")
}

// validateDashboardConfig returns an error if the dashboard config is invalid.
func validateDashboardConfig(dc DashboardConfig, cfg *config.ServerConfig) error {
	if !dc.Enabled {
		return nil
	}
	if dc.DBPath == "" {
		return fmt.Errorf("--dashboard-db is required when dashboard is enabled")
	}
	if (dc.TLSCert == "") != (dc.TLSKey == "") {
		return fmt.Errorf("--dashboard-cert and --dashboard-key must be set together")
	}
	if dc.Host != "127.0.0.1" && dc.Host != "::1" && dc.Creds == "" {
		return fmt.Errorf("non-localhost dashboard requires --dashboard-creds")
	}
	for hostname, vh := range cfg.VHosts {
		if vh.Port == dc.Port {
			return fmt.Errorf("port %d conflicts with vhost %q", dc.Port, hostname)
		}
	}
	return nil
}
