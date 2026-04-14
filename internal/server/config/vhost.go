package config

import (
    "time"
)

type SecurityConfig struct {
    Headers struct {
        FrameOptions   string
        ContentType    string 
        XSSProtection string 
        CSP           string 
        HSTS          string 
    }
    RateLimit struct {
        Enabled  bool
        Requests int           
        Window   time.Duration 
    }
    MaxBodySize int 
}

// BotProtectionConfig controls per-vhost bot detection settings.
type BotProtectionConfig struct {
    Enabled       bool
    BlockScanners bool
    Honeypot      bool     // serve convincing fake content instead of 
    BlockedAgents string
    AllowedAgents string
    BlockedPaths  string // operator-defined paths to block in addition to built-ins
}

type VirtualHost struct {
    Hostname    string
    Port        int
    Root        string
    ProxyPass   string
    SSL         bool
    CertFile    string
    KeyFile     string
    Compression bool
    Security    SecurityConfig
    BotProtection BotProtectionConfig
    ClientMaxBodySize int
    ReadTimeout     time.Duration
    WriteTimeout    time.Duration
    IdleTimeout     time.Duration
}
