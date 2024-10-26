package config

import (
    "time"
)

type SecurityConfig struct {
    Headers struct {
        FrameOptions   string `yaml:"frame_options"`
        ContentType    string `yaml:"content_type"`
        XSSProtection string `yaml:"xss_protection"`
        CSP           string `yaml:"csp"`
        HSTS          string `yaml:"hsts"`
    } `yaml:"headers"`
    RateLimit struct {
        Requests int           `yaml:"requests"`
        Window   time.Duration `yaml:"window"`
        Enabled  bool          `yaml:"enabled"`
    } `yaml:"rate_limit"`
    MaxBodySize int64 `yaml:"max_body_size"`
}

type VirtualHost struct {
    Hostname    string
    Port        int
    Root        string
    ProxyPass   string
    SSL         bool
    CertFile    string
    KeyFile     string
    Compression bool `yaml:"compression" default:"true"`
    Security    SecurityConfig `yaml:"security"`
    // Add SOCKS5 configuration
    SOCKS5 struct {
        Enabled  bool   `yaml:"enabled"`
        Address  string `yaml:"address"`
        Username string `yaml:"username"`
        Password string `yaml:"password"`
    } `yaml:"socks5"`
}

func NewVirtualHost() *VirtualHost {
    vh := &VirtualHost{
        Compression: true,
        Security: SecurityConfig{
            Headers: struct {
                FrameOptions   string `yaml:"frame_options"`
                ContentType    string `yaml:"content_type"`
                XSSProtection string `yaml:"xss_protection"`
                CSP           string `yaml:"csp"`
                HSTS          string `yaml:"hsts"`
            }{
                FrameOptions:   "SAMEORIGIN",
                ContentType:    "nosniff",
                XSSProtection: "1; mode=block",
                CSP:           "default-src 'self'",
                HSTS:          "max-age=31536000; includeSubDomains",
            },
            RateLimit: struct {
                Requests int           `yaml:"requests"`
                Window   time.Duration `yaml:"window"`
                Enabled  bool          `yaml:"enabled"`
            }{
                Enabled:  true,
                Requests: 100,
                Window:   time.Minute,
            },
            MaxBodySize: 10 << 20, // 10MB default max body size
        },
        SOCKS5: struct {
            Enabled  bool   `yaml:"enabled"`
            Address  string `yaml:"address"`
            Username string `yaml:"username"`
            Password string `yaml:"password"`
        }{
            Enabled:  false,
            Address:  "127.0.0.1:1080",
            Username: "",
            Password: "",
        },
    }
    return vh
}

type ServerConfig struct {
    VHosts map[string]*VirtualHost
}

func NewServerConfig() *ServerConfig {
    config := &ServerConfig{
        VHosts: make(map[string]*VirtualHost),
    }
    
    // Add default vhost for both HTTP and HTTPS
    defaultVHost := &VirtualHost{
        Hostname:    "_",
        Port:        80, // Will handle both 80 and 443
        Compression: true,
        Security: SecurityConfig{
            Headers: struct {
                FrameOptions   string `yaml:"frame_options"`
                ContentType    string `yaml:"content_type"`
                XSSProtection string `yaml:"xss_protection"`
                CSP           string `yaml:"csp"`
                HSTS          string `yaml:"hsts"`
            }{
                FrameOptions:   "SAMEORIGIN",
                ContentType:    "nosniff",
                XSSProtection: "1; mode=block",
                CSP:           "default-src 'self'",
                HSTS:          "max-age=31536000; includeSubDomains",
            },
            RateLimit: struct {
                Requests int           `yaml:"requests"`
                Window   time.Duration `yaml:"window"`
                Enabled  bool          `yaml:"enabled"`
            }{
                Enabled:  true,
                Requests: 100,
                Window:   time.Minute,
            },
            MaxBodySize: 10 << 20,
        },
    }
    
    // Add the same vhost config for both default hostnames
    config.VHosts["default"] = defaultVHost
    config.VHosts["default_ssl"] = defaultVHost
    
    return config
}