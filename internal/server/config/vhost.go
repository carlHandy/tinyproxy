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
    MaxBodySize int64 
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
    MaxBodySize int64
    // Add SOCKS5 configuration
    SOCKS5 struct {
        Enabled  bool   
        Address  string 
        Username string 
        Password string 
    }
    FastCGI struct {
        Enabled  bool
        Pass     string // e.g. "127.0.0.1:9000"
        Index    string // e.g. "index.php"
        Params   map[string]string
    }
}

func NewVirtualHost() *VirtualHost {
    vh := &VirtualHost{
        Compression: true,
        Security: SecurityConfig{
            Headers: struct {
                FrameOptions   string 
                ContentType    string 
                XSSProtection string 
                CSP           string 
                HSTS          string 
            }{
                FrameOptions:   "SAMEORIGIN",
                ContentType:    "nosniff",
                XSSProtection: "1; mode=block",
                CSP:           "",
                HSTS:          "max-age=31536000; includeSubDomains",
            },
            RateLimit: struct {
                Enabled  bool
                Requests int           
                Window   time.Duration
            }{
                Enabled:  true,
                Requests: 100,
                Window:   time.Minute,
            },
        },
        MaxBodySize: 10 << 20, // 10MB default max body size

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
        Root: "static",
        Security: SecurityConfig{
            Headers: struct {
                FrameOptions   string 
                ContentType    string 
                XSSProtection string 
                CSP           string 
                HSTS          string 
            }{
                FrameOptions:   "SAMEORIGIN",
                ContentType:    "nosniff",
                XSSProtection: "1; mode=block",
                CSP:           "default-src 'self'",
                HSTS:          "max-age=31536000; includeSubDomains",
            },
            RateLimit: struct {
                Enabled  bool
                Requests int           
                Window   time.Duration 
            }{
                Enabled:  true,
                Requests: 100,
                Window:   time.Minute,
            },
            MaxBodySize: 10 << 20,
        },
        SOCKS5: struct {
            Enabled  bool
            Address  string 
            Username string 
            Password string 
        }{
            Enabled:  true,
            Address:  "127.0.0.1:1080",
            Username: "",
            Password: "",
        },
    }
    
    // Add the same vhost config for both default hostnames
    config.VHosts["default"] = defaultVHost
    config.VHosts["default_ssl"] = defaultVHost
    
    return config
}