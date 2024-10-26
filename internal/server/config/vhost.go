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
        Requests int           
        Window   time.Duration 
        Enabled  bool          
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
    // Add SOCKS5 configuration
    SOCKS5 struct {
        Enabled  bool   
        Address  string 
        Username string 
        Password string 
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
                CSP:           "default-src 'self'",
                HSTS:          "max-age=31536000; includeSubDomains",
            },
            RateLimit: struct {
                Requests int           
                Window   time.Duration
                Enabled  bool         
            }{
                Enabled:  true,
                Requests: 100,
                Window:   time.Minute,
            },
            MaxBodySize: 10 << 20, // 10MB default max body size
        },
        SOCKS5: struct {
            Enabled  bool   
            Address  string 
            Username string 
            Password string 
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
                Requests int           
                Window   time.Duration 
                Enabled  bool          
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