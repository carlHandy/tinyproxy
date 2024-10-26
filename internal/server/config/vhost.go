package config

type VirtualHost struct {
    Hostname    string
    Port        int
    Root        string
    ProxyPass   string
    SSL         bool
    CertFile    string
    KeyFile     string
    Compression bool `yaml:"compression" default:"true"`
}

func NewVirtualHost() *VirtualHost {
    return &VirtualHost{
        Compression: true,
    }
}

type ServerConfig struct {
    VHosts map[string]*VirtualHost
}

func NewServerConfig() *ServerConfig {
    config := &ServerConfig{
        VHosts: make(map[string]*VirtualHost),
    }
    
    // Add default vhost
    config.VHosts["default"] = &VirtualHost{
        Hostname:    "_",
        Port:        80,
        Compression: true,
    }
    
    return config
}
