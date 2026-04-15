package config

import (
    "bufio"
    "fmt"
    "io"
    "strconv"
    "strings"
    "time"

    "tinyproxy/internal/loadbalancer"
)

type Parser struct {
    scanner *bufio.Scanner
    line    int
    config  *ServerConfig
    currentVHost *VirtualHost
}

func NewParser(reader io.Reader) *Parser {
    return &Parser{
        scanner: bufio.NewScanner(reader),
        config:  NewServerConfig(),
    }
}

func (p *Parser) Parse() (*ServerConfig, error) {
    for p.scanner.Scan() {
        p.line++
        line := strings.TrimSpace(p.scanner.Text())
        
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        
        // Check for vhosts block
        if line == "vhosts {" {
            if err := p.parseVhosts(); err != nil {
                return nil, fmt.Errorf("line %d: %v", p.line, err)
            }
            continue
        }
        
        return nil, fmt.Errorf("line %d: expected vhosts block", p.line)
    }
    
    return p.config, nil
}

func (p *Parser) parseVhosts() error {
    for p.scanner.Scan() {
        p.line++
        line := strings.TrimSpace(p.scanner.Text())
        
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        
        if line == "}" {
            return nil
        }
        
        if strings.HasSuffix(line, "{") {
            domain := strings.TrimSpace(strings.TrimSuffix(line, "{"))
            p.currentVHost = NewVirtualHost()
            p.currentVHost.Hostname = domain
            
            if err := p.parseVHostBlock(); err != nil {
                return err
            }
            
            p.config.VHosts[domain] = p.currentVHost
        }
    }
    return nil
}

func (p *Parser) parseVHostBlock() error {
    for p.scanner.Scan() {
        p.line++
        line := strings.TrimSpace(p.scanner.Text())
        
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        
        if line == "}" {
            return nil
        }
        
        if err := p.parseLine(line); err != nil {
            return err
        }
    }
    return nil
}

func (p *Parser) parseLine(line string) error {
    parts := strings.Fields(line)
    if len(parts) < 2 {
        return nil
    }

    switch parts[0] {
    case "port":
        port, err := strconv.Atoi(parts[1])
        if err != nil {
            return err
        }
        p.currentVHost.Port = port
    case "proxy_pass":
        p.currentVHost.ProxyPass = parts[1]
    case "root":
        p.currentVHost.Root = parts[1]
    case "ssl":
        return p.parseSSL()
    case "security":
        return p.parseSecurity()
    case "socks5":
        return p.parseSocks5()
    case "fastcgi":
        return p.parseFastCGI()
    case "bot_protection":
        return p.parseBotProtection()
    case "cache":
        return p.parseCache()
    case "upstream":
        return p.parseUpstream()
    }

    return nil
}

func (p *Parser) parseFastCGI() error {
    p.currentVHost.FastCGI.Enabled = p.currentVHost.FastCGI.Pass != ""
    p.currentVHost.FastCGI.Params = make(map[string]string)
    for p.scanner.Scan() {
        p.line++
        line := strings.TrimSpace(p.scanner.Text())
        
        if line == "}" {
            return nil
        }
        
        parts := strings.Fields(line)
        if len(parts) < 2 {
            continue
        }
        
        switch parts[0] {
        case "pass":
            p.currentVHost.FastCGI.Pass = parts[1]
        case "index":
            p.currentVHost.FastCGI.Index = parts[1]
        case "param":
            if len(parts) >= 3 {
                p.currentVHost.FastCGI.Params[parts[1]] = parts[2]
            }
        }
    }
    return nil
}

func (p *Parser) parseSSL() error {
    for p.scanner.Scan() {
        p.line++
        line := strings.TrimSpace(p.scanner.Text())
        
        if line == "}" {
            return nil
        }
        
        parts := strings.Fields(line)
        if len(parts) < 2 {
            continue
        }
        
        switch parts[0] {
        case "cert":
            p.currentVHost.CertFile = parts[1]
            p.currentVHost.SSL = true
        case "key":
            p.currentVHost.KeyFile = parts[1]
            p.currentVHost.SSL = true
        }
    }
    return nil
}

func (p *Parser) parseSecurity() error {
    for p.scanner.Scan() {
        p.line++
        line := strings.TrimSpace(p.scanner.Text())
        
        if line == "}" {
            return nil
        }
        
        if strings.HasSuffix(line, "{") {
            directive := strings.TrimSpace(strings.TrimSuffix(line, "{"))
            if directive == "rate_limit" {
                if err := p.parseRateLimit(); err != nil {
                    return err
                }
                continue
            }
        }
        
        parts := strings.Fields(line)
        if len(parts) < 2 {
            continue
        }
        
        switch parts[0] {
        case "frame_options":
            p.currentVHost.Security.Headers.FrameOptions = parts[1]
        case "content_type":
            p.currentVHost.Security.Headers.ContentType = parts[1]
        case "xss_protection":
            p.currentVHost.Security.Headers.XSSProtection = strings.Join(parts[1:], " ")
        case "csp":
            p.currentVHost.Security.Headers.CSP = strings.Join(parts[1:], " ")
        case "hsts":
            p.currentVHost.Security.Headers.HSTS = strings.Join(parts[1:], " ")
        }
    }
    return nil
}

func (p *Parser) parseRateLimit() error {
    for p.scanner.Scan() {
        p.line++
        line := strings.TrimSpace(p.scanner.Text())
        
        if line == "}" {
            return nil
        }
        
        parts := strings.Fields(line)
        if len(parts) < 2 {
            continue
        }
        
        switch parts[0] {
        case "requests":
            requests, err := strconv.Atoi(parts[1])
            if err != nil {
                return err
            }
            p.currentVHost.Security.RateLimit.Requests = requests
        case "window":
            window, err := time.ParseDuration(parts[1])
            if err != nil {
                return err
            }
            p.currentVHost.Security.RateLimit.Window = window
        case "enabled":
            p.currentVHost.Security.RateLimit.Enabled = p.currentVHost.Security.RateLimit.Requests != 0
        }
    }
    return nil
}

func (p *Parser) parseBotProtection() error {
    for p.scanner.Scan() {
        p.line++
        line := strings.TrimSpace(p.scanner.Text())

        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        if line == "}" {
            return nil
        }

        parts := strings.Fields(line)
        if len(parts) < 2 {
            continue
        }

        switch parts[0] {
        case "enabled":
            p.currentVHost.BotProtection.Enabled = parts[1] == "true"
        case "block_scanners":
            p.currentVHost.BotProtection.BlockScanners = parts[1] == "true"
        case "honeypot":
            p.currentVHost.BotProtection.Honeypot = parts[1] == "true"
        case "block":
            p.currentVHost.BotProtection.BlockedAgents = append(
                p.currentVHost.BotProtection.BlockedAgents, parts[1])
        case "block_path":
            p.currentVHost.BotProtection.BlockedPaths = append(
                p.currentVHost.BotProtection.BlockedPaths, parts[1])
        case "allow":
            p.currentVHost.BotProtection.AllowedAgents = append(
                p.currentVHost.BotProtection.AllowedAgents, parts[1])
        }
    }
    return nil
}

func (p *Parser) parseSocks5() error {
    for p.scanner.Scan() {
        p.line++
        line := strings.TrimSpace(p.scanner.Text())
        
        if line == "}" {
            return nil
        }
        
        parts := strings.Fields(line)
        if len(parts) < 2 {
            continue
        }
        
        switch parts[0] {
        case "enabled":
            p.currentVHost.SOCKS5.Enabled = parts[1] == "true"
        case "address":
            p.currentVHost.SOCKS5.Address = parts[1]
        case "username":
            p.currentVHost.SOCKS5.Username = parts[1]
        case "password":
            p.currentVHost.SOCKS5.Password = parts[1]
        }
    }
    return nil
}

func (p *Parser) parseCache() error {
    for p.scanner.Scan() {
        p.line++
        line := strings.TrimSpace(p.scanner.Text())

        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        if line == "}" {
            return nil
        }

        parts := strings.Fields(line)
        if len(parts) < 2 {
            continue
        }

        switch parts[0] {
        case "enabled":
            p.currentVHost.Cache.Enabled = parts[1] == "true"
        case "max_size":
            size, err := parseByteSize(parts[1])
            if err != nil {
                return fmt.Errorf("cache max_size: %w", err)
            }
            p.currentVHost.Cache.MaxSize = size
        case "default_ttl":
            d, err := time.ParseDuration(parts[1])
            if err != nil {
                return fmt.Errorf("cache default_ttl: %w", err)
            }
            p.currentVHost.Cache.DefaultTTL = d
        case "bypass_header":
            p.currentVHost.Cache.BypassHeader = parts[1]
        case "stale_while_revalidate":
            d, err := time.ParseDuration(parts[1])
            if err != nil {
                return fmt.Errorf("cache stale_while_revalidate: %w", err)
            }
            p.currentVHost.Cache.StaleWhileRevalidate = d
        }
    }
    return nil
}

func (p *Parser) parseUpstream() error {
    for p.scanner.Scan() {
        p.line++
        line := strings.TrimSpace(p.scanner.Text())

        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        if line == "}" {
            return nil
        }

        if strings.HasSuffix(line, "{") {
            directive := strings.TrimSpace(strings.TrimSuffix(line, "{"))
            if directive == "health_check" {
                if err := p.parseHealthCheck(); err != nil {
                    return err
                }
                continue
            }
        }

        parts := strings.Fields(line)
        if len(parts) < 2 {
            continue
        }

        switch parts[0] {
        case "strategy":
            p.currentVHost.Upstream.Strategy = parts[1]
        case "cookie_name":
            p.currentVHost.Upstream.CookieName = parts[1]
        case "backend":
            bc := loadbalancer.BackendConfig{
                URL:    parts[1],
                Weight: 1,
            }
            // Parse optional "weight N"
            for i := 2; i < len(parts)-1; i++ {
                if parts[i] == "weight" {
                    w, err := strconv.Atoi(parts[i+1])
                    if err != nil {
                        return fmt.Errorf("upstream backend weight: %w", err)
                    }
                    bc.Weight = w
                }
            }
            p.currentVHost.Upstream.Backends = append(p.currentVHost.Upstream.Backends, bc)
        }
    }
    return nil
}

func (p *Parser) parseHealthCheck() error {
    // Enable health checking when the block is present
    p.currentVHost.Upstream.HealthCheck.Enabled = true
    for p.scanner.Scan() {
        p.line++
        line := strings.TrimSpace(p.scanner.Text())

        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        if line == "}" {
            return nil
        }

        parts := strings.Fields(line)
        if len(parts) < 2 {
            continue
        }

        switch parts[0] {
        case "path":
            p.currentVHost.Upstream.HealthCheck.Path = parts[1]
        case "interval":
            d, err := time.ParseDuration(parts[1])
            if err != nil {
                return fmt.Errorf("health_check interval: %w", err)
            }
            p.currentVHost.Upstream.HealthCheck.Interval = d
        case "timeout":
            d, err := time.ParseDuration(parts[1])
            if err != nil {
                return fmt.Errorf("health_check timeout: %w", err)
            }
            p.currentVHost.Upstream.HealthCheck.Timeout = d
        case "fail_threshold":
            n, err := strconv.Atoi(parts[1])
            if err != nil {
                return fmt.Errorf("health_check fail_threshold: %w", err)
            }
            p.currentVHost.Upstream.HealthCheck.FailThreshold = n
        case "pass_threshold":
            n, err := strconv.Atoi(parts[1])
            if err != nil {
                return fmt.Errorf("health_check pass_threshold: %w", err)
            }
            p.currentVHost.Upstream.HealthCheck.PassThreshold = n
        }
    }
    return nil
}

// parseByteSize parses human-readable byte sizes like "256MB", "1GB", "512KB".
func parseByteSize(s string) (int64, error) {
    s = strings.TrimSpace(s)
    if s == "" {
        return 0, fmt.Errorf("empty size")
    }

    multiplier := int64(1)
    upper := strings.ToUpper(s)

    switch {
    case strings.HasSuffix(upper, "GB"):
        multiplier = 1 << 30
        s = s[:len(s)-2]
    case strings.HasSuffix(upper, "MB"):
        multiplier = 1 << 20
        s = s[:len(s)-2]
    case strings.HasSuffix(upper, "KB"):
        multiplier = 1 << 10
        s = s[:len(s)-2]
    case strings.HasSuffix(upper, "B"):
        s = s[:len(s)-1]
    }

    n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
    if err != nil {
        return 0, fmt.Errorf("invalid size %q: %w", s, err)
    }
    return n * multiplier, nil
}
