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
            if domain == "" {
                return fmt.Errorf("vhost block has no hostname")
            }
            p.currentVHost = NewVirtualHost()
            p.currentVHost.Hostname = domain

            if err := p.parseVHostBlock(); err != nil {
                return err
            }

            p.config.VHosts[domain] = p.currentVHost
            continue
        }

        return fmt.Errorf("unexpected token %q (expected vhost block or })", line)
    }
    return fmt.Errorf("unexpected end of file: missing closing } for vhosts block")
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
    return fmt.Errorf("unexpected end of file: missing closing } for vhost %q", p.currentVHost.Hostname)
}

func (p *Parser) parseLine(line string) error {
    parts := strings.Fields(line)
    if len(parts) == 0 {
        return nil
    }

    switch parts[0] {
    case "port":
        if len(parts) < 2 {
            return fmt.Errorf("port requires a value")
        }
        port, err := strconv.Atoi(parts[1])
        if err != nil {
            return fmt.Errorf("invalid port %q: must be an integer", parts[1])
        }
        if port < 1 || port > 65535 {
            return fmt.Errorf("invalid port %d: must be 1-65535", port)
        }
        p.currentVHost.Port = port
    case "proxy_pass":
        if len(parts) < 2 {
            return fmt.Errorf("proxy_pass requires a URL")
        }
        if p.currentVHost.Root != "" {
            return fmt.Errorf("proxy_pass and root are mutually exclusive")
        }
        p.currentVHost.ProxyPass = parts[1]
    case "root":
        if len(parts) < 2 {
            return fmt.Errorf("root requires a path")
        }
        if p.currentVHost.ProxyPass != "" {
            return fmt.Errorf("root and proxy_pass are mutually exclusive")
        }
        p.currentVHost.Root = parts[1]
    case "compression":
        if len(parts) < 2 {
            return fmt.Errorf("compression requires on or off")
        }
        switch parts[1] {
        case "on":
            p.currentVHost.Compression = true
        case "off":
            p.currentVHost.Compression = false
        default:
            return fmt.Errorf("invalid compression value %q: must be on or off", parts[1])
        }
    case "ssl", "security", "socks5", "fastcgi", "bot_protection", "cache", "upstream":
        if len(parts) != 2 || parts[1] != "{" {
            return fmt.Errorf("%q block must be opened with %q", parts[0], parts[0]+" {")
        }
        switch parts[0] {
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
    default:
        return fmt.Errorf("unknown directive %q", parts[0])
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
        default:
            return fmt.Errorf("unknown fastcgi directive %q", parts[0])
        }
    }
    return fmt.Errorf("unexpected end of file: missing closing } for fastcgi block")
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
        default:
            return fmt.Errorf("unknown ssl directive %q", parts[0])
        }
    }
    return fmt.Errorf("unexpected end of file: missing closing } for ssl block")
}

func (p *Parser) parseSecurity() error {
    for p.scanner.Scan() {
        p.line++
        line := strings.TrimSpace(p.scanner.Text())
        
        if line == "}" {
            return nil
        }
        
        if line == "rate_limit {" {
            if err := p.parseRateLimit(); err != nil {
                return err
            }
            continue
        }
        
        parts := strings.Fields(line)
        if len(parts) < 2 {
            continue
        }
        
        switch parts[0] {
        case "frame_options":
            switch parts[1] {
            case "SAMEORIGIN", "DENY", "ALLOWALL":
            default:
                return fmt.Errorf("invalid frame_options value %q: must be SAMEORIGIN, DENY, or ALLOWALL", parts[1])
            }
            p.currentVHost.Security.Headers.FrameOptions = parts[1]
        case "content_type":
            if parts[1] != "nosniff" {
                return fmt.Errorf("invalid content_type value %q: must be nosniff", parts[1])
            }
            p.currentVHost.Security.Headers.ContentType = parts[1]
        case "xss_protection":
            p.currentVHost.Security.Headers.XSSProtection = strings.Join(parts[1:], " ")
        case "csp":
            p.currentVHost.Security.Headers.CSP = strings.Join(parts[1:], " ")
        case "hsts":
            p.currentVHost.Security.Headers.HSTS = strings.Join(parts[1:], " ")
        default:
            return fmt.Errorf("unknown security directive %q", parts[0])
        }
    }
    return fmt.Errorf("unexpected end of file: missing closing } for security block")
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
                return fmt.Errorf("invalid rate_limit requests %q: must be an integer", parts[1])
            }
            if requests < 0 {
                return fmt.Errorf("rate_limit requests must be >= 0")
            }
            p.currentVHost.Security.RateLimit.Requests = requests
        case "window":
            window, err := time.ParseDuration(parts[1])
            if err != nil {
                return fmt.Errorf("invalid rate_limit window %q: %w", parts[1], err)
            }
            p.currentVHost.Security.RateLimit.Window = window
        default:
            return fmt.Errorf("unknown rate_limit directive %q", parts[0])
        }
    }
    return fmt.Errorf("unexpected end of file: missing closing } for rate_limit block")
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
        case "enabled", "block_scanners", "honeypot":
            if parts[1] != "true" && parts[1] != "false" {
                return fmt.Errorf("invalid boolean value %q for %q (must be true or false)", parts[1], parts[0])
            }
            val := parts[1] == "true"
            switch parts[0] {
            case "enabled":
                p.currentVHost.BotProtection.Enabled = val
            case "block_scanners":
                p.currentVHost.BotProtection.BlockScanners = val
            case "honeypot":
                p.currentVHost.BotProtection.Honeypot = val
            }
        case "block":
            p.currentVHost.BotProtection.BlockedAgents = append(
                p.currentVHost.BotProtection.BlockedAgents, parts[1])
        case "block_path":
            p.currentVHost.BotProtection.BlockedPaths = append(
                p.currentVHost.BotProtection.BlockedPaths, parts[1])
        case "allow":
            p.currentVHost.BotProtection.AllowedAgents = append(
                p.currentVHost.BotProtection.AllowedAgents, parts[1])
        default:
            return fmt.Errorf("unknown bot_protection directive %q", parts[0])
        }
    }
    return fmt.Errorf("unexpected end of file: missing closing } for bot_protection block")
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
            if parts[1] != "true" && parts[1] != "false" {
                return fmt.Errorf("invalid boolean value %q for socks5 enabled", parts[1])
            }
            p.currentVHost.SOCKS5.Enabled = parts[1] == "true"
        case "address":
            p.currentVHost.SOCKS5.Address = parts[1]
        case "username":
            p.currentVHost.SOCKS5.Username = parts[1]
        case "password":
            p.currentVHost.SOCKS5.Password = parts[1]
        default:
            return fmt.Errorf("unknown socks5 directive %q", parts[0])
        }
    }
    return fmt.Errorf("unexpected end of file: missing closing } for socks5 block")
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
            if parts[1] != "true" && parts[1] != "false" {
                return fmt.Errorf("invalid boolean value %q for cache enabled", parts[1])
            }
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
        default:
            return fmt.Errorf("unknown cache directive %q", parts[0])
        }
    }
    return fmt.Errorf("unexpected end of file: missing closing } for cache block")
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

        if line == "health_check {" {
            if err := p.parseHealthCheck(); err != nil {
                return err
            }
            continue
        }

        parts := strings.Fields(line)
        if len(parts) < 2 {
            continue
        }

        switch parts[0] {
        case "strategy":
            if !validStrategies[parts[1]] {
                return fmt.Errorf("unknown upstream strategy %q: must be round_robin, least_conn, ip_hash, weighted, or cookie", parts[1])
            }
            p.currentVHost.Upstream.Strategy = parts[1]
        case "cookie_name":
            p.currentVHost.Upstream.CookieName = parts[1]
        case "backend":
            bc := loadbalancer.BackendConfig{
                URL:    parts[1],
                Weight: 1,
            }
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
        default:
            return fmt.Errorf("unknown upstream directive %q", parts[0])
        }
    }
    return fmt.Errorf("unexpected end of file: missing closing } for upstream block")
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
        default:
            return fmt.Errorf("unknown health_check directive %q", parts[0])
        }
    }
    return fmt.Errorf("unexpected end of file: missing closing } for health_check block")
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
