package config

import (
    "bufio"
    "strings"
    "io"
    "strconv"
    "time"
    "fmt"
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
