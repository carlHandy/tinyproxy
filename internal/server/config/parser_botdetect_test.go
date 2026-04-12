package config

import (
	"strings"
	"testing"
)

func TestParser_BotProtection(t *testing.T) {
	input := `
vhosts {
    example.com {
        port 80
        root /var/www
        bot_protection {
            enabled true
            block_scanners true
            block GPTBot
            block MyBadBot
            allow FriendlyBot
        }
    }
}`
	p := NewParser(strings.NewReader(input))
	cfg, err := p.Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	vh, ok := cfg.VHosts["example.com"]
	if !ok {
		t.Fatal("vhost example.com not found")
	}

	bp := vh.BotProtection
	if !bp.Enabled {
		t.Error("expected BotProtection.Enabled = true")
	}
	if !bp.BlockScanners {
		t.Error("expected BotProtection.BlockScanners = true")
	}
	if len(bp.BlockedAgents) != 2 || bp.BlockedAgents[0] != "GPTBot" || bp.BlockedAgents[1] != "MyBadBot" {
		t.Errorf("unexpected BlockedAgents: %v", bp.BlockedAgents)
	}
	if len(bp.AllowedAgents) != 1 || bp.AllowedAgents[0] != "FriendlyBot" {
		t.Errorf("unexpected AllowedAgents: %v", bp.AllowedAgents)
	}
}
