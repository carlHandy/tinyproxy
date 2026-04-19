package config

import (
	"strings"
	"testing"
)

func TestParser_MaxBodySize(t *testing.T) {
	input := `
vhosts {
    example.com {
        port 80
        root /var/www
        max_body_size 20MB
    }
}`
	p := NewParser(strings.NewReader(input))
	cfg, err := p.Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	vh, ok := cfg.VHosts["example.com"]
	if !ok {
		t.Fatal("vhost not found")
	}
	const want = 20 << 20
	if vh.MaxBodySize != want {
		t.Errorf("MaxBodySize = %d, want %d", vh.MaxBodySize, want)
	}
}
