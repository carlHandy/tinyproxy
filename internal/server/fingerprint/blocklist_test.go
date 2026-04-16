package fingerprint

import (
	"strings"
	"testing"
)

func TestLoadBlocklist(t *testing.T) {
	input := `
# scanner fingerprints
ja3:abc123
ja4:t13d0101h2_abc123def456_fedcba987654

ja3:deadbeef  # inline comment
unknown:xyz
`
	bl := LoadBlocklist(strings.NewReader(input))

	if _, ok := bl["ja3:abc123"]; !ok {
		t.Error("expected ja3:abc123 to be in blocklist")
	}
	if _, ok := bl["ja4:t13d0101h2_abc123def456_fedcba987654"]; !ok {
		t.Error("expected ja4 entry to be in blocklist")
	}
	if _, ok := bl["ja3:deadbeef"]; !ok {
		t.Error("expected ja3:deadbeef (with inline comment) to be in blocklist")
	}
	if _, ok := bl["unknown:xyz"]; ok {
		t.Error("unknown prefix should not be in blocklist")
	}
	if len(bl) != 3 {
		t.Errorf("blocklist length: got %d, want 3", len(bl))
	}
}

func TestIsBlocked(t *testing.T) {
	bl := map[string]struct{}{
		"ja3:abc123": {},
	}
	fp := Fingerprints{JA3: "abc123", JA4: "t12i020200_abc_def"}
	if !IsBlocked(bl, fp) {
		t.Error("expected blocked=true for matching JA3")
	}
	fp2 := Fingerprints{JA3: "other", JA4: "t12i020200_abc_def"}
	if IsBlocked(bl, fp2) {
		t.Error("expected blocked=false for non-matching fingerprint")
	}
}
