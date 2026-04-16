// internal/server/fingerprint/ja3_test.go
package fingerprint

import "testing"

func TestJA3(t *testing.T) {
	ch, err := ParseClientHello(testClientHello)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	got := JA3(ch)
	const want = "424eb263ba64207d9ab10e204c2daf31"
	if got != want {
		t.Errorf("JA3 hash: got %q, want %q", got, want)
	}
}

func TestJA3_noExtensions(t *testing.T) {
	ch := ClientHello{
		Version:      771,
		CipherSuites: []uint16{49195},
	}
	got := JA3(ch)
	// string is "771,49195,,," — verify it hashes without panic
	if len(got) != 32 {
		t.Errorf("JA3 hash length: got %d, want 32", len(got))
	}
}
