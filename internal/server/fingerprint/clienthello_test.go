// internal/server/fingerprint/clienthello_test.go
package fingerprint

import (
	"testing"
)

// testClientHello is a hand-crafted minimal TLS 1.2 ClientHello:
//
//	Version: 0x0303 (TLS 1.2)
//	Ciphers: 0xC02B (49195), 0xC02C (49196)
//	Extensions: supported_groups (10), ec_point_formats (11)
//	EllipticCurves: 0x0017 (23 = x25519)
//	PointFormats: 0x00 (uncompressed)
//	No SNI, no ALPN, no supported_versions
var testClientHello = []byte{
	// TLS record header: Handshake(0x16), TLS1.0(0x0301), length=63(0x003F)
	0x16, 0x03, 0x01, 0x00, 0x3F,
	// Handshake header: ClientHello(0x01), length=59(0x00003B)
	0x01, 0x00, 0x00, 0x3B,
	// client_version = TLS 1.2
	0x03, 0x03,
	// random (32 bytes)
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	// session_id_length = 0
	0x00,
	// cipher_suites_length = 4
	0x00, 0x04,
	// 0xC02B = 49195, 0xC02C = 49196
	0xC0, 0x2B, 0xC0, 0x2C,
	// compression_methods: length=1, null
	0x01, 0x00,
	// extensions_length = 14
	0x00, 0x0E,
	// supported_groups (type=10): length=4, list_length=2, x25519=23
	0x00, 0x0A, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17,
	// ec_point_formats (type=11): length=2, list_length=1, uncompressed=0
	0x00, 0x0B, 0x00, 0x02, 0x01, 0x00,
}

func TestParseClientHello_basic(t *testing.T) {
	ch, err := ParseClientHello(testClientHello)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ch.Version != 0x0303 {
		t.Errorf("Version: got %#x, want 0x0303", ch.Version)
	}
	if len(ch.CipherSuites) != 2 || ch.CipherSuites[0] != 49195 || ch.CipherSuites[1] != 49196 {
		t.Errorf("CipherSuites: got %v, want [49195 49196]", ch.CipherSuites)
	}
	if len(ch.Extensions) != 2 || ch.Extensions[0] != 10 || ch.Extensions[1] != 11 {
		t.Errorf("Extensions: got %v, want [10 11]", ch.Extensions)
	}
	if len(ch.EllipticCurves) != 1 || ch.EllipticCurves[0] != 23 {
		t.Errorf("EllipticCurves: got %v, want [23]", ch.EllipticCurves)
	}
	if len(ch.EllipticCurvePointFormats) != 1 || ch.EllipticCurvePointFormats[0] != 0 {
		t.Errorf("PointFormats: got %v, want [0]", ch.EllipticCurvePointFormats)
	}
	if ch.HasSNI {
		t.Error("HasSNI: got true, want false")
	}
	if ch.FirstALPN != "" {
		t.Errorf("FirstALPN: got %q, want empty", ch.FirstALPN)
	}
}

func TestParseClientHello_notTLS(t *testing.T) {
	_, err := ParseClientHello([]byte("GET / HTTP/1.1\r\n"))
	if err == nil {
		t.Error("expected error for non-TLS data")
	}
}

func TestParseClientHello_tooShort(t *testing.T) {
	_, err := ParseClientHello([]byte{0x16, 0x03})
	if err == nil {
		t.Error("expected error for truncated data")
	}
}

func TestIsGREASE(t *testing.T) {
	cases := []struct {
		v    uint16
		want bool
	}{
		{0x0a0a, true},
		{0x1a1a, true},
		{0xfafa, true},
		{0xaaaa, true},
		{0x0303, false},
		{0xC02B, false},
		{0x0000, false},
	}
	for _, tc := range cases {
		if got := isGREASE(tc.v); got != tc.want {
			t.Errorf("isGREASE(%#x) = %v, want %v", tc.v, got, tc.want)
		}
	}
}
