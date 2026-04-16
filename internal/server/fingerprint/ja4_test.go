package fingerprint

import "testing"

func TestJA4(t *testing.T) {
	ch, err := ParseClientHello(testClientHello)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	got := JA4(ch)
	const want = "t12i020200_177d36ae841b_33a13ba74d1c"
	if got != want {
		t.Errorf("JA4: got %q, want %q", got, want)
	}
}

func TestJA4_tlsVersion(t *testing.T) {
	cases := []struct {
		version    uint16
		negotiated uint16
		want       string
	}{
		{0x0303, 0x0304, "13"}, // negotiated wins
		{0x0303, 0x0000, "12"}, // falls back to client_version
		{0x0302, 0x0000, "11"},
		{0x0301, 0x0000, "10"},
		{0x0200, 0x0000, "00"}, // unknown
	}
	for _, tc := range cases {
		ch := ClientHello{Version: tc.version, NegotiatedVersion: tc.negotiated}
		got := tlsVersionCode(ch)
		if got != tc.want {
			t.Errorf("tlsVersionCode(%#x, %#x) = %q, want %q", tc.version, tc.negotiated, got, tc.want)
		}
	}
}
