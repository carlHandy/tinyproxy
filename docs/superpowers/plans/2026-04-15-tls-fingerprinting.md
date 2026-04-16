# TLS Fingerprinting (JA3/JA4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compute JA3 and JA4 TLS fingerprints for every connection at the TCP layer, block known-bad fingerprints from a global config file, log them in access logs, and forward them as headers to upstream backends.

**Architecture:** Extend `sniffingListener.Accept()` in `main.go` to buffer the full TLS ClientHello record before handing the connection to the TLS layer, compute JA3/JA4, and store them on a `fingerprintConn` struct. Go 1.18's `tls.Conn.NetConn()` lets `http.Server.ConnContext` unwrap the TLS conn back to `fingerprintConn` and inject fingerprints into the request context. `ServeHTTP` reads them from context to check the blocklist, log them, and the proxy Director injects them as upstream headers.

**Tech Stack:** Go 1.23 stdlib only (`crypto/md5`, `crypto/sha256`, `encoding/binary`, `bufio`, `context`). No external dependencies added.

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Create | `internal/server/fingerprint/clienthello.go` | Parse raw ClientHello bytes → `ClientHello` struct |
| Create | `internal/server/fingerprint/clienthello_test.go` | Tests for parser |
| Create | `internal/server/fingerprint/ja3.go` | JA3 string + MD5 hash |
| Create | `internal/server/fingerprint/ja3_test.go` | Tests for JA3 |
| Create | `internal/server/fingerprint/ja4.go` | JA4 string computation |
| Create | `internal/server/fingerprint/ja4_test.go` | Tests for JA4 |
| Create | `internal/server/fingerprint/context.go` | `Fingerprints` type, context helpers, `Compute()` |
| Create | `internal/server/fingerprint/blocklist.go` | Load + query the blocklist |
| Create | `internal/server/fingerprint/blocklist_test.go` | Tests for blocklist |
| Modify | `cmd/tinyproxy/main.go` | Replace `peekedConn`, add `fingerprintConn`, `ConnContext`, blocklist loading, logging |
| Modify | `internal/server/proxy/proxy.go` | Inject `X-JA3-Fingerprint` / `X-JA4-Fingerprint` in both Directors |
| Create | `config/fingerprints.conf` | Sample global blocklist |

---

## Task 1: `Fingerprints` type, context helpers, and `Compute()`

**Files:**
- Create: `internal/server/fingerprint/context.go`

- [ ] **Step 1: Write the file**

```go
package fingerprint

import "context"

type contextKey struct{}

// Fingerprints holds the JA3 MD5 hash and JA4 string for a TLS connection.
// Both fields are empty for plain-HTTP connections or when ClientHello parsing fails.
type Fingerprints struct {
	JA3 string
	JA4 string
}

// WithFingerprints returns a child context carrying fp.
func WithFingerprints(ctx context.Context, fp Fingerprints) context.Context {
	return context.WithValue(ctx, contextKey{}, fp)
}

// FromContext retrieves Fingerprints from ctx.
// Returns zero-value Fingerprints if none are present.
func FromContext(ctx context.Context) Fingerprints {
	fp, _ := ctx.Value(contextKey{}).(Fingerprints)
	return fp
}

// Compute parses data as a raw TLS ClientHello record and returns both fingerprints.
// Returns zero-value Fingerprints if data is not a valid ClientHello.
func Compute(data []byte) Fingerprints {
	ch, err := ParseClientHello(data)
	if err != nil {
		return Fingerprints{}
	}
	return Fingerprints{
		JA3: JA3(ch),
		JA4: JA4(ch),
	}
}
```

- [ ] **Step 2: Verify package compiles (will fail until other files exist — that's fine)**

```bash
cd /path/to/tinyproxy
go build ./internal/server/fingerprint/ 2>&1 | head -5
```

Expected: errors about undefined `ParseClientHello`, `JA3`, `JA4` — that's correct, those come in later tasks.

- [ ] **Step 3: Commit**

```bash
git add internal/server/fingerprint/context.go
git commit -m "feat(fingerprint): add Fingerprints type and context helpers"
```

---

## Task 2: ClientHello parser

**Files:**
- Create: `internal/server/fingerprint/clienthello.go`
- Create: `internal/server/fingerprint/clienthello_test.go`

The raw TLS record layout parsed here:
```
TLS Record Header (5 bytes):
  [0]    content_type  (0x16 = Handshake)
  [1-2]  legacy_version
  [3-4]  record length (uint16 big-endian)

Handshake Header (4 bytes, inside record):
  [0]    msg_type      (0x01 = ClientHello)
  [1-3]  length        (uint24 big-endian)

ClientHello body:
  [0-1]   client_version (uint16)
  [2-33]  random         (32 bytes, skip)
  [34]    session_id_len
  [35..]  session_id     (skip)
  [..]    cipher_suites_len (uint16)
  [..]    cipher_suites     (each uint16)
  [..]    compression_methods_len (uint8)
  [..]    compression_methods     (skip)
  [..]    extensions_len (uint16, optional)
  [..]    extensions: each is type(uint16) + len(uint16) + data
```

Extension types parsed:
- `0x0000` SNI: sets `HasSNI = true`, extracts first hostname
- `0x000a` supported_groups: populates `EllipticCurves` (excluding GREASE)
- `0x000b` ec_point_formats: populates `EllipticCurvePointFormats`
- `0x000d` signature_algorithms: (type ID collected, data skipped)
- `0x0010` ALPN: sets `FirstALPN` to first protocol name
- `0x002b` supported_versions: sets `NegotiatedVersion` to highest non-GREASE version

GREASE values (RFC 8701): both bytes equal, low nibble = `0xa`. Examples: `0x0a0a`, `0x1a1a`, `0xfafa`.

- [ ] **Step 1: Write the failing test**

```go
// internal/server/fingerprint/clienthello_test.go
package fingerprint

import (
	"testing"
)

// testClientHello is a hand-crafted minimal TLS 1.2 ClientHello:
//   Version: 0x0303 (TLS 1.2)
//   Ciphers: 0xC02B (49195), 0xC02C (49196)
//   Extensions: supported_groups (10), ec_point_formats (11)
//   EllipticCurves: 0x0017 (23 = x25519)
//   PointFormats: 0x00 (uncompressed)
//   No SNI, no ALPN, no supported_versions
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
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test ./internal/server/fingerprint/ -run TestParseClientHello -v
```

Expected: `FAIL` — `ParseClientHello` undefined.

- [ ] **Step 3: Write the implementation**

```go
// internal/server/fingerprint/clienthello.go
package fingerprint

import (
	"encoding/binary"
	"errors"
)

// ClientHello holds fields extracted from a TLS ClientHello message.
type ClientHello struct {
	Version                   uint16
	NegotiatedVersion         uint16   // from supported_versions ext (0x002b); 0 if absent
	CipherSuites              []uint16 // excluding GREASE
	Extensions                []uint16 // all extension type IDs in order, excluding GREASE
	EllipticCurves            []uint16 // from supported_groups ext, excluding GREASE
	EllipticCurvePointFormats []uint8
	HasSNI                    bool
	SNI                       string
	FirstALPN                 string // first value from ALPN ext; empty if absent
}

var errNotClientHello = errors.New("fingerprint: not a TLS ClientHello")

// ParseClientHello parses raw bytes beginning at the TLS record header.
// Returns errNotClientHello for non-TLS data or non-ClientHello handshake types.
func ParseClientHello(data []byte) (ClientHello, error) {
	// TLS record header: 5 bytes
	if len(data) < 5 {
		return ClientHello{}, errNotClientHello
	}
	if data[0] != 0x16 { // content_type must be Handshake
		return ClientHello{}, errNotClientHello
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return ClientHello{}, errNotClientHello
	}
	body := data[5 : 5+recordLen]

	// Handshake header: 4 bytes
	if len(body) < 4 {
		return ClientHello{}, errNotClientHello
	}
	if body[0] != 0x01 { // msg_type must be ClientHello
		return ClientHello{}, errNotClientHello
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if len(body) < 4+hsLen {
		return ClientHello{}, errNotClientHello
	}
	return parseClientHelloBody(body[4 : 4+hsLen])
}

func parseClientHelloBody(data []byte) (ClientHello, error) {
	var ch ClientHello
	if len(data) < 34 { // version(2) + random(32)
		return ch, errNotClientHello
	}
	ch.Version = binary.BigEndian.Uint16(data[0:2])
	pos := 34 // skip version + random

	// session_id
	if pos >= len(data) {
		return ch, errNotClientHello
	}
	pos += 1 + int(data[pos])

	// cipher suites
	if pos+2 > len(data) {
		return ch, errNotClientHello
	}
	csLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+csLen > len(data) {
		return ch, errNotClientHello
	}
	for i := 0; i+1 < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(data[pos+i : pos+i+2])
		if !isGREASE(cs) {
			ch.CipherSuites = append(ch.CipherSuites, cs)
		}
	}
	pos += csLen

	// compression methods
	if pos >= len(data) {
		return ch, errNotClientHello
	}
	pos += 1 + int(data[pos])

	// extensions (optional — valid ClientHello can omit them)
	if pos+2 > len(data) {
		return ch, nil
	}
	extTotal := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	end := pos + extTotal
	if end > len(data) {
		return ch, errNotClientHello
	}

	for pos < end {
		if pos+4 > end {
			break
		}
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > end {
			break
		}
		extData := data[pos : pos+extLen]
		pos += extLen

		if !isGREASE(extType) {
			ch.Extensions = append(ch.Extensions, extType)
		}

		switch extType {
		case 0x0000: // SNI
			ch.HasSNI = true
			// format: list_length(2) + type(1) + name_length(2) + name
			if len(extData) >= 5 {
				nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
				if len(extData) >= 5+nameLen {
					ch.SNI = string(extData[5 : 5+nameLen])
				}
			}
		case 0x000a: // supported_groups
			if len(extData) >= 2 {
				listLen := int(binary.BigEndian.Uint16(extData[0:2]))
				for i := 2; i+1 < 2+listLen && i+1 < len(extData); i += 2 {
					g := binary.BigEndian.Uint16(extData[i : i+2])
					if !isGREASE(g) {
						ch.EllipticCurves = append(ch.EllipticCurves, g)
					}
				}
			}
		case 0x000b: // ec_point_formats
			if len(extData) >= 1 {
				fmtLen := int(extData[0])
				for i := 1; i <= fmtLen && i < len(extData); i++ {
					ch.EllipticCurvePointFormats = append(ch.EllipticCurvePointFormats, extData[i])
				}
			}
		case 0x0010: // ALPN
			if ch.FirstALPN == "" && len(extData) >= 4 {
				// list_length(2) + name_length(1) + name
				nameLen := int(extData[2])
				if len(extData) >= 3+nameLen {
					ch.FirstALPN = string(extData[3 : 3+nameLen])
				}
			}
		case 0x002b: // supported_versions
			// ClientHello format: list_length(1) then uint16 versions
			if len(extData) >= 1 {
				listLen := int(extData[0])
				for i := 1; i+1 < 1+listLen && i+1 < len(extData); i += 2 {
					v := binary.BigEndian.Uint16(extData[i : i+2])
					if !isGREASE(v) && v > ch.NegotiatedVersion {
						ch.NegotiatedVersion = v
					}
				}
			}
		}
	}
	return ch, nil
}

// isGREASE reports whether v is a GREASE value per RFC 8701.
// GREASE values have equal high and low bytes, both with low nibble 0xA.
func isGREASE(v uint16) bool {
	lo := byte(v)
	hi := byte(v >> 8)
	return lo == hi && lo&0x0f == 0x0a
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/server/fingerprint/ -run "TestParseClientHello|TestIsGREASE" -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/fingerprint/clienthello.go internal/server/fingerprint/clienthello_test.go
git commit -m "feat(fingerprint): add TLS ClientHello parser"
```

---

## Task 3: JA3 computation

**Files:**
- Create: `internal/server/fingerprint/ja3.go`
- Create: `internal/server/fingerprint/ja3_test.go`

JA3 string format: `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`
- Each list is decimal values joined by `-`
- Fields joined by `,`
- GREASE already excluded by the parser
- MD5 of the resulting string → 32-char hex

For the `testClientHello` fixture from Task 2, the expected values are:
- JA3 string: `771,49195-49196,10-11,23,0`
- JA3 hash: `424eb263ba64207d9ab10e204c2daf31`

- [ ] **Step 1: Write the failing test**

```go
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
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test ./internal/server/fingerprint/ -run TestJA3 -v
```

Expected: `FAIL` — `JA3` undefined.

- [ ] **Step 3: Write the implementation**

```go
// internal/server/fingerprint/ja3.go
package fingerprint

import (
	"crypto/md5"
	"fmt"
	"strings"
)

// JA3 computes the JA3 fingerprint MD5 hash from a parsed ClientHello.
func JA3(ch ClientHello) string {
	s := ja3String(ch)
	sum := md5.Sum([]byte(s))
	return fmt.Sprintf("%x", sum)
}

func ja3String(ch ClientHello) string {
	return strings.Join([]string{
		fmt.Sprintf("%d", ch.Version),
		uint16sToDecimalList(ch.CipherSuites),
		uint16sToDecimalList(ch.Extensions),
		uint16sToDecimalList(ch.EllipticCurves),
		uint8sToDecimalList(ch.EllipticCurvePointFormats),
	}, ",")
}

// uint16sToDecimalList joins a slice as decimal values separated by "-".
func uint16sToDecimalList(vs []uint16) string {
	if len(vs) == 0 {
		return ""
	}
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

// uint8sToDecimalList joins a slice as decimal values separated by "-".
func uint8sToDecimalList(vs []uint8) string {
	if len(vs) == 0 {
		return ""
	}
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/server/fingerprint/ -run TestJA3 -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/fingerprint/ja3.go internal/server/fingerprint/ja3_test.go
git commit -m "feat(fingerprint): add JA3 computation"
```

---

## Task 4: JA4 computation

**Files:**
- Create: `internal/server/fingerprint/ja4.go`
- Create: `internal/server/fingerprint/ja4_test.go`

JA4 format: `{a}_{b}_{c}` where:
- `a` = `t` + version(2 chars) + sni_flag(1) + cipher_count(02) + ext_count(02) + alpn(2 chars)
- `b` = SHA-256(sorted cipher hex, comma-separated), first 12 chars
- `c` = SHA-256(sorted ext type hex, comma-separated, excl. SNI=0x0000 and ALPN=0x0010), first 12 chars

Version mapping (uses `NegotiatedVersion` if set, else `Version`):
- `0x0304` → `"13"`, `0x0303` → `"12"`, `0x0302` → `"11"`, `0x0301` → `"10"`, other → `"00"`

SNI flag: `"d"` if `HasSNI`, else `"i"`

ALPN: first + last char of `FirstALPN`, or `"00"` if empty

Cipher count/ext count: `fmt.Sprintf("%02d", n)`, capped at 99

Cipher hex: each cipher as 4-char lowercase hex, sorted numerically, comma-separated
Ext hex: same, but extension type IDs only (excl. GREASE already done), sorted numerically

For the `testClientHello` fixture:
- `a` = `t12i020200` (TLS 1.2, no SNI, 2 ciphers, 2 exts, no ALPN)
- `b` = SHA-256(`"c02b,c02c"`) → first 12 chars = `177d36ae841b`
- `c` = SHA-256(`"000a,000b"`) → first 12 chars = `33a13ba74d1c`
- Full JA4: `t12i020200_177d36ae841b_33a13ba74d1c`

- [ ] **Step 1: Write the failing test**

```go
// internal/server/fingerprint/ja4_test.go
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
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test ./internal/server/fingerprint/ -run TestJA4 -v
```

Expected: `FAIL` — `JA4` undefined.

- [ ] **Step 3: Write the implementation**

```go
// internal/server/fingerprint/ja4.go
package fingerprint

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

// JA4 computes the JA4 fingerprint string from a parsed ClientHello.
func JA4(ch ClientHello) string {
	a := ja4PartA(ch)
	b := ja4PartB(ch)
	c := ja4PartC(ch)
	return a + "_" + b + "_" + c
}

func ja4PartA(ch ClientHello) string {
	ver := tlsVersionCode(ch)

	sni := "i"
	if ch.HasSNI {
		sni = "d"
	}

	cipherCount := len(ch.CipherSuites)
	if cipherCount > 99 {
		cipherCount = 99
	}

	// Extensions excluding SNI (0x0000) and ALPN (0x0010)
	extCount := 0
	for _, e := range ch.Extensions {
		if e != 0x0000 && e != 0x0010 {
			extCount++
		}
	}
	if extCount > 99 {
		extCount = 99
	}

	alpn := "00"
	if ch.FirstALPN != "" {
		r := []rune(ch.FirstALPN)
		alpn = string(r[0]) + string(r[len(r)-1])
	}

	return fmt.Sprintf("t%s%s%02d%02d%s", ver, sni, cipherCount, extCount, alpn)
}

func ja4PartB(ch ClientHello) string {
	sorted := make([]uint16, len(ch.CipherSuites))
	copy(sorted, ch.CipherSuites)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	hexParts := make([]string, len(sorted))
	for i, c := range sorted {
		hexParts[i] = fmt.Sprintf("%04x", c)
	}
	input := strings.Join(hexParts, ",")
	sum := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", sum)[:12]
}

func ja4PartC(ch ClientHello) string {
	var filtered []uint16
	for _, e := range ch.Extensions {
		if e != 0x0000 && e != 0x0010 { // exclude SNI and ALPN
			filtered = append(filtered, e)
		}
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i] < filtered[j] })

	hexParts := make([]string, len(filtered))
	for i, e := range filtered {
		hexParts[i] = fmt.Sprintf("%04x", e)
	}
	input := strings.Join(hexParts, ",")
	sum := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", sum)[:12]
}

// tlsVersionCode returns the two-character JA4 version string.
// Uses NegotiatedVersion (from supported_versions ext) if non-zero.
func tlsVersionCode(ch ClientHello) string {
	ver := ch.NegotiatedVersion
	if ver == 0 {
		ver = ch.Version
	}
	switch ver {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	default:
		return "00"
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/server/fingerprint/ -run TestJA4 -v
```

Expected: all PASS.

- [ ] **Step 5: Run all fingerprint tests to confirm nothing broken**

```bash
go test ./internal/server/fingerprint/ -v
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/server/fingerprint/ja4.go internal/server/fingerprint/ja4_test.go
git commit -m "feat(fingerprint): add JA4 computation"
```

---

## Task 5: Blocklist loader

**Files:**
- Create: `internal/server/fingerprint/blocklist.go`
- Create: `internal/server/fingerprint/blocklist_test.go`

`config/fingerprints.conf` format:
```
# comment
ja3:<md5hex>
ja4:<ja4string>
ja3:<hash>  # inline comment
```

- [ ] **Step 1: Write the failing test**

```go
// internal/server/fingerprint/blocklist_test.go
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
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test ./internal/server/fingerprint/ -run "TestLoadBlocklist|TestIsBlocked" -v
```

Expected: `FAIL` — `LoadBlocklist`, `IsBlocked` undefined.

- [ ] **Step 3: Write the implementation**

```go
// internal/server/fingerprint/blocklist.go
package fingerprint

import (
	"bufio"
	"io"
	"strings"
)

// LoadBlocklist parses a fingerprints.conf reader and returns a set of
// blocked fingerprint keys in the form "ja3:<hash>" or "ja4:<ja4string>".
// Blank lines and lines starting with "#" are ignored.
// Inline comments (space + "#") are stripped.
// Entries with unrecognised prefixes are silently ignored.
func LoadBlocklist(r io.Reader) map[string]struct{} {
	blocked := make(map[string]struct{})
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// strip inline comment: first " #" sequence
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if strings.HasPrefix(line, "ja3:") || strings.HasPrefix(line, "ja4:") {
			blocked[line] = struct{}{}
		}
	}
	return blocked
}

// IsBlocked reports whether fp matches any entry in blocked.
func IsBlocked(blocked map[string]struct{}, fp Fingerprints) bool {
	if fp.JA3 != "" {
		if _, ok := blocked["ja3:"+fp.JA3]; ok {
			return true
		}
	}
	if fp.JA4 != "" {
		if _, ok := blocked["ja4:"+fp.JA4]; ok {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run all tests to verify they pass**

```bash
go test ./internal/server/fingerprint/ -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/fingerprint/blocklist.go internal/server/fingerprint/blocklist_test.go
git commit -m "feat(fingerprint): add blocklist loader"
```

---

## Task 6: `fingerprintConn` — replace `peekedConn` in `main.go`

**Files:**
- Modify: `cmd/tinyproxy/main.go`

Replace `peekedConn` (peeks 1 byte) with `fingerprintConn` (buffers full ClientHello). Update `sniffingListener.Accept()` to read the complete TLS record. Add `ConnContext` to `http.Server`.

- [ ] **Step 1: Delete `peekedConn` and add `fingerprintConn`**

Remove the entire `peekedConn` struct and its `Read` method (lines 32–45). Replace with:

```go
// fingerprintConn replays buffered bytes before delegating reads to the underlying conn.
// For TLS connections it holds the full ClientHello record so that both the TLS
// handshake and the fingerprint computation receive the same bytes.
type fingerprintConn struct {
	net.Conn
	buf []byte
	pos int
	fp  fingerprint.Fingerprints
}

func (c *fingerprintConn) Read(b []byte) (int, error) {
	if c.pos < len(c.buf) {
		n := copy(b, c.buf[c.pos:])
		c.pos += n
		return n, nil
	}
	return c.Conn.Read(b)
}
```

- [ ] **Step 2: Rewrite `sniffingListener.Accept()`**

Replace the entire `Accept` method body (lines 54–80) with:

```go
func (l *sniffingListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}

		// Read the 5-byte TLS record header.
		hdr := make([]byte, 5)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = io.ReadFull(conn, hdr)
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			conn.Close()
			continue
		}

		if hdr[0] != 0x16 {
			// Plain HTTP — send redirect and loop.
			fmt.Fprint(conn, "HTTP/1.1 301 Moved Permanently\r\nLocation: https://localhost:8080\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			conn.Close()
			continue
		}

		// TLS — read the rest of the record body.
		recordLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		if recordLen > 16384 { // max TLS record size
			conn.Close()
			continue
		}
		body := make([]byte, recordLen)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = io.ReadFull(conn, body)
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			conn.Close()
			continue
		}

		buf := append(hdr, body...)
		fc := &fingerprintConn{
			Conn: conn,
			buf:  buf,
			fp:   fingerprint.Compute(buf),
		}
		return tls.Server(fc, l.tlsCfg), nil
	}
}
```

- [ ] **Step 3: Add `"encoding/binary"` and `"io"` imports and fingerprint package import**

In the import block of `main.go`, add:
- `"encoding/binary"` (if not already present — check first)
- `"io"` (already present — verify)
- `"tinyproxy/internal/server/fingerprint"` (new)

- [ ] **Step 4: Add `ConnContext` to the server declaration**

In `runServer()`, there is a single `server := &http.Server{Handler: handler}` declaration before the `if os.Getenv("ENV") == "dev"` branch (around line 337). Both dev and production paths use the same variable, so one change covers both. Replace it with:

```go
server := &http.Server{
	Handler: handler,
	ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		if tc, ok := c.(*tls.Conn); ok {
			if fc, ok := tc.NetConn().(*fingerprintConn); ok {
				return fingerprint.WithFingerprints(ctx, fc.fp)
			}
		}
		return ctx
	},
}
```

Also add `"context"` to the import block — it is not currently imported in `main.go`.

- [ ] **Step 6: Build to verify no compile errors**

```bash
go build ./cmd/tinyproxy/ 2>&1
```

Expected: no output (clean build).

- [ ] **Step 7: Commit**

```bash
git add cmd/tinyproxy/main.go
git commit -m "feat(fingerprint): replace peekedConn with fingerprintConn, add ConnContext"
```

---

## Task 7: Blocklist loading, ServeHTTP check, and access logging

**Files:**
- Modify: `cmd/tinyproxy/main.go`

- [ ] **Step 1: Add `blocklist` field to `VHostHandler`**

Change the `VHostHandler` struct (around line 85) from:

```go
type VHostHandler struct {
	mu        sync.RWMutex
	config    *config.ServerConfig
	caches    map[string]*cache.Cache
	balancers map[string]*loadbalancer.LoadBalancer
}
```

to:

```go
type VHostHandler struct {
	mu        sync.RWMutex
	config    *config.ServerConfig
	blocklist map[string]struct{}
	caches    map[string]*cache.Cache
	balancers map[string]*loadbalancer.LoadBalancer
}
```

- [ ] **Step 2: Add `fingerprintsPath()` and `loadFingerprintBlocklist()` helpers**

Add after the existing `configPath()` function:

```go
// fingerprintsPath returns the active fingerprints config path: local first, then system.
func fingerprintsPath() string {
	if _, err := os.Stat("config/fingerprints.conf"); err == nil {
		return "config/fingerprints.conf"
	}
	return "/etc/go-tinyproxy/fingerprints.conf"
}

// loadFingerprintBlocklist loads config/fingerprints.conf (or system path).
// Returns an empty blocklist without error if the file does not exist.
func loadFingerprintBlocklist(path string) map[string]struct{} {
	f, err := os.Open(path)
	if err != nil {
		return make(map[string]struct{})
	}
	defer f.Close()
	return fingerprint.LoadBlocklist(f)
}
```

- [ ] **Step 3: Initialize blocklist in `runServer()`**

In `runServer()`, after `handler.initSubsystems()`, add:

```go
handler.blocklist = loadFingerprintBlocklist(fingerprintsPath())
```

- [ ] **Step 4: Reload blocklist on SIGHUP**

In the SIGHUP goroutine inside `runServer()`, after the `handler.reload(path)` call succeeds, add:

```go
handler.mu.Lock()
handler.blocklist = loadFingerprintBlocklist(fingerprintsPath())
handler.mu.Unlock()
```

The full SIGHUP handler becomes:

```go
go func() {
	for range sigs {
		if err := handler.reload(path); err != nil {
			log.Printf("reload failed: %v", err)
		} else {
			log.Println("config reloaded")
		}
		handler.mu.Lock()
		handler.blocklist = loadFingerprintBlocklist(fingerprintsPath())
		handler.mu.Unlock()
	}
}()
```

- [ ] **Step 5: Add fingerprint check and logging to `ServeHTTP`**

In `VHostHandler.ServeHTTP`, after the three `vh.mu.RLock()/RUnlock()` lines that read config/caches/balancers, add:

```go
fp := fingerprint.FromContext(r.Context())
if fingerprint.IsBlocked(blocklist, fp) {
	http.Error(w, "Forbidden", http.StatusForbidden)
	return
}
```

But wait — `blocklist` is read inside the RLock. Extend the read section so you also capture `blocklist`:

```go
vh.mu.RLock()
cfg := vh.config
bl := vh.blocklist
caches := vh.caches
balancers := vh.balancers
vh.mu.RUnlock()
```

Then the fingerprint check uses `bl`:

```go
fp := fingerprint.FromContext(r.Context())
if fingerprint.IsBlocked(bl, fp) {
	http.Error(w, "Forbidden", http.StatusForbidden)
	return
}
```

Also add logging at the end of `ServeHTTP`, just before the final `security.RateLimit(...)` call. Wrap the logging in the inner handler. Find the `inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {` block and add at the top of the inner handler, after `vh.setSecurityHeaders(w, vhost)`:

```go
if fp.JA3 != "" {
	log.Printf("%s %s JA3=%s JA4=%s", r.Method, r.URL.Path, fp.JA3, fp.JA4)
}
```

Note: `fp` is captured from the outer `ServeHTTP` scope — it's available because it was set before `inner` is defined.

- [ ] **Step 6: Build to verify**

```bash
go build ./cmd/tinyproxy/ 2>&1
```

Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add cmd/tinyproxy/main.go
git commit -m "feat(fingerprint): add blocklist check and access logging in ServeHTTP"
```

---

## Task 8: Upstream proxy header forwarding

**Files:**
- Modify: `internal/server/proxy/proxy.go`

Inject `X-JA3-Fingerprint` and `X-JA4-Fingerprint` into both Director functions — the one in `NewReverseProxy` and the one in `NewSingleBackendProxy`.

- [ ] **Step 1: Add the fingerprint import**

In `proxy.go` imports, add:

```go
"tinyproxy/internal/server/fingerprint"
```

- [ ] **Step 2: Update the Director in `NewReverseProxy`**

Find the Director closure (around line 49) and add fingerprint headers after the existing header assignments:

```go
p.Director = func(req *http.Request) {
	originalDirector(req)
	req.Header.Set("X-Forwarded-Host", req.Host)
	req.Header.Set("X-Forwarded-Proto", schemeFromRequest(req))
	if ip, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		req.Header.Set("X-Real-IP", ip)
	}
	if fp := fingerprint.FromContext(req.Context()); fp.JA3 != "" {
		req.Header.Set("X-JA3-Fingerprint", fp.JA3)
		req.Header.Set("X-JA4-Fingerprint", fp.JA4)
	}
}
```

- [ ] **Step 3: Update the Director in `NewSingleBackendProxy`**

Find the Director closure (around line 164) and make the same addition:

```go
p.Director = func(req *http.Request) {
	originalDirector(req)
	req.Header.Set("X-Forwarded-Host", req.Host)
	req.Header.Set("X-Forwarded-Proto", schemeFromRequest(req))
	if ip, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		req.Header.Set("X-Real-IP", ip)
	}
	if fp := fingerprint.FromContext(req.Context()); fp.JA3 != "" {
		req.Header.Set("X-JA3-Fingerprint", fp.JA3)
		req.Header.Set("X-JA4-Fingerprint", fp.JA4)
	}
}
```

- [ ] **Step 4: Build to verify**

```bash
go build ./... 2>&1
```

Expected: clean.

- [ ] **Step 5: Run all tests**

```bash
go test ./... 2>&1
```

Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/server/proxy/proxy.go
git commit -m "feat(fingerprint): forward X-JA3-Fingerprint and X-JA4-Fingerprint to upstream"
```

---

## Task 9: Sample `config/fingerprints.conf`

**Files:**
- Create: `config/fingerprints.conf`

- [ ] **Step 1: Write the sample config**

```
# TLS Fingerprint Blocklist
#
# Block known scanners, bots, or malicious TLS clients by their JA3 or JA4 fingerprint.
# One entry per line. Prefix with "ja3:" or "ja4:". Lines starting with "#" are ignored.
# Inline comments are supported (append " # comment" after the hash).
# This file is reloaded on SIGHUP alongside vhosts.conf.
#
# Example entries (commented out — uncomment to activate):
#
# ja3:e7d705a3286e19ea42f587b344ee6865  # curl 7.x default
# ja3:6734f37431670b3ab4292b8f60f29984  # Python requests
# ja4:t13d1516h2_8daaf6152771_e5627efa2ab1  # Chrome 108 on macOS
```

- [ ] **Step 2: Commit**

```bash
git add config/fingerprints.conf
git commit -m "chore: add sample config/fingerprints.conf for TLS fingerprint blocklist"
```

---

## Task 10: Final verification

- [ ] **Step 1: Run the full test suite**

```bash
go test ./... -v 2>&1 | tail -20
```

Expected: all PASS, no failures.

- [ ] **Step 2: Build the binary**

```bash
go build -o go-tinyproxy ./cmd/tinyproxy/
```

Expected: clean build, `go-tinyproxy` binary produced.

- [ ] **Step 3: Smoke-test in dev mode**

```bash
ENV=dev ./go-tinyproxy serve &
curl -k https://localhost:8080/ -v 2>&1 | grep -i ja3
```

Expected: server starts without errors. The `grep` won't show anything in curl output (JA3 is logged server-side), but the server log should include a `JA3=` line.

- [ ] **Step 4: Verify log output contains fingerprints**

Check server stdout for a line like:
```
GET / JA3=<32-char-hex> JA4=t13...
```

- [ ] **Step 5: Kill dev server and clean up binary**

```bash
kill %1
rm go-tinyproxy
```

- [ ] **Step 6: Final commit (if anything changed)**

```bash
go vet ./...
```

Expected: no issues.
