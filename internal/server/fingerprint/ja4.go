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
