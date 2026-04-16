// internal/server/fingerprint/ja3.go
package fingerprint

import (
	"crypto/md5"
	"fmt"
	"strings"
)

// JA3 computes the JA3 fingerprint MD5 hash from a parsed ClientHello.
// Format: MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
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
