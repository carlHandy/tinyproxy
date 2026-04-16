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
