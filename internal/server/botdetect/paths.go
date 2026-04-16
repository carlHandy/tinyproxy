package botdetect

import (
	"net/url"
	"path"
	"strings"
)

// suspiciousPaths contains paths that are universally suspicious — dotfiles,
// system paths, framework internals, and well-known admin interfaces that no
// legitimate public endpoint should expose.
var suspiciousPaths = []string{
	"/.env",
	"/.git",
	"/.svn",
	"/.htaccess",
	"/.aws",
	"/etc/passwd",
	"/etc/shadow",
	"/proc/self",
	"/config.json",
	"/credentials",
	// Well-known admin/framework paths
	"/wp-admin",
	"/wp-login",
	"/phpmyadmin",
	"/actuator",
}

// isBlockedPath checks whether rawPath matches any operator-defined blocked path prefix.
func isBlockedPath(rawPath string, blocked []string) bool {
	if len(blocked) == 0 {
		return false
	}
	decoded, err := url.PathUnescape(rawPath)
	if err != nil {
		decoded = rawPath
	}
	lower := strings.ToLower(path.Clean(decoded))
	for _, p := range blocked {
		if strings.HasPrefix(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func isSuspiciousPath(rawPath string) bool {
	decoded, err := url.PathUnescape(rawPath)
	if err != nil {
		decoded = rawPath
	}
	lower := strings.ToLower(path.Clean(decoded))
	for _, p := range suspiciousPaths {
		if strings.HasPrefix(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}
