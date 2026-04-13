package botdetect

import (
	"net/url"
	"path"
	"strings"
)

/** 
	suspiciousPaths contains paths that are universally suspicious — dotfiles,
	system paths, and framework internals that no legitimate web application
 	should expose publicly.

	Application-specific paths (WordPress, phpMyAdmin, Jenkins, Solr, etc.) are
	intentionally excluded. A site may legitimately run any of these, and
	operators who know they are not should add them via the `block_path` directive
	rather than having the default list break their stack.
**/
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
