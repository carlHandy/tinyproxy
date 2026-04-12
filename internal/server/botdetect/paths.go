package botdetect

import (
	"net/url"
	"path"
	"strings"
)

var suspiciousPaths = []string{
	"/.env",
	"/.git",
	"/.svn",
	"/.htaccess",
	"/wp-admin",
	"/wp-login",
	"/phpMyAdmin",
	"/phpmyadmin",
	"/etc/passwd",
	"/etc/shadow",
	"/actuator",
	"/console",
	"/manager/html",
	"/solr/",
	"/jenkins",
	"/.aws",
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
