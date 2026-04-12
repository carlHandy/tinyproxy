package botdetect

import "strings"

var blockedAgents = []string{
	// AI crawlers
	"gptbot",
	"chatgpt-user",
	"ccbot",
	"anthropic-ai",
	"claudebot",
	"claude-web",
	"perplexitybot",
	"youbot",
	"cohere-ai",
	"bytespider",
	"petalbot",
	"semrushbot",
	"ahrefsbot",
	"mj12bot",
	"dotbot",
	// Generic headless/scripted
	"python-requests",
	"scrapy",
	"libwww-perl",
	"masscan",
	"zgrab",
}

var allowedAgents = []string{
	"googlebot",
	"bingbot",
	"slurp",
	"duckduckbot",
	"baiduspider",
	"facebookexternalhit",
	"twitterbot",
	"linkedinbot",
	"applebot",
}

// containsToken returns true if ua contains token as a word-boundary-delimited substring.
// This prevents "EvilGooglebot" from matching "Googlebot".
func containsToken(ua, token string) bool {
	idx := strings.Index(ua, token)
	if idx < 0 {
		return false
	}
	// Check the character before the token (if any) is non-alphanumeric
	if idx > 0 {
		prev := ua[idx-1]
		if (prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') || (prev >= '0' && prev <= '9') {
			return false
		}
	}
	// Check the character after the token (if any) is non-alphanumeric
	end := idx + len(token)
	if end < len(ua) {
		next := ua[end]
		if (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') || (next >= '0' && next <= '9') {
			return false
		}
	}
	return true
}

func isAllowedBot(ua string) bool {
	if ua == "" {
		return false
	}
	lower := strings.ToLower(ua)
	for _, a := range allowedAgents {
		if containsToken(lower, a) {
			return true
		}
	}
	return false
}

func isKnownBot(ua string) bool {
	if ua == "" {
		return false
	}
	lower := strings.ToLower(ua)
	for _, b := range blockedAgents {
		if strings.Contains(lower, b) {
			return true
		}
	}
	return false
}
