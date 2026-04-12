package botdetect

import "testing"

func TestIsKnownBot_AIcrawlers(t *testing.T) {
	cases := []struct {
		ua      string
		wantBot bool
	}{
		{"Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)", true},
		{"Mozilla/5.0 (compatible; ClaudeBot/1.0; +https://anthropic.com/)", true},
		{"CCBot/2.0 (https://commoncrawl.org/faq/)", true},
		{"PerplexityBot/1.0", true},
		{"Mozilla/5.0 AppleWebKit/537.36 Chrome/120.0", false},
		{"", false},
	}
	for _, c := range cases {
		t.Run(c.ua, func(t *testing.T) {
			if got := isKnownBot(c.ua); got != c.wantBot {
				t.Errorf("isKnownBot(%q) = %v, want %v", c.ua, got, c.wantBot)
			}
		})
	}
}

func TestIsAllowedBot_LegitCrawlers(t *testing.T) {
	cases := []struct {
		ua        string
		wantAllow bool
	}{
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", true},
		{"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", true},
		{"DuckDuckBot/1.1", true},
		{"GPTBot/1.0", false},
		{"curl/7.88.0", false},
	}
	for _, c := range cases {
		t.Run(c.ua, func(t *testing.T) {
			if got := isAllowedBot(c.ua); got != c.wantAllow {
				t.Errorf("isAllowedBot(%q) = %v, want %v", c.ua, got, c.wantAllow)
			}
		})
	}
}

func TestIsKnownBot_CaseInsensitive(t *testing.T) {
	cases := []struct {
		ua      string
		wantBot bool
	}{
		{"Scrapy/2.0", true},           // capitalised variant
		{"Python-Requests/2.28", true}, // real default casing from requests lib
		{"MASSCAN/1.0", true},          // all caps
	}
	for _, c := range cases {
		t.Run(c.ua, func(t *testing.T) {
			if got := isKnownBot(c.ua); got != c.wantBot {
				t.Errorf("isKnownBot(%q) = %v, want %v", c.ua, got, c.wantBot)
			}
		})
	}
}

func TestIsAllowedBot_WordBoundary(t *testing.T) {
	cases := []struct {
		ua        string
		wantAllow bool
	}{
		{"EvilGooglebot/1.0", false},    // must NOT match Googlebot
		{"Googlebot/2.1", true},          // exact prefix — must match
		{"Mozilla Googlebot/2.1", true},  // space-separated — must match
		{"Googlebots/1.0", false},        // right-boundary spoofing — must NOT match Googlebot
		{"googlebot/2.1", true},           // lowercase UA — case-insensitive allow
	}
	for _, c := range cases {
		t.Run(c.ua, func(t *testing.T) {
			if got := isAllowedBot(c.ua); got != c.wantAllow {
				t.Errorf("isAllowedBot(%q) = %v, want %v", c.ua, got, c.wantAllow)
			}
		})
	}
}

func TestIsAllowedBot_EmptyString(t *testing.T) {
	if isAllowedBot("") {
		t.Error("isAllowedBot(\"\") should return false")
	}
}
