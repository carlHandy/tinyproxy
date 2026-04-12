package botdetect

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestBotDetect_BlocksKnownBot(t *testing.T) {
	cfg := BotConfig{Enabled: true, BlockScanners: true}
	handler := BotDetect(cfg)(okHandler())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "GPTBot/1.0")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestBotDetect_AllowsLegitCrawler(t *testing.T) {
	cfg := BotConfig{Enabled: true, BlockScanners: true}
	handler := BotDetect(cfg)(okHandler())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1)")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestBotDetect_BlocksScanner(t *testing.T) {
	cfg := BotConfig{Enabled: true, BlockScanners: true}
	handler := BotDetect(cfg)(okHandler())

	req := httptest.NewRequest("GET", "/.env", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestBotDetect_DisabledPassesAll(t *testing.T) {
	cfg := BotConfig{Enabled: false}
	handler := BotDetect(cfg)(okHandler())

	req := httptest.NewRequest("GET", "/.env", nil)
	req.Header.Set("User-Agent", "GPTBot/1.0")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 when disabled, got %d", w.Code)
	}
}

func TestBotDetect_CustomBlockedAgents(t *testing.T) {
	cfg := BotConfig{
		Enabled:       true,
		BlockedAgents: []string{"MyCustomScraper"},
	}
	handler := BotDetect(cfg)(okHandler())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "MyCustomScraper/2.0")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for custom blocked agent, got %d", w.Code)
	}
}

func TestBotDetect_CustomAllowedAgents(t *testing.T) {
	cfg := BotConfig{
		Enabled:       true,
		AllowedAgents: []string{"FriendlyBot"},
	}
	handler := BotDetect(cfg)(okHandler())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "FriendlyBot/1.0 GPTBot")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for custom allowed agent, got %d", w.Code)
	}
}
