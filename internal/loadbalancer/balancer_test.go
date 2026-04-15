package loadbalancer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestConfig(strategy string, urls ...string) LBConfig {
	backends := make([]BackendConfig, len(urls))
	for i, u := range urls {
		backends[i] = BackendConfig{URL: u, Weight: 1}
	}
	return LBConfig{
		Strategy:   strategy,
		CookieName: "_tp_test",
		Backends:   backends,
		HealthCheck: HealthCheckConfig{
			Enabled: false, // disable for unit tests
		},
	}
}

func TestRoundRobin(t *testing.T) {
	cfg := newTestConfig("round_robin", "http://a:1", "http://b:2", "http://c:3")
	lb, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]int{}
	for i := 0; i < 9; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		b, err := lb.Next(req)
		if err != nil {
			t.Fatal(err)
		}
		seen[b.URL]++
	}

	// Round-robin should distribute evenly
	for url, count := range seen {
		if count != 3 {
			t.Errorf("backend %s got %d requests, want 3", url, count)
		}
	}
}

func TestLeastConn(t *testing.T) {
	cfg := newTestConfig("least_conn", "http://a:1", "http://b:2")
	lb, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Mark one backend as busy
	req := httptest.NewRequest("GET", "/", nil)
	b1, _ := lb.Next(req)
	lb.MarkActive(b1)

	// Next request should go to the other backend
	req2 := httptest.NewRequest("GET", "/", nil)
	b2, _ := lb.Next(req2)

	if b1.URL == b2.URL {
		t.Error("least_conn should have picked the backend with fewer connections")
	}

	lb.MarkDone(b1)
}

func TestIPHash(t *testing.T) {
	cfg := newTestConfig("ip_hash", "http://a:1", "http://b:2", "http://c:3")
	lb, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	// Same IP should always get the same backend
	var firstURL string
	for i := 0; i < 10; i++ {
		b, err := lb.Next(req)
		if err != nil {
			t.Fatal(err)
		}
		if firstURL == "" {
			firstURL = b.URL
		} else if b.URL != firstURL {
			t.Errorf("ip_hash inconsistent: got %s, expected %s", b.URL, firstURL)
		}
	}
}

func TestCookieAffinity(t *testing.T) {
	cfg := newTestConfig("cookie", "http://a:1", "http://b:2")
	lb, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// First request — no cookie, gets assigned a backend
	req1 := httptest.NewRequest("GET", "/", nil)
	b1, err := lb.Next(req1)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the cookie being set
	rr := httptest.NewRecorder()
	lb.SetAffinityCookie(rr, b1)

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected affinity cookie to be set")
	}

	// Second request — with the cookie, should get the same backend
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(cookies[0])
	b2, err := lb.Next(req2)
	if err != nil {
		t.Fatal(err)
	}

	if b1.URL != b2.URL {
		t.Errorf("cookie affinity broken: first=%s, second=%s", b1.URL, b2.URL)
	}
}

func TestCookieAffinityDeadBackendFallback(t *testing.T) {
	cfg := newTestConfig("cookie", "http://a:1", "http://b:2")
	lb, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Assign backend
	req := httptest.NewRequest("GET", "/", nil)
	b1, _ := lb.Next(req)
	rr := httptest.NewRecorder()
	lb.SetAffinityCookie(rr, b1)
	cookies := rr.Result().Cookies()

	// Mark that backend as dead
	b1.SetAlive(false)

	// Request with stale cookie should fall through to another backend
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(cookies[0])
	b2, err := lb.Next(req2)
	if err != nil {
		t.Fatal("expected fallback to alive backend, got error:", err)
	}
	if b2.URL == b1.URL {
		t.Error("should not route to dead backend")
	}
}

func TestWeightedDistribution(t *testing.T) {
	cfg := LBConfig{
		Strategy:   "weighted",
		CookieName: "_tp_test",
		Backends: []BackendConfig{
			{URL: "http://heavy:1", Weight: 3},
			{URL: "http://light:1", Weight: 1},
		},
		HealthCheck: HealthCheckConfig{Enabled: false},
	}
	lb, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]int{}
	for i := 0; i < 1000; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		b, _ := lb.Next(req)
		seen[b.URL]++
	}

	// Heavy backend (weight 3) should get roughly 3x the traffic of light (weight 1)
	ratio := float64(seen["http://heavy:1"]) / float64(seen["http://light:1"])
	if ratio < 2.0 || ratio > 4.5 {
		t.Errorf("weighted ratio = %.2f, expected ~3.0 (heavy=%d, light=%d)",
			ratio, seen["http://heavy:1"], seen["http://light:1"])
	}
}

func TestNoHealthyBackends(t *testing.T) {
	cfg := newTestConfig("round_robin", "http://a:1")
	lb, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Mark all backends down
	for _, b := range lb.Backends() {
		b.SetAlive(false)
	}

	req := httptest.NewRequest("GET", "/", nil)
	_, err = lb.Next(req)
	if err != ErrNoHealthyBackends {
		t.Errorf("expected ErrNoHealthyBackends, got %v", err)
	}
}

func TestNoBackendsConfigured(t *testing.T) {
	_, err := New(LBConfig{Strategy: "round_robin"})
	if err != ErrNoBackends {
		t.Errorf("expected ErrNoBackends, got %v", err)
	}
}

func TestSetAffinityCookieOnlyForStickyStrategies(t *testing.T) {
	cfg := newTestConfig("round_robin", "http://a:1")
	lb, _ := New(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	b, _ := lb.Next(req)

	rr := httptest.NewRecorder()
	lb.SetAffinityCookie(rr, b)

	cookies := rr.Result().Cookies()
	if len(cookies) != 0 {
		t.Error("round_robin should not set affinity cookie")
	}
}

func TestCookieProperties(t *testing.T) {
	cfg := newTestConfig("cookie", "http://a:1")
	lb, _ := New(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	b, _ := lb.Next(req)

	rr := httptest.NewRecorder()
	lb.SetAffinityCookie(rr, b)

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	c := cookies[0]
	if c.Name != "_tp_test" {
		t.Errorf("cookie name = %q, want %q", c.Name, "_tp_test")
	}
	if !c.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}
	if !c.Secure {
		t.Error("cookie should be Secure")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.MaxAge != 86400 {
		t.Errorf("MaxAge = %d, want 86400", c.MaxAge)
	}
}
