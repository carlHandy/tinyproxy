package cache

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCacheSetGet(t *testing.T) {
	c := New(1 << 20) // 1MB

	entry := &CacheEntry{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Body:       []byte("hello"),
		StoredAt:   time.Now(),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
		ETag:       `"abc123"`,
	}

	c.Set("test-key", entry)

	got, hit := c.Get("test-key")
	if !hit {
		t.Fatal("expected cache hit")
	}
	if got.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", got.StatusCode)
	}
	if string(got.Body) != "hello" {
		t.Errorf("Body = %q, want %q", got.Body, "hello")
	}
	if got.ETag != `"abc123"` {
		t.Errorf("ETag = %q, want %q", got.ETag, `"abc123"`)
	}
}

func TestCacheMiss(t *testing.T) {
	c := New(1 << 20)

	_, hit := c.Get("nonexistent")
	if hit {
		t.Fatal("expected cache miss for nonexistent key")
	}
}

func TestCacheExpiry(t *testing.T) {
	c := New(1 << 20)

	entry := &CacheEntry{
		StatusCode: 200,
		Body:       []byte("stale"),
		StoredAt:   time.Now().Add(-10 * time.Minute),
		ExpiresAt:  time.Now().Add(-1 * time.Minute), // already expired
	}
	c.Set("expired-key", entry)

	_, hit := c.Get("expired-key")
	if hit {
		t.Fatal("expected cache miss for expired entry")
	}
}

func TestCacheDelete(t *testing.T) {
	c := New(1 << 20)
	c.Set("key1", &CacheEntry{
		Body:      []byte("val"),
		StoredAt:  time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	c.Delete("key1")

	_, hit := c.Get("key1")
	if hit {
		t.Fatal("expected miss after delete")
	}
}

func TestCachePurge(t *testing.T) {
	c := New(1 << 20)
	for i := 0; i < 100; i++ {
		c.Set("key-"+string(rune(i)), &CacheEntry{
			Body:      []byte("v"),
			StoredAt:  time.Now(),
			ExpiresAt: time.Now().Add(5 * time.Minute),
		})
	}
	c.Purge()

	stats := c.GetStats()
	if stats.Bytes != 0 {
		t.Errorf("after purge Bytes = %d, want 0", stats.Bytes)
	}
}

func TestCacheEviction(t *testing.T) {
	// Tiny cache: 1KB max
	c := New(1024)

	bigBody := make([]byte, 800)
	for i := range bigBody {
		bigBody[i] = 'X'
	}

	c.Set("a", &CacheEntry{
		Body:      bigBody,
		StoredAt:  time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})
	c.Set("b", &CacheEntry{
		Body:      bigBody,
		StoredAt:  time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	stats := c.GetStats()
	if stats.Evictions == 0 {
		t.Error("expected at least one eviction when exceeding max size")
	}
}

func TestCacheStats(t *testing.T) {
	c := New(1 << 20)
	c.Set("k", &CacheEntry{
		Body:      []byte("data"),
		StoredAt:  time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	c.Get("k")       // hit
	c.Get("missing")  // miss

	stats := c.GetStats()
	if stats.Hits != 1 {
		t.Errorf("Hits = %d, want 1", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("Misses = %d, want 1", stats.Misses)
	}
	if stats.Stores != 1 {
		t.Errorf("Stores = %d, want 1", stats.Stores)
	}
}

func TestHandlerCacheMissAndHit(t *testing.T) {
	cfg := DefaultCacheConfig()
	cfg.Enabled = true

	c := New(cfg.MaxSize)

	callCount := 0
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write([]byte("upstream response"))
	})

	handler := Handler(cfg, c)(upstream)

	// First request: MISS
	req := httptest.NewRequest("GET", "http://example.com/page", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Header().Get("X-Cache") != "MISS" {
		t.Errorf("first request X-Cache = %q, want MISS", rr.Header().Get("X-Cache"))
	}
	if rr.Body.String() != "upstream response" {
		t.Errorf("body = %q, want %q", rr.Body.String(), "upstream response")
	}

	// Second request: HIT
	req2 := httptest.NewRequest("GET", "http://example.com/page", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("second request X-Cache = %q, want HIT", rr2.Header().Get("X-Cache"))
	}
	if callCount != 1 {
		t.Errorf("upstream called %d times, want 1 (should serve from cache)", callCount)
	}
}

func TestHandlerBypassHeader(t *testing.T) {
	cfg := DefaultCacheConfig()
	cfg.Enabled = true
	cfg.BypassHeader = "X-Cache-Bypass"

	c := New(cfg.MaxSize)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("fresh"))
	})

	handler := Handler(cfg, c)(upstream)

	req := httptest.NewRequest("GET", "http://example.com/page", nil)
	req.Header.Set("X-Cache-Bypass", "1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Header().Get("X-Cache") != "BYPASS" {
		t.Errorf("X-Cache = %q, want BYPASS", rr.Header().Get("X-Cache"))
	}
}

func TestHandlerNoCacheDirective(t *testing.T) {
	cfg := DefaultCacheConfig()
	cfg.Enabled = true

	c := New(cfg.MaxSize)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(200)
		w.Write([]byte("private"))
	})

	handler := Handler(cfg, c)(upstream)

	// Request 1
	req := httptest.NewRequest("GET", "http://example.com/secret", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Request 2 should still be a miss (no-store response should not be cached)
	req2 := httptest.NewRequest("GET", "http://example.com/secret", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Header().Get("X-Cache") != "MISS" {
		t.Errorf("no-store response X-Cache = %q, want MISS", rr2.Header().Get("X-Cache"))
	}
}

func TestHandlerPostNotCached(t *testing.T) {
	cfg := DefaultCacheConfig()
	cfg.Enabled = true

	c := New(cfg.MaxSize)

	callCount := 0
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})

	handler := Handler(cfg, c)(upstream)

	// POST should not be cached
	req := httptest.NewRequest("POST", "http://example.com/api", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	req2 := httptest.NewRequest("POST", "http://example.com/api", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if callCount != 2 {
		t.Errorf("POST upstream called %d times, want 2 (POST should not be cached)", callCount)
	}
}

func TestHandlerConditionalETag(t *testing.T) {
	cfg := DefaultCacheConfig()
	cfg.Enabled = true

	c := New(cfg.MaxSize)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"etag123"`)
		w.WriteHeader(200)
		w.Write([]byte("content"))
	})

	handler := Handler(cfg, c)(upstream)

	// Populate cache
	req := httptest.NewRequest("GET", "http://example.com/resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Conditional request with matching ETag
	req2 := httptest.NewRequest("GET", "http://example.com/resource", nil)
	req2.Header.Set("If-None-Match", `"etag123"`)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != 304 {
		t.Errorf("conditional request status = %d, want 304", rr2.Code)
	}
}
