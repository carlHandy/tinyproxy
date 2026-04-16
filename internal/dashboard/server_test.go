package dashboard_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"tinyproxy/internal/dashboard"
	"tinyproxy/internal/dashboard/stats"
)

func mustHash(password string) []byte {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}
	return h
}

func TestAuthMiddlewareRejects(t *testing.T) {
	am := dashboard.NewAuthMiddleware("admin", mustHash("secret"))
	handler := am.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddlewareAccepts(t *testing.T) {
	am := dashboard.NewAuthMiddleware("admin", mustHash("secret"))
	handler := am.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "secret")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestAuthMiddlewareWrongPassword(t *testing.T) {
	am := dashboard.NewAuthMiddleware("admin", mustHash("secret"))
	handler := am.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "wrong")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRateLimiterBlocks(t *testing.T) {
	rl := dashboard.NewAuthLimiter(3)
	ip := "10.0.0.1"
	for i := 0; i < 3; i++ {
		if !rl.Allow(ip) {
			t.Fatalf("expected allow on attempt %d", i+1)
		}
	}
	if rl.Allow(ip) {
		t.Fatal("expected block after 3 failures")
	}
}

func testDB(t *testing.T) *stats.DB {
	t.Helper()
	f, _ := os.CreateTemp("", "dash-*.db")
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	db, err := stats.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestStatsHandlerReturnsJSON(t *testing.T) {
	db := testDB(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/stats?window=1h", nil)
	dashboard.NewStatsHandler(db).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var result stats.StatsResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestLogsHandlerReturnsJSON(t *testing.T) {
	db := testDB(t)
	db.WriteLogLine(time.Now().UnixMilli(), "info", "test line")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/logs?limit=10", nil)
	dashboard.NewLogsHandler(db).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}
