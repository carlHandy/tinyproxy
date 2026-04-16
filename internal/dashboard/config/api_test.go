package dashconfig_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	dashconfig "tinyproxy/internal/dashboard/config"
)

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "vhosts-*.conf")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(content)
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

const validConfig = `
vhosts {
    default {
        root static
    }
}
`

func TestHandleGetReturnsConfig(t *testing.T) {
	path := writeTempConfig(t, validConfig)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/config", nil)
	dashconfig.HandleGet(path).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["raw"] == nil {
		t.Error("expected 'raw' field")
	}
}

func TestHandleValidateRejectsInvalid(t *testing.T) {
	path := writeTempConfig(t, validConfig)
	body := bytes.NewBufferString("this is not valid config %%%")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/config/validate", body)
	dashconfig.HandleValidate(path).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d", rec.Code)
	}
}

func TestHandleValidateAcceptsValid(t *testing.T) {
	path := writeTempConfig(t, validConfig)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/config/validate", strings.NewReader(validConfig))
	dashconfig.HandleValidate(path).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandlePutAtomicWrite(t *testing.T) {
	path := writeTempConfig(t, validConfig)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/config", strings.NewReader(validConfig+"\n# updated\n"))
	dashconfig.HandlePut(path, nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "# updated") {
		t.Error("config file not updated")
	}
}
