package dashconfig

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"tinyproxy/internal/server/config"
)

// HandleGet returns the current config file as JSON {"raw": "...", "parsed": {...}}.
func HandleGet(configPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := os.ReadFile(configPath)
		if err != nil {
			http.Error(w, "failed to read config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		cfg, parseErr := config.NewParser(strings.NewReader(string(raw))).Parse()
		resp := map[string]any{"raw": string(raw)}
		if parseErr == nil {
			resp["parsed"] = cfg
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// HandleValidate parses request body as config. Returns 200 on success,
// 422 with {"error": "..."} on failure. Never writes to disk.
func HandleValidate(_ string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		if _, parseErr := config.NewParser(strings.NewReader(string(body))).Parse(); parseErr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(map[string]string{"error": parseErr.Error()})
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// HandlePut validates, atomically writes, and optionally calls sighupFn to reload.
// Pass nil sighupFn in tests to skip the reload signal.
func HandlePut(configPath string, sighupFn func()) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		if _, parseErr := config.NewParser(strings.NewReader(string(body))).Parse(); parseErr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(map[string]string{"error": parseErr.Error()})
			return
		}
		tmpPath := configPath + ".tmp"
		if err := os.WriteFile(tmpPath, body, 0644); err != nil {
			http.Error(w, "failed to write temp config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.Rename(tmpPath, configPath); err != nil {
			os.Remove(tmpPath)
			http.Error(w, "failed to replace config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if sighupFn != nil {
			sighupFn()
		}
		w.WriteHeader(http.StatusOK)
	}
}
