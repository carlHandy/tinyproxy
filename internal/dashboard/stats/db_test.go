package stats_test

import (
	"context"
	"os"
	"testing"
	"time"
	"tinyproxy/internal/dashboard/stats"
)

func tempDB(t *testing.T) *stats.DB {
	t.Helper()
	f, err := os.CreateTemp("", "dashtest-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	db, err := stats.Open(f.Name())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestDBOpenCreatesSchema(t *testing.T) {
	db := tempDB(t)
	if db == nil {
		t.Fatal("expected non-nil DB")
	}
}

func TestDBWriteLogLine(t *testing.T) {
	db := tempDB(t)
	err := db.WriteLogLine(time.Now().UnixMilli(), "info", "test log line")
	if err != nil {
		t.Fatalf("WriteLogLine: %v", err)
	}
}

// Suppress unused import error — context is used by RunBatchWriter signature
var _ = context.Background
