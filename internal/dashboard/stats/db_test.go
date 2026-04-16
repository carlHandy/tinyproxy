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

func TestDBBatchWriterFlushesRecords(t *testing.T) {
	db := tempDB(t)
	c := stats.NewCollector(64)
	ctx, cancel := context.WithCancel(context.Background())

	go db.RunBatchWriter(ctx, c.Chan())

	now := time.Now().UnixMilli()
	for i := 0; i < 5; i++ {
		c.Record(stats.RequestRecord{
			TS: now, VHost: "test.com", Method: "GET",
			Path: "/", Status: 200, Latency: 1000, Bytes: 512, Remote: "1.2.3.4",
		})
	}
	cancel()
	time.Sleep(50 * time.Millisecond)

	result, err := db.QueryStats(time.Hour)
	if err != nil {
		t.Fatalf("QueryStats: %v", err)
	}
	if result.TotalRequests < 5 {
		t.Fatalf("expected >= 5 records, got %d", result.TotalRequests)
	}
}

func TestQueryStatsReturnsAggregates(t *testing.T) {
	db := tempDB(t)
	now := time.Now().UnixMilli()
	for i := 0; i < 8; i++ {
		db.WriteRequestDirect(stats.RequestRecord{TS: now, VHost: "a.com", Method: "GET", Path: "/", Status: 200, Latency: 2000, Bytes: 100, Remote: "1.1.1.1"})
	}
	for i := 0; i < 2; i++ {
		db.WriteRequestDirect(stats.RequestRecord{TS: now, VHost: "b.com", Method: "POST", Path: "/err", Status: 500, Latency: 5000, Bytes: 50, Remote: "2.2.2.2"})
	}

	result, err := db.QueryStats(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalRequests != 10 {
		t.Errorf("TotalRequests: got %d, want 10", result.TotalRequests)
	}
	if result.ErrorRate < 0.19 || result.ErrorRate > 0.21 {
		t.Errorf("ErrorRate: got %f, want ~0.2", result.ErrorRate)
	}
	if len(result.TopVHosts) == 0 {
		t.Error("expected top vhosts")
	}
	if result.StatusCodes["200"] != 8 {
		t.Errorf("StatusCodes[200]: got %d, want 8", result.StatusCodes["200"])
	}
}

func TestQueryLogsFilters(t *testing.T) {
	db := tempDB(t)
	now := time.Now().UnixMilli()
	db.WriteLogLine(now, "info", "startup complete")
	db.WriteLogLine(now+1, "error", "connection refused")
	db.WriteLogLine(now+2, "info", "request served")

	all, _ := db.QueryLogs(0, 10, "", "")
	if len(all) != 3 {
		t.Fatalf("want 3, got %d", len(all))
	}
	errors, _ := db.QueryLogs(0, 10, "", "error")
	if len(errors) != 1 || errors[0].Body != "connection refused" {
		t.Fatalf("expected 1 error line, got %v", errors)
	}
}
