# Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional admin dashboard (`--enable-dashboard`) to go-tinyproxy providing config CRUD, live log streaming, and traffic analytics with SQLite persistence.

**Architecture:** A second `http.Server` runs inside the main process sharing `VHostHandler` state via a buffered channel for stats and an `io.Writer` hook for logs. Binds to `127.0.0.1:9000` by default (no auth); requires credentials file + TLS when exposed on any non-localhost address. UI is HTMX + Tailwind, embedded via `go:embed`.

**Tech Stack:** Go `database/sql` + `modernc.org/sqlite` (pure-Go, no CGo), HTMX 1.9, Tailwind CSS (pre-built), Chart.js, `golang.org/x/crypto/bcrypt`, `golang.org/x/term`.

**Security note:** All server-side values injected into HTML must be sanitised with `escapeHtml()` before use in `innerHTML` template literals. Log lines use `textContent` directly. Diff previews use `textContent` on `<pre>` elements.

---

## File Map

**New files:**
- `internal/dashboard/stats/collector.go` — `RequestRecord` type + `Collector` (buffered channel)
- `internal/dashboard/stats/collector_test.go`
- `internal/dashboard/stats/db.go` — SQLite schema, batch writer, pruning, query methods
- `internal/dashboard/stats/db_test.go`
- `internal/dashboard/logring/buffer.go` — ring buffer, `io.Writer` hook, SSE fan-out
- `internal/dashboard/logring/buffer_test.go`
- `internal/dashboard/config/api.go` — GET/POST validate/PUT `/api/config` handlers
- `internal/dashboard/config/api_test.go`
- `internal/dashboard/server.go` — `dashboard.Server`, route registration, auth + rate-limit middleware
- `internal/dashboard/server_test.go`
- `internal/dashboard/static/index.html` — HTMX + Tailwind shell
- `internal/dashboard/static/dashboard.css` — pre-built Tailwind output
- `internal/dashboard/static/dashboard.js` — SSE wiring, diff preview, Chart.js init
- `cmd/tinyproxy/dashboard_flags.go` — flag definitions, startup validation, `isLocalhostAddr`
- `cmd/tinyproxy/dashboard_flags_test.go`

**Modified files:**
- `go.mod` / `go.sum` — add `modernc.org/sqlite`, `golang.org/x/term`
- `cmd/tinyproxy/main.go` — `responseWriter` wrapper, `VHostHandler.stats` field, dashboard server start/stop, `dashboard passwd` subcommand

---

## Task 1: Add dependencies

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add SQLite and term dependencies**

```bash
cd /path/to/tinyproxy
go get modernc.org/sqlite@latest
go get golang.org/x/term@latest
```

- [ ] **Step 2: Verify build still compiles**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add modernc.org/sqlite and golang.org/x/term dependencies"
```

---

## Task 2: `stats.Collector` — request record type and buffered channel

**Files:**
- Create: `internal/dashboard/stats/collector.go`
- Create: `internal/dashboard/stats/collector_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/dashboard/stats/collector_test.go
package stats_test

import (
	"testing"
	"tinyproxy/internal/dashboard/stats"
)

func TestCollectorRecordNonBlocking(t *testing.T) {
	c := stats.NewCollector(2)
	c.Record(stats.RequestRecord{VHost: "a.com", Status: 200})
	c.Record(stats.RequestRecord{VHost: "b.com", Status: 404})
	done := make(chan struct{})
	go func() {
		c.Record(stats.RequestRecord{VHost: "c.com", Status: 500})
		close(done)
	}()
	select {
	case <-done:
	default:
		t.Fatal("Record blocked on full buffer")
	}
}

func TestCollectorChan(t *testing.T) {
	c := stats.NewCollector(8)
	r := stats.RequestRecord{VHost: "x.com", Method: "GET", Status: 200, Latency: 1000}
	c.Record(r)
	got := <-c.Chan()
	if got.VHost != "x.com" || got.Status != 200 {
		t.Fatalf("unexpected record: %+v", got)
	}
}
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
go test ./internal/dashboard/stats/... -v
```

Expected: `cannot find package` or `undefined: stats.NewCollector`.

- [ ] **Step 3: Write implementation**

```go
// internal/dashboard/stats/collector.go
package stats

import "log"

// RequestRecord holds per-request data recorded by the proxy.
type RequestRecord struct {
	TS      int64  // unix milliseconds
	VHost   string
	Method  string
	Path    string
	Status  int
	Latency int64 // microseconds
	Bytes   int64
	Remote  string
}

// Collector receives RequestRecords from the proxy handler via a buffered
// channel. Record is non-blocking — a full buffer drops and logs the record.
type Collector struct {
	ch chan RequestRecord
}

// NewCollector creates a Collector with a channel buffer of bufSize.
func NewCollector(bufSize int) *Collector {
	return &Collector{ch: make(chan RequestRecord, bufSize)}
}

// Record sends r to the collector. Returns immediately; drops if full.
func (c *Collector) Record(r RequestRecord) {
	select {
	case c.ch <- r:
	default:
		log.Println("dashboard: stats buffer full, record dropped")
	}
}

// Chan returns the receive-only channel consumed by the DB batch writer.
func (c *Collector) Chan() <-chan RequestRecord {
	return c.ch
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/dashboard/stats/... -v
```

Expected: `PASS`.

- [ ] **Step 5: Commit**

```bash
git add internal/dashboard/stats/collector.go internal/dashboard/stats/collector_test.go
git commit -m "feat(dashboard): add stats.Collector with non-blocking record channel"
```

---

## Task 3: `stats.DB` — SQLite schema, batch writer, pruning

**Files:**
- Create: `internal/dashboard/stats/db.go`
- Create: `internal/dashboard/stats/db_test.go`

- [ ] **Step 1: Write failing tests**

```go
// internal/dashboard/stats/db_test.go
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

func TestDBWriteLogLine(t *testing.T) {
	db := tempDB(t)
	err := db.WriteLogLine(time.Now().UnixMilli(), "info", "test log line")
	if err != nil {
		t.Fatalf("WriteLogLine: %v", err)
	}
	lines, err := db.QueryLogs(0, 10, "", "")
	if err != nil {
		t.Fatalf("QueryLogs: %v", err)
	}
	if len(lines) == 0 {
		t.Fatal("expected at least 1 log line")
	}
	if lines[0].Body != "test log line" {
		t.Fatalf("unexpected body: %q", lines[0].Body)
	}
}
```

- [ ] **Step 2: Run tests to confirm failure**

```bash
go test ./internal/dashboard/stats/... -v -run TestDB
```

Expected: compile error — `stats.Open` undefined.

- [ ] **Step 3: Write implementation**

```go
// internal/dashboard/stats/db.go
package stats

import (
	"context"
	"database/sql"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS requests (
	id      INTEGER PRIMARY KEY,
	ts      INTEGER NOT NULL,
	vhost   TEXT NOT NULL,
	method  TEXT NOT NULL,
	path    TEXT NOT NULL,
	status  INTEGER NOT NULL,
	latency INTEGER NOT NULL,
	bytes   INTEGER NOT NULL,
	remote  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_requests_ts    ON requests(ts);
CREATE INDEX IF NOT EXISTS idx_requests_vhost ON requests(vhost, ts);

CREATE TABLE IF NOT EXISTS log_lines (
	id    INTEGER PRIMARY KEY,
	ts    INTEGER NOT NULL,
	level TEXT NOT NULL,
	body  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_log_lines_ts ON log_lines(ts);
`

// DB wraps a SQLite database for stats and log persistence.
type DB struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path, initialises the schema,
// and prunes rows older than 30 days.
func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	d := &DB{db: db}
	d.prune()
	return d, nil
}

// Close closes the underlying database.
func (d *DB) Close() error { return d.db.Close() }

func (d *DB) prune() {
	cutoff := time.Now().AddDate(0, 0, -30).UnixMilli()
	d.db.Exec(`DELETE FROM requests WHERE ts < ?`, cutoff)
	d.db.Exec(`DELETE FROM log_lines WHERE ts < ?`, cutoff)
}

// RunBatchWriter reads RequestRecords from ch and writes them to SQLite in
// batches every 5 seconds. Flushes remaining records when ctx is cancelled.
func (d *DB) RunBatchWriter(ctx context.Context, ch <-chan RequestRecord) {
	var batch []RequestRecord
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case r := <-ch:
			batch = append(batch, r)
		case <-ticker.C:
			if len(batch) > 0 {
				if err := d.writeBatch(batch); err != nil {
					log.Printf("dashboard: stats batch write error: %v", err)
				}
				batch = batch[:0]
			}
		case <-ctx.Done():
			if len(batch) > 0 {
				d.writeBatch(batch)
			}
			return
		}
	}
}

func (d *DB) writeBatch(records []RequestRecord) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO requests (ts,vhost,method,path,status,latency,bytes,remote) VALUES (?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range records {
		if _, err := stmt.Exec(r.TS, r.VHost, r.Method, r.Path, r.Status, r.Latency, r.Bytes, r.Remote); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// WriteLogLine persists a single log line.
func (d *DB) WriteLogLine(ts int64, level, body string) error {
	_, err := d.db.Exec(`INSERT INTO log_lines (ts,level,body) VALUES (?,?,?)`, ts, level, body)
	return err
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/dashboard/stats/... -v -run TestDBOpen|TestDBWriteLog
```

Expected: PASS (batch writer test needs query methods — covered in Task 4).

- [ ] **Step 5: Commit**

```bash
git add internal/dashboard/stats/db.go internal/dashboard/stats/db_test.go
git commit -m "feat(dashboard): add stats.DB with SQLite schema, batch writer, pruning"
```

---

## Task 4: `stats.DB` — query methods

**Files:**
- Modify: `internal/dashboard/stats/db.go` (append query types and methods)
- Modify: `internal/dashboard/stats/db_test.go` (append query tests)

- [ ] **Step 1: Add query tests**

Append to `internal/dashboard/stats/db_test.go`:

```go
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
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/dashboard/stats/... -v -run TestQuery
```

Expected: compile error — `WriteRequestDirect` and `QueryStats` undefined.

- [ ] **Step 3: Append query types and methods to `db.go`**

```go
// StatsResult is the payload for GET /api/stats.
type StatsResult struct {
	Window        string           `json:"window"`
	TotalRequests int64            `json:"total_requests"`
	ErrorRate     float64          `json:"error_rate"`
	AvgLatencyUS  float64          `json:"avg_latency_us"`
	TotalBytes    int64            `json:"total_bytes"`
	RPSSeries     []RPSPoint       `json:"rps_series"`
	TopVHosts     []CountEntry     `json:"top_vhosts"`
	TopPaths      []CountEntry     `json:"top_paths"`
	StatusCodes   map[string]int64 `json:"status_codes"`
	TopIPs        []CountEntry     `json:"top_ips"`
}

// RPSPoint is one data point in the requests-per-second time series.
type RPSPoint struct {
	TS  int64   `json:"ts"`
	RPS float64 `json:"rps"`
}

// CountEntry is a key + count pair used for ranked lists.
type CountEntry struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// LogLine is a single persisted log entry.
type LogLine struct {
	TS    int64  `json:"ts"`
	Level string `json:"level"`
	Body  string `json:"body"`
}

// WriteRequestDirect is a test helper that bypasses the batch writer.
func (d *DB) WriteRequestDirect(r RequestRecord) error {
	_, err := d.db.Exec(
		`INSERT INTO requests (ts,vhost,method,path,status,latency,bytes,remote) VALUES (?,?,?,?,?,?,?,?)`,
		r.TS, r.VHost, r.Method, r.Path, r.Status, r.Latency, r.Bytes, r.Remote)
	return err
}

// QueryStats returns aggregated traffic statistics for the given window.
func (d *DB) QueryStats(window time.Duration) (*StatsResult, error) {
	since := time.Now().Add(-window).UnixMilli()
	result := &StatsResult{
		Window:      window.String(),
		StatusCodes: make(map[string]int64),
	}

	row := d.db.QueryRow(`
		SELECT COUNT(*),
		       CAST(SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END) AS REAL) / MAX(CAST(COUNT(*) AS REAL), 1),
		       COALESCE(AVG(CAST(latency AS REAL)), 0),
		       COALESCE(SUM(bytes), 0)
		FROM requests WHERE ts >= ?`, since)
	if err := row.Scan(&result.TotalRequests, &result.ErrorRate, &result.AvgLatencyUS, &result.TotalBytes); err != nil {
		return nil, err
	}

	// RPS series — 1-minute buckets
	bucketMs := int64(60 * 1000)
	rows, err := d.db.Query(`
		SELECT (ts / ?) * ? AS bucket, CAST(COUNT(*) AS REAL) / 60.0
		FROM requests WHERE ts >= ?
		GROUP BY bucket ORDER BY bucket`, bucketMs, bucketMs, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var p RPSPoint
		rows.Scan(&p.TS, &p.RPS)
		result.RPSSeries = append(result.RPSSeries, p)
	}

	result.TopVHosts, err = d.queryTopN(`SELECT vhost, COUNT(*) FROM requests WHERE ts >= ? GROUP BY vhost ORDER BY COUNT(*) DESC LIMIT 10`, since)
	if err != nil {
		return nil, err
	}
	result.TopPaths, err = d.queryTopN(`SELECT path, COUNT(*) FROM requests WHERE ts >= ? GROUP BY path ORDER BY COUNT(*) DESC LIMIT 10`, since)
	if err != nil {
		return nil, err
	}

	rows2, err := d.db.Query(`SELECT CAST(status AS TEXT), COUNT(*) FROM requests WHERE ts >= ? GROUP BY status`, since)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var code string
		var count int64
		rows2.Scan(&code, &count)
		result.StatusCodes[code] = count
	}

	result.TopIPs, err = d.queryTopN(`SELECT remote, COUNT(*) FROM requests WHERE ts >= ? GROUP BY remote ORDER BY COUNT(*) DESC LIMIT 10`, since)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (d *DB) queryTopN(query string, args ...any) ([]CountEntry, error) {
	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []CountEntry
	for rows.Next() {
		var e CountEntry
		rows.Scan(&e.Key, &e.Count)
		entries = append(entries, e)
	}
	return entries, nil
}

// QueryLogs returns log lines ordered by ts DESC, with optional filters.
// before=0 means most recent. Empty level or vhost disables those filters.
func (d *DB) QueryLogs(before int64, limit int, vhost, level string) ([]LogLine, error) {
	q := `SELECT ts, level, body FROM log_lines WHERE 1=1`
	var args []any
	if before > 0 {
		q += ` AND ts < ?`
		args = append(args, before)
	}
	if level != "" {
		q += ` AND level = ?`
		args = append(args, level)
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)

	rows, err := d.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var lines []LogLine
	for rows.Next() {
		var l LogLine
		rows.Scan(&l.TS, &l.Level, &l.Body)
		lines = append(lines, l)
	}
	return lines, nil
}
```

- [ ] **Step 4: Run all stats tests**

```bash
go test ./internal/dashboard/stats/... -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/dashboard/stats/db.go internal/dashboard/stats/db_test.go
git commit -m "feat(dashboard): add stats.DB query methods (QueryStats, QueryLogs)"
```

---

## Task 5: `logring.Buffer` — ring buffer, log capture, SSE fan-out

**Files:**
- Create: `internal/dashboard/logring/buffer.go`
- Create: `internal/dashboard/logring/buffer_test.go`

- [ ] **Step 1: Write failing tests**

```go
// internal/dashboard/logring/buffer_test.go
package logring_test

import (
	"bytes"
	"strings"
	"testing"
	"tinyproxy/internal/dashboard/logring"
)

func TestBufferCapturesWrites(t *testing.T) {
	var underlying bytes.Buffer
	b := logring.New(100, &underlying)
	b.Write([]byte("hello world\n"))
	b.Write([]byte("second line\n"))

	recent := b.Recent(10)
	if len(recent) != 2 {
		t.Fatalf("want 2 lines, got %d", len(recent))
	}
	if recent[0].Body != "hello world" {
		t.Errorf("unexpected body: %q", recent[0].Body)
	}
	if !strings.Contains(underlying.String(), "hello world") {
		t.Error("underlying writer not written to")
	}
}

func TestBufferRingWraps(t *testing.T) {
	b := logring.New(3, nil)
	b.Write([]byte("line1\n"))
	b.Write([]byte("line2\n"))
	b.Write([]byte("line3\n"))
	b.Write([]byte("line4\n"))

	recent := b.Recent(3)
	if len(recent) != 3 {
		t.Fatalf("want 3, got %d", len(recent))
	}
	if recent[0].Body != "line2" {
		t.Errorf("expected line2 as oldest after wrap, got %q", recent[0].Body)
	}
	if recent[2].Body != "line4" {
		t.Errorf("expected line4 as newest, got %q", recent[2].Body)
	}
}

func TestBufferLevelDetection(t *testing.T) {
	b := logring.New(10, nil)
	b.Write([]byte("INFO: normal\n"))
	b.Write([]byte("ERROR: something bad\n"))

	recent := b.Recent(2)
	if recent[0].Level != "info" {
		t.Errorf("expected info, got %q", recent[0].Level)
	}
	if recent[1].Level != "error" {
		t.Errorf("expected error, got %q", recent[1].Level)
	}
}

func TestBufferSubscribeFanOut(t *testing.T) {
	b := logring.New(100, nil)
	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	b.Write([]byte("broadcast\n"))

	select {
	case line := <-ch:
		if line.Body != "broadcast" {
			t.Errorf("unexpected: %q", line.Body)
		}
	default:
		t.Fatal("subscriber did not receive line")
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/dashboard/logring/... -v
```

Expected: `cannot find package`.

- [ ] **Step 3: Write implementation**

```go
// internal/dashboard/logring/buffer.go
package logring

import (
	"io"
	"strings"
	"sync"
	"time"
)

// LogLine is a single captured log entry.
type LogLine struct {
	TS    int64  `json:"ts"`
	Level string `json:"level"`
	Body  string `json:"body"`
}

// Buffer captures log output into a fixed-size ring buffer and fans out
// to SSE subscribers. It implements io.Writer for use with log.SetOutput.
type Buffer struct {
	mu         sync.RWMutex
	lines      []LogLine
	maxSize    int
	size       int
	head       int
	subs       map[chan LogLine]struct{}
	underlying io.Writer
}

// New returns a Buffer with the given capacity.
// Writes are also forwarded to underlying (may be nil).
func New(maxSize int, underlying io.Writer) *Buffer {
	return &Buffer{
		lines:      make([]LogLine, maxSize),
		maxSize:    maxSize,
		subs:       make(map[chan LogLine]struct{}),
		underlying: underlying,
	}
}

// Write implements io.Writer. Called by the log package for each log line.
func (b *Buffer) Write(p []byte) (int, error) {
	body := strings.TrimRight(string(p), "\n\r")
	level := "info"
	lower := strings.ToLower(body)
	if strings.Contains(lower, "error") || strings.Contains(lower, "panic") || strings.Contains(lower, "fatal") {
		level = "error"
	}
	line := LogLine{
		TS:    time.Now().UnixMilli(),
		Level: level,
		Body:  body,
	}

	b.mu.Lock()
	b.lines[b.head] = line
	b.head = (b.head + 1) % b.maxSize
	if b.size < b.maxSize {
		b.size++
	}
	subs := make([]chan LogLine, 0, len(b.subs))
	for ch := range b.subs {
		subs = append(subs, ch)
	}
	b.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- line:
		default:
			// subscriber too slow; drop rather than block
		}
	}

	if b.underlying != nil {
		b.underlying.Write(p)
	}
	return len(p), nil
}

// Recent returns up to n most recent log lines in chronological order.
func (b *Buffer) Recent(n int) []LogLine {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if n > b.size {
		n = b.size
	}
	result := make([]LogLine, n)
	for i := 0; i < n; i++ {
		idx := ((b.head - n + i) + b.maxSize) % b.maxSize
		result[i] = b.lines[idx]
	}
	return result
}

// Subscribe returns a channel that receives new log lines as they arrive.
func (b *Buffer) Subscribe() chan LogLine {
	ch := make(chan LogLine, 64)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes ch from the fan-out set and closes it.
func (b *Buffer) Unsubscribe(ch chan LogLine) {
	b.mu.Lock()
	delete(b.subs, ch)
	b.mu.Unlock()
	close(ch)
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/dashboard/logring/... -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/dashboard/logring/buffer.go internal/dashboard/logring/buffer_test.go
git commit -m "feat(dashboard): add logring.Buffer with ring buffer and SSE fan-out"
```

---

## Task 6: Dashboard auth middleware and brute-force rate limiter

**Files:**
- Create: `internal/dashboard/server.go` (auth skeleton)
- Create: `internal/dashboard/server_test.go`

- [ ] **Step 1: Write failing tests**

```go
// internal/dashboard/server_test.go
package dashboard_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"tinyproxy/internal/dashboard"
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
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/dashboard/... -v -run TestAuth|TestRate
```

Expected: compile error.

- [ ] **Step 3: Write server.go auth skeleton**

```go
// internal/dashboard/server.go
package dashboard

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// AuthMiddleware enforces HTTP Basic Auth with bcrypt password comparison.
type AuthMiddleware struct {
	username string
	hash     []byte
	limiter  *AuthLimiter
}

// NewAuthMiddleware creates an AuthMiddleware for the given username and bcrypt hash.
func NewAuthMiddleware(username string, hash []byte) *AuthMiddleware {
	return &AuthMiddleware{
		username: username,
		hash:     hash,
		limiter:  NewAuthLimiter(5),
	}
}

// Wrap returns next wrapped with Basic Auth enforcement.
func (a *AuthMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := remoteIP(r)
		if !a.limiter.Allow(ip) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != a.username || bcrypt.CompareHashAndPassword(a.hash, []byte(pass)) != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="tinyproxy dashboard"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func remoteIP(r *http.Request) string {
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}

// AuthLimiter tracks failed auth attempts per IP.
type AuthLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

// NewAuthLimiter creates a limiter allowing max failed attempts per minute per IP.
func NewAuthLimiter(max int) *AuthLimiter {
	return &AuthLimiter{
		hits:   make(map[string][]time.Time),
		max:    max,
		window: time.Minute,
	}
}

// Allow records a failed attempt for ip and returns false if the limit is exceeded.
func (l *AuthLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-l.window)
	hits := l.hits[ip]
	i := 0
	for ; i < len(hits) && hits[i].Before(cutoff); i++ {
	}
	hits = hits[i:]
	if len(hits) >= l.max {
		l.hits[ip] = hits
		return false
	}
	l.hits[ip] = append(hits, now)
	return true
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/dashboard/... -v -run TestAuth|TestRate
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/dashboard/server.go internal/dashboard/server_test.go
git commit -m "feat(dashboard): add auth middleware with bcrypt and per-IP rate limiter"
```

---

## Task 7: Config API handlers

**Files:**
- Create: `internal/dashboard/config/api.go`
- Create: `internal/dashboard/config/api_test.go`

- [ ] **Step 1: Write failing tests**

```go
// internal/dashboard/config/api_test.go
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
vhost default {
    root static
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
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/dashboard/config/... -v
```

Expected: compile error.

- [ ] **Step 3: Write implementation**

```go
// internal/dashboard/config/api.go
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
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/dashboard/config/... -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/dashboard/config/api.go internal/dashboard/config/api_test.go
git commit -m "feat(dashboard): add config API handlers (GET, validate, PUT atomic write)"
```

---

## Task 8: Stats and Logs API handlers + SSE endpoint

**Files:**
- Modify: `internal/dashboard/server.go` (append handler functions)
- Modify: `internal/dashboard/server_test.go` (append handler tests)

- [ ] **Step 1: Add handler tests**

Append to `internal/dashboard/server_test.go`:

```go
import (
	// Add to existing imports:
	"encoding/json"
	"os"
	"time"

	"tinyproxy/internal/dashboard/stats"
)

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
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/dashboard/... -v -run TestStats|TestLogs
```

Expected: `NewStatsHandler` undefined.

- [ ] **Step 3: Append handler functions to server.go**

```go
// Add to import block: "encoding/json", "fmt", "strconv", "time",
// "tinyproxy/internal/dashboard/logring", "tinyproxy/internal/dashboard/stats"

// NewStatsHandler returns an http.Handler for GET /api/stats.
func NewStatsHandler(db *stats.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		window := time.Hour
		switch r.URL.Query().Get("window") {
		case "6h":
			window = 6 * time.Hour
		case "24h":
			window = 24 * time.Hour
		case "7d":
			window = 7 * 24 * time.Hour
		}
		result, err := db.QueryStats(window)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
}

// NewLogsHandler returns an http.Handler for GET /api/logs.
func NewLogsHandler(db *stats.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 || limit > 500 {
			limit = 100
		}
		lines, err := db.QueryLogs(before, limit, q.Get("vhost"), q.Get("level"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(lines)
	})
}

// NewLogsStreamHandler returns an http.Handler for GET /api/logs/stream (SSE).
func NewLogsStreamHandler(buf *logring.Buffer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "SSE not supported", http.StatusInternalServerError)
			return
		}
		levelFilter := r.URL.Query().Get("level")

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		sub := buf.Subscribe()
		defer buf.Unsubscribe(sub)

		for {
			select {
			case line, ok := <-sub:
				if !ok {
					return
				}
				if levelFilter != "" && line.Level != levelFilter {
					continue
				}
				data, _ := json.Marshal(line)
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/dashboard/... -v -run TestStats|TestLogs
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/dashboard/server.go internal/dashboard/server_test.go
git commit -m "feat(dashboard): add stats, logs, and SSE stream API handlers"
```

---

## Task 9: `dashboard.Server` assembly — embed, mux, TLS, start/shutdown

**Files:**
- Modify: `internal/dashboard/server.go` (append Server struct and New/Start/Shutdown)
- Create: `internal/dashboard/static/index.html` (placeholder)
- Create: `internal/dashboard/static/dashboard.css` (placeholder)
- Create: `internal/dashboard/static/dashboard.js` (placeholder)

- [ ] **Step 1: Create placeholder static files**

`internal/dashboard/static/index.html`:
```html
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>tinyproxy</title></head>
<body><p>Dashboard loading...</p></body>
</html>
```

`internal/dashboard/static/dashboard.css`:
```css
/* placeholder */
```

`internal/dashboard/static/dashboard.js`:
```js
// placeholder
```

- [ ] **Step 2: Append Server struct and constructor to server.go**

Add the following to the import block:
`"context"`, `"crypto/tls"`, `"embed"`, `"fmt"`, `"io/fs"`, `"log"`, `"os"`, `"syscall"`,
`dashconfig "tinyproxy/internal/dashboard/config"`,
`"tinyproxy/internal/server/middleware"`

```go
//go:embed static
var staticFiles embed.FS

// Config holds dashboard runtime configuration.
type Config struct {
	Host       string
	Port       int
	CredsFile  string
	DBPath     string
	TLSCert    string
	TLSKey     string
	ConfigPath string
}

// Server is a self-contained admin dashboard HTTP server.
type Server struct {
	cfg    Config
	srv    *http.Server
	cancel context.CancelFunc
}

// New creates a Server. Returns an error if credentials cannot be loaded.
func New(cfg Config, db *stats.DB, logbuf *logring.Buffer) (*Server, error) {
	mux := http.NewServeMux()

	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return nil, err
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.Handle("/api/stats", NewStatsHandler(db))
	mux.Handle("/api/logs", NewLogsHandler(db))
	mux.Handle("/api/logs/stream", NewLogsStreamHandler(logbuf))
	mux.Handle("/api/config", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			dashconfig.HandleGet(cfg.ConfigPath)(w, r)
		case http.MethodPut:
			dashconfig.HandlePut(cfg.ConfigPath, func() {
				syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
			})(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	mux.Handle("/api/config/validate", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		dashconfig.HandleValidate(cfg.ConfigPath)(w, r)
	}))

	var handler http.Handler = middleware.Recovery(mux)

	if cfg.CredsFile != "" {
		username, hash, err := loadCreds(cfg.CredsFile)
		if err != nil {
			return nil, fmt.Errorf("dashboard: failed to load credentials: %w", err)
		}
		am := NewAuthMiddleware(username, hash)
		handler = am.Wrap(handler)
	}

	s := &Server{cfg: cfg}
	s.srv = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler: handler,
	}

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("dashboard: failed to load TLS cert: %w", err)
		}
		s.srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}
	return s, nil
}

// Start launches the dashboard server in a background goroutine.
func (s *Server) Start() {
	go func() {
		log.Printf("dashboard: listening on %s", s.srv.Addr)
		var err error
		if s.srv.TLSConfig != nil {
			err = s.srv.ListenAndServeTLS("", "")
		} else {
			err = s.srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Printf("dashboard: server error: %v", err)
		}
	}()
}

// Shutdown gracefully stops the dashboard server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

func loadCreds(path string) (username string, hash []byte, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	line := strings.TrimSpace(string(data))
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("invalid credentials file: expected username:bcrypt_hash on one line")
	}
	return parts[0], []byte(parts[1]), nil
}
```

- [ ] **Step 3: Verify build**

```bash
go build ./internal/dashboard/...
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add internal/dashboard/server.go internal/dashboard/static/
git commit -m "feat(dashboard): assemble Server with embed, routes, TLS, auth wiring"
```

---

## Task 10: CLI flags, startup validation, `isLocalhostAddr`

**Files:**
- Create: `cmd/tinyproxy/dashboard_flags.go`
- Create: `cmd/tinyproxy/dashboard_flags_test.go`

- [ ] **Step 1: Write failing tests**

```go
// cmd/tinyproxy/dashboard_flags_test.go
package main

import "testing"

func TestIsLocalhostAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1", true},
		{"localhost", true},
		{"::1", true},
		{"127.0.0.2", true},
		{"0.0.0.0", false},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
	}
	for _, tc := range cases {
		got := isLocalhostAddr(tc.addr)
		if got != tc.want {
			t.Errorf("isLocalhostAddr(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestValidateDashboardConfigRequiresCreds(t *testing.T) {
	dc := DashboardConfig{Enabled: true, Host: "0.0.0.0", Port: 9000}
	if err := validateDashboardConfig(dc, nil); err == nil {
		t.Fatal("expected error when host is 0.0.0.0 and no creds")
	}
}

func TestValidateDashboardConfigDisabledSkipsValidation(t *testing.T) {
	dc := DashboardConfig{Enabled: false, Host: "0.0.0.0"}
	if err := validateDashboardConfig(dc, nil); err != nil {
		t.Fatalf("disabled dashboard should skip validation, got: %v", err)
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./cmd/tinyproxy/... -v -run TestIsLocalhost|TestValidate
```

Expected: `isLocalhostAddr` undefined.

- [ ] **Step 3: Write implementation**

```go
// cmd/tinyproxy/dashboard_flags.go
package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"tinyproxy/internal/server/config"
)

// DashboardConfig holds all parsed dashboard CLI flags.
type DashboardConfig struct {
	Enabled bool
	Host    string
	Port    int
	Creds   string
	DBPath  string
	TLSCert string
	TLSKey  string
}

func registerDashboardFlags(fs *flag.FlagSet, cfg *DashboardConfig) {
	fs.BoolVar(&cfg.Enabled, "enable-dashboard", false, "enable the admin dashboard")
	fs.StringVar(&cfg.Host, "dashboard-host", "127.0.0.1", "dashboard bind address")
	fs.IntVar(&cfg.Port, "dashboard-port", 9000, "dashboard listen port")
	fs.StringVar(&cfg.Creds, "dashboard-creds", "", "credentials file (required when host is not localhost)")
	fs.StringVar(&cfg.DBPath, "dashboard-db", "dashboard.db", "SQLite database path for dashboard stats")
	fs.StringVar(&cfg.TLSCert, "dashboard-cert", "", "TLS certificate for dashboard")
	fs.StringVar(&cfg.TLSKey, "dashboard-key", "", "TLS key for dashboard")
}

// isLocalhostAddr returns true if host is a loopback address.
func isLocalhostAddr(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validateDashboardConfig enforces startup rules when dashboard is enabled.
func validateDashboardConfig(dc DashboardConfig, sc *config.ServerConfig) error {
	if !dc.Enabled {
		return nil
	}
	if !isLocalhostAddr(dc.Host) {
		if dc.Creds == "" {
			return fmt.Errorf("--dashboard-creds is required when --dashboard-host (%s) is not localhost", dc.Host)
		}
		if _, err := os.Open(dc.Creds); err != nil {
			return fmt.Errorf("--dashboard-creds: %w", err)
		}
		hasCert := dc.TLSCert != "" && dc.TLSKey != ""
		if !hasCert && sc != nil {
			hasCert = vhostHasCert(sc)
		}
		if !hasCert {
			return fmt.Errorf("TLS certificate required when --dashboard-host is not localhost; provide --dashboard-cert/--dashboard-key or configure a vhost with ssl")
		}
	}
	return nil
}

// vhostHasCert returns true if any configured vhost has a TLS cert.
// Prefers "default"; falls back to any vhost with a cert.
func vhostHasCert(sc *config.ServerConfig) bool {
	if dv, ok := sc.VHosts["default"]; ok && dv.CertFile != "" {
		return true
	}
	for _, vh := range sc.VHosts {
		if vh.CertFile != "" {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./cmd/tinyproxy/... -v -run TestIsLocalhost|TestValidate
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/tinyproxy/dashboard_flags.go cmd/tinyproxy/dashboard_flags_test.go
git commit -m "feat(dashboard): add CLI flags and startup validation"
```

---

## Task 11: Wire into `main.go` — responseWriter, VHostHandler stats, server start/stop

**Files:**
- Modify: `cmd/tinyproxy/main.go`

- [ ] **Step 1: Add `responseWriter` wrapper**

Add this struct after the `VHostHandler` struct definition:

```go
// responseWriter wraps http.ResponseWriter to capture status code and bytes written.
type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if rw.status == 0 {
		rw.status = http.StatusOK
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytes += int64(n)
	return n, err
}
```

- [ ] **Step 2: Add `stats` field to `VHostHandler` and update `ServeHTTP`**

Change the struct:
```go
type VHostHandler struct {
	mu        sync.RWMutex
	config    *config.ServerConfig
	blocklist map[string]struct{}
	caches    map[string]*cache.Cache
	balancers map[string]*loadbalancer.LoadBalancer
	stats     *stats.Collector // nil when dashboard is disabled
}
```

Add import: `"tinyproxy/internal/dashboard/stats"` (alias as `dashstats` if name conflicts with other `stats` imports).

Replace the top of `ServeHTTP`:
```go
func (vh *VHostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rw := &responseWriter{ResponseWriter: w}

	vh.mu.RLock()
	cfg := vh.config
	bl := vh.blocklist
	caches := vh.caches
	balancers := vh.balancers
	collector := vh.stats
	vh.mu.RUnlock()
	// ... (rest of handler unchanged, but pass rw instead of w to inner handlers)
```

Replace the final `security.RateLimit(...)(botHandler).ServeHTTP(w, r)` line with:
```go
	security.RateLimit(
		vhost.Security.RateLimit.Requests,
		vhost.Security.RateLimit.Window,
	)(botHandler).ServeHTTP(rw, r)

	if collector != nil {
		host := r.Host
		if i := strings.LastIndex(host, ":"); i > 0 {
			host = host[:i]
		}
		collector.Record(stats.RequestRecord{
			TS:      time.Now().UnixMilli(),
			VHost:   host,
			Method:  r.Method,
			Path:    r.URL.Path,
			Status:  rw.status,
			Latency: time.Since(start).Microseconds(),
			Bytes:   rw.bytes,
			Remote:  r.RemoteAddr,
		})
	}
```

- [ ] **Step 3: Wire dashboard server in `runServer()`**

Replace the top of `runServer()`:

```go
func runServer() {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var dc DashboardConfig
	registerDashboardFlags(fs, &dc)
	if len(os.Args) > 2 {
		fs.Parse(os.Args[2:])
	}

	path := configPath()
	cfg, err := loadConfig(path)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	if err := validateDashboardConfig(dc, cfg); err != nil {
		log.Fatalf("dashboard: %v", err)
	}

	handler := &VHostHandler{config: cfg}
	handler.initSubsystems()
	handler.blocklist = loadFingerprintBlocklist(fingerprintsPath())

	var dashSrv *dashboard.Server
	if dc.Enabled {
		db, err := dashstats.Open(dc.DBPath)
		if err != nil {
			log.Fatalf("dashboard: failed to open database: %v", err)
		}
		logbuf := logring.New(10000, os.Stderr)
		log.SetOutput(logbuf)

		collector := dashstats.NewCollector(4096)
		handler.stats = collector

		batchCtx, batchCancel := context.WithCancel(context.Background())
		defer batchCancel()
		go db.RunBatchWriter(batchCtx, collector.Chan())

		logSub := logbuf.Subscribe()
		go func() {
			for line := range logSub {
				db.WriteLogLine(line.TS, line.Level, line.Body)
			}
		}()

		dashCfg := dashboard.Config{
			Host: dc.Host, Port: dc.Port, CredsFile: dc.Creds,
			DBPath: dc.DBPath, TLSCert: dc.TLSCert, TLSKey: dc.TLSKey,
			ConfigPath: path,
		}
		dashSrv, err = dashboard.New(dashCfg, db, logbuf)
		if err != nil {
			log.Fatalf("dashboard: %v", err)
		}
		dashSrv.Start()
	}
	// ... rest of existing runServer() unchanged ...
```

Add shutdown at the end of `runServer()` (after the signal handling):
```go
	// Graceful shutdown
	<-quit // existing signal channel
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if dashSrv != nil {
		dashSrv.Shutdown(ctx)
	}
	server.Shutdown(ctx)
```

Add missing imports: `"flag"`, `"context"`, `"tinyproxy/internal/dashboard"`, `dashstats "tinyproxy/internal/dashboard/stats"`, `"tinyproxy/internal/dashboard/logring"`.

- [ ] **Step 4: Verify build**

```bash
go build ./cmd/tinyproxy/
```

Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add cmd/tinyproxy/main.go
git commit -m "feat(dashboard): wire stats collector, logring, and dashboard server into main"
```

---

## Task 12: `dashboard passwd` subcommand

**Files:**
- Modify: `cmd/tinyproxy/main.go`

- [ ] **Step 1: Add `runDashboardPasswd` function**

```go
func runDashboardPasswd() {
	fmt.Print("Username: ")
	var username string
	fmt.Scanln(&username)
	if username == "" {
		log.Fatal("username cannot be empty")
	}

	fmt.Print("Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		log.Fatalf("failed to read password: %v", err)
	}
	if len(pw) == 0 {
		log.Fatal("password cannot be empty")
	}

	hash, err := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("failed to hash password: %v", err)
	}
	fmt.Printf("%s:%s\n", username, hash)
}
```

Add imports: `"golang.org/x/crypto/bcrypt"`, `"golang.org/x/term"`.

- [ ] **Step 2: Add `"dashboard"` case to `main()` switch**

```go
case "dashboard":
	sub := ""
	if len(os.Args) > 2 {
		sub = os.Args[2]
	}
	switch sub {
	case "passwd":
		runDashboardPasswd()
	default:
		fmt.Fprintf(os.Stderr, "Usage: go-tinyproxy dashboard passwd\n")
		os.Exit(1)
	}
```

Update the usage string to include `dashboard`:
```go
fmt.Fprintf(os.Stderr, "Usage: go-tinyproxy {serve|start|stop|restart|reload|status|config|logs|upgrade|ssl|dashboard}\n")
```

- [ ] **Step 3: Build and smoke test**

```bash
go build -o go-tinyproxy ./cmd/tinyproxy/
echo -e "admin\n" | ./go-tinyproxy dashboard passwd
```

Expected: prompts for username (enter "admin"), prompts for password, prints `admin:$2a$10$...`.

- [ ] **Step 4: Commit**

```bash
git add cmd/tinyproxy/main.go
git commit -m "feat(dashboard): add 'dashboard passwd' subcommand for credential generation"
```

---

## Task 13: UI shell — sidebar, nav, section routing

**Files:**
- Modify: `internal/dashboard/static/index.html`
- Modify: `internal/dashboard/static/dashboard.css`
- Modify: `internal/dashboard/static/dashboard.js`

- [ ] **Step 1: Write `index.html`**

```html
<!DOCTYPE html>
<html lang="en" class="h-full">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>tinyproxy dashboard</title>
  <link rel="stylesheet" href="/dashboard.css">
  <script src="https://unpkg.com/htmx.org@1.9.10" defer></script>
  <script src="https://unpkg.com/htmx.org@1.9.10/dist/ext/sse.js" defer></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4" defer></script>
  <script src="/dashboard.js" defer></script>
</head>
<body class="h-full flex bg-gray-950 text-gray-100 font-mono">
  <aside class="w-52 shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col">
    <div class="px-4 py-5 border-b border-gray-800">
      <span class="text-sm font-bold text-indigo-400 tracking-widest uppercase">tinyproxy</span>
    </div>
    <nav class="flex-1 px-2 py-4 space-y-1">
      <a href="#" class="nav-link active" data-section="overview">Overview</a>
      <a href="#" class="nav-link"        data-section="traffic">Traffic</a>
      <a href="#" class="nav-link"        data-section="logs">Logs</a>
      <a href="#" class="nav-link"        data-section="config">Config</a>
    </nav>
    <div class="px-4 py-3 border-t border-gray-800 text-xs text-gray-500">go-tinyproxy</div>
  </aside>
  <main class="flex-1 overflow-auto">
    <div id="section-overview" class="section p-6"></div>
    <div id="section-traffic"  class="section p-6 hidden"></div>
    <div id="section-logs"     class="section p-6 hidden"></div>
    <div id="section-config"   class="section p-6 hidden"></div>
  </main>
</body>
</html>
```

- [ ] **Step 2: Write `dashboard.css`**

```css
body { background-color: #030712; }
.nav-link {
  display: block; padding: .5rem .75rem; border-radius: .375rem;
  font-size: .875rem; color: #9ca3af; text-decoration: none;
  transition: background .15s, color .15s;
}
.nav-link:hover { background: #1f2937; color: #e5e7eb; }
.nav-link.active { background: #312e81; color: #a5b4fc; }
.hidden { display: none !important; }
.card {
  background: #111827; border: 1px solid #1f2937;
  border-radius: .5rem; padding: 1.25rem;
}
.stat-label { font-size: .75rem; color: #6b7280; text-transform: uppercase; letter-spacing: .05em; }
.stat-value { font-size: 1.75rem; font-weight: 700; color: #f9fafb; margin-top: .25rem; }
.cfg-input {
  background: #0f172a; border: 1px solid #374151; border-radius: .375rem;
  padding: .375rem .625rem; color: #e5e7eb; width: 100%;
}
.cfg-input:focus { outline: none; border-color: #6366f1; }
.grid { display: grid; }
.grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.grid-cols-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
.gap-4 { gap: 1rem; }
.gap-3 { gap: .75rem; }
.gap-2 { gap: .5rem; }
.mb-4 { margin-bottom: 1rem; }
.mb-3 { margin-bottom: .75rem; }
.mb-2 { margin-bottom: .5rem; }
.mt-4 { margin-top: 1rem; }
.mt-3 { margin-top: .75rem; }
.mt-2 { margin-top: .5rem; }
.mt-1 { margin-top: .25rem; }
.flex { display: flex; }
.flex-col { flex-direction: column; }
.items-center { align-items: center; }
.justify-between { justify-content: space-between; }
.text-lg { font-size: 1.125rem; }
.font-semibold { font-weight: 600; }
.text-gray-200 { color: #e5e7eb; }
.text-gray-300 { color: #d1d5db; }
.text-gray-400 { color: #9ca3af; }
.text-gray-500 { color: #6b7280; }
.text-red-400 { color: #f87171; }
.text-yellow-400 { color: #facc15; }
.text-green-400 { color: #4ade80; }
.text-indigo-400 { color: #818cf8; }
.text-white { color: #ffffff; }
.text-sm { font-size: .875rem; }
.text-xs { font-size: .75rem; }
.w-full { width: 100%; }
.h-96 { height: 24rem; }
.h-80 { height: 20rem; }
.overflow-y-auto { overflow-y: auto; }
.overflow-auto { overflow: auto; }
.overflow-hidden { overflow: hidden; }
.max-h-48 { max-height: 12rem; }
.max-w-xs { max-width: 20rem; }
.truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.whitespace-pre-wrap { white-space: pre-wrap; }
.break-all { word-break: break-all; }
.space-y-0\.5 > * + * { margin-top: .125rem; }
.p-6 { padding: 1.5rem; }
.p-3 { padding: .75rem; }
.p-2 { padding: .5rem; }
.px-3 { padding-left: .75rem; padding-right: .75rem; }
.px-4 { padding-left: 1rem; padding-right: 1rem; }
.py-1 { padding-top: .25rem; padding-bottom: .25rem; }
.py-2 { padding-top: .5rem; padding-bottom: .5rem; }
.rounded { border-radius: .375rem; }
.border { border-width: 1px; }
.border-b { border-bottom-width: 1px; }
.border-gray-700 { border-color: #374151; }
.border-gray-800 { border-color: #1f2937; }
.bg-indigo-600 { background-color: #4f46e5; }
.bg-indigo-700 { background-color: #4338ca; }
.bg-gray-700 { background-color: #374151; }
.bg-gray-800 { background-color: #1f2937; }
.bg-gray-950 { background-color: #030712; }
.hover\:bg-indigo-500:hover { background-color: #6366f1; }
.hover\:bg-gray-600:hover { background-color: #4b5563; }
.hover\:bg-gray-700:hover { background-color: #374151; }
.resize-y { resize: vertical; }
button { cursor: pointer; }
```

- [ ] **Step 3: Write `dashboard.js` scaffold**

```js
// dashboard.js
let _currentSection = 'overview';

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      switchSection(link.dataset.section, link);
    });
  });
  switchSection('overview', document.querySelector('.nav-link.active'));
});

function switchSection(name, linkEl) {
  _currentSection = name;
  document.querySelectorAll('.section').forEach(s => s.classList.add('hidden'));
  document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
  document.getElementById('section-' + name).classList.remove('hidden');
  if (linkEl) linkEl.classList.add('active');
  loadSection(name);
}

function loadSection(name) {
  switch (name) {
    case 'overview': loadOverview(); break;
    case 'traffic':  loadTraffic();  break;
    case 'logs':     initLogs();     break;
    case 'config':   loadConfig();   break;
  }
}

function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
```

- [ ] **Step 4: Start dev server and verify shell**

```bash
ENV=dev ./go-tinyproxy serve --enable-dashboard
```

Open `http://localhost:9000` — expect sidebar with four nav links and an empty main area. Nav links switch sections without page reload.

- [ ] **Step 5: Commit**

```bash
git add internal/dashboard/static/
git commit -m "feat(dashboard): add UI shell with sidebar and section routing"
```

---

## Task 14: UI — Overview section

**Files:**
- Modify: `internal/dashboard/static/dashboard.js`

- [ ] **Step 1: Add `loadOverview` function**

Append to `dashboard.js`:

```js
let _rpsChart = null;

async function loadOverview() {
  const container = document.getElementById('section-overview');
  let data;
  try {
    data = await fetch('/api/stats?window=1h').then(r => r.json());
  } catch (e) {
    container.innerHTML = '<p class="text-red-400">Failed to load stats.</p>';
    return;
  }

  const errorPct = ((data.error_rate || 0) * 100).toFixed(1);
  const avgMs    = ((data.avg_latency_us || 0) / 1000).toFixed(1);
  const bwMb     = ((data.total_bytes || 0) / 1_048_576).toFixed(2);
  const total    = (data.total_requests || 0).toLocaleString();

  // Build stat card HTML using only escaped values
  container.innerHTML =
    '<h2 class="text-lg font-semibold mb-4 text-gray-200">Overview</h2>' +
    '<div class="grid grid-cols-2 grid-cols-4 gap-4 mb-4">' +
      '<div class="card"><div class="stat-label">Total Requests</div><div class="stat-value" id="ov-total"></div></div>' +
      '<div class="card"><div class="stat-label">Error Rate</div><div class="stat-value text-red-400" id="ov-err"></div></div>' +
      '<div class="card"><div class="stat-label">Avg Latency</div><div class="stat-value" id="ov-lat"></div></div>' +
      '<div class="card"><div class="stat-label">Bandwidth</div><div class="stat-value" id="ov-bw"></div></div>' +
    '</div>' +
    '<div class="card"><div class="stat-label mb-3">Requests / min (last 60 min)</div><canvas id="rps-chart" height="80"></canvas></div>';

  // Assign text content (no innerHTML, no XSS risk)
  document.getElementById('ov-total').textContent = total;
  document.getElementById('ov-err').textContent   = errorPct + '%';
  document.getElementById('ov-lat').textContent   = avgMs + ' ms';
  document.getElementById('ov-bw').textContent    = bwMb + ' MB';

  const labels = (data.rps_series || []).map(p => new Date(p.ts).toLocaleTimeString());
  const values = (data.rps_series || []).map(p => p.rps);

  if (_rpsChart) _rpsChart.destroy();
  _rpsChart = new Chart(document.getElementById('rps-chart').getContext('2d'), {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'req/s', data: values,
        borderColor: '#6366f1', backgroundColor: 'rgba(99,102,241,0.1)',
        fill: true, tension: 0.3, pointRadius: 0,
      }]
    },
    options: {
      scales: {
        x: { ticks: { color: '#6b7280', maxTicksLimit: 8 }, grid: { color: '#1f2937' } },
        y: { ticks: { color: '#6b7280' }, grid: { color: '#1f2937' } }
      },
      plugins: { legend: { display: false } },
      animation: false,
    }
  });

  setTimeout(() => { if (_currentSection === 'overview') loadOverview(); }, 10000);
}
```

- [ ] **Step 2: Verify in browser**

Generate proxy traffic: `curl -k https://localhost:8080/` several times.
Open `http://localhost:9000` — expect stat cards with values and a line chart. Wait 10s — cards refresh.

- [ ] **Step 3: Commit**

```bash
git add internal/dashboard/static/dashboard.js
git commit -m "feat(dashboard): add Overview section with stat cards and RPS chart"
```

---

## Task 15: UI — Traffic section

**Files:**
- Modify: `internal/dashboard/static/dashboard.js`

- [ ] **Step 1: Add `loadTraffic` function**

Append to `dashboard.js`:

```js
async function loadTraffic(w) {
  const win = w || '1h';
  const container = document.getElementById('section-traffic');
  let data;
  try {
    data = await fetch('/api/stats?window=' + win).then(r => r.json());
  } catch (e) {
    container.innerHTML = '<p class="text-red-400">Failed to load traffic data.</p>';
    return;
  }

  const tabBtn = (label, active) =>
    '<button onclick="loadTraffic(\'' + escapeHtml(label) + '\')" style="' +
    'padding:.25rem .75rem;border-radius:.375rem;font-size:.875rem;margin-right:.5rem;' +
    (active ? 'background:#4338ca;color:#fff;' : 'background:#1f2937;color:#9ca3af;') + '">' +
    escapeHtml(label) + '</button>';

  const tabs = ['1h','6h','24h','7d'].map(t => tabBtn(t, t === win)).join('');

  const topRows = (entries) => {
    if (!entries || entries.length === 0) return '<p class="text-gray-500 text-sm">No data</p>';
    return entries.map(e => {
      const row = document.createElement('div');
      row.className = 'flex justify-between text-sm py-1 border-b border-gray-800';
      const key = document.createElement('span');
      key.className = 'text-gray-300 truncate max-w-xs';
      key.textContent = e.key;
      const cnt = document.createElement('span');
      cnt.className = 'text-indigo-400';
      cnt.textContent = Number(e.count).toLocaleString();
      row.appendChild(key);
      row.appendChild(cnt);
      return row.outerHTML;
    }).join('');
  };

  const statusRows = Object.entries(data.status_codes || {})
    .sort((a,b) => b[1] - a[1])
    .map(([code, count]) => {
      const cls = code.startsWith('5') ? 'text-red-400' : code.startsWith('4') ? 'text-yellow-400' : 'text-green-400';
      const row = document.createElement('div');
      row.className = 'flex justify-between text-sm py-1 border-b border-gray-800';
      const c = document.createElement('span');
      c.className = cls;
      c.textContent = code;
      const n = document.createElement('span');
      n.textContent = Number(count).toLocaleString();
      row.appendChild(c);
      row.appendChild(n);
      return row.outerHTML;
    }).join('');

  container.innerHTML =
    '<div class="flex items-center justify-between mb-4">' +
      '<h2 class="text-lg font-semibold text-gray-200">Traffic</h2>' +
      '<div>' + tabs + '</div>' +
    '</div>' +
    '<div class="grid grid-cols-2 gap-4">' +
      '<div class="card"><div class="stat-label mb-3">Top Vhosts</div>'    + topRows(data.top_vhosts) + '</div>' +
      '<div class="card"><div class="stat-label mb-3">Top Paths</div>'     + topRows(data.top_paths)  + '</div>' +
      '<div class="card"><div class="stat-label mb-3">Status Codes</div>'  + statusRows               + '</div>' +
      '<div class="card"><div class="stat-label mb-3">Top IPs</div>'       + topRows(data.top_ips)    + '</div>' +
    '</div>';
}
```

- [ ] **Step 2: Verify in browser**

Navigate to Traffic. Check time-range tabs switch data correctly.

- [ ] **Step 3: Commit**

```bash
git add internal/dashboard/static/dashboard.js
git commit -m "feat(dashboard): add Traffic section with tabbed breakdown"
```

---

## Task 16: UI — Logs section

**Files:**
- Modify: `internal/dashboard/static/dashboard.js`

- [ ] **Step 1: Add `initLogs` and helpers**

Append to `dashboard.js`:

```js
let _logsES = null;
let _autoScroll = true;

function initLogs() {
  const container = document.getElementById('section-logs');
  container.innerHTML =
    '<div class="flex items-center justify-between mb-4">' +
      '<h2 class="text-lg font-semibold text-gray-200">Logs</h2>' +
      '<div class="flex items-center gap-3">' +
        '<select id="log-level" class="cfg-input" style="width:auto">' +
          '<option value="">All levels</option>' +
          '<option value="info">Info</option>' +
          '<option value="error">Error</option>' +
        '</select>' +
        '<label class="flex items-center gap-2 text-sm text-gray-400" style="cursor:pointer">' +
          '<input type="checkbox" id="auto-scroll" checked> Auto-scroll' +
        '</label>' +
      '</div>' +
    '</div>' +
    '<div class="card overflow-hidden">' +
      '<div id="log-output" class="h-96 overflow-y-auto p-2 space-y-0\.5 text-xs"></div>' +
    '</div>';

  document.getElementById('log-level').addEventListener('change', reconnectLogs);
  document.getElementById('auto-scroll').addEventListener('change', e => { _autoScroll = e.target.checked; });
  connectLogStream();
}

function connectLogStream() {
  if (_logsES) { _logsES.close(); _logsES = null; }
  const level = document.getElementById('log-level') ? document.getElementById('log-level').value : '';
  const url   = '/api/logs/stream' + (level ? '?level=' + encodeURIComponent(level) : '');
  _logsES = new EventSource(url);
  _logsES.onmessage = e => {
    try { appendLogLine(JSON.parse(e.data)); } catch {}
  };
}

function appendLogLine(line) {
  const output = document.getElementById('log-output');
  if (!output) return;
  const div = document.createElement('div');
  div.className = line.level === 'error' ? 'text-red-400 whitespace-pre-wrap break-all' : 'text-gray-300 whitespace-pre-wrap break-all';
  const ts = new Date(line.ts).toLocaleTimeString();
  // Use textContent — no XSS risk, no escaping needed
  div.textContent = '[' + ts + '] ' + line.body;
  output.appendChild(div);
  if (_autoScroll) output.scrollTop = output.scrollHeight;
  while (output.children.length > 2000) output.removeChild(output.firstChild);
}

function reconnectLogs() { connectLogStream(); }
```

- [ ] **Step 2: Verify SSE stream**

Navigate to Logs. Run `curl -k https://localhost:8080/` a few times — log lines should appear live. Toggle Error filter.

- [ ] **Step 3: Commit**

```bash
git add internal/dashboard/static/dashboard.js
git commit -m "feat(dashboard): add Logs section with live SSE tail"
```

---

## Task 17: UI — Config section

**Files:**
- Modify: `internal/dashboard/static/dashboard.js`

- [ ] **Step 1: Add `loadConfig` and editor functions**

Append to `dashboard.js`:

```js
let _originalRaw = '';

async function loadConfig() {
  const container = document.getElementById('section-config');
  let resp;
  try {
    resp = await fetch('/api/config').then(r => r.json());
  } catch (e) {
    container.innerHTML = '<p class="text-red-400">Failed to load config.</p>';
    return;
  }
  _originalRaw = resp.raw || '';
  const parsed  = resp.parsed || {};

  container.innerHTML =
    '<div class="flex items-center justify-between mb-4">' +
      '<h2 class="text-lg font-semibold text-gray-200">Config</h2>' +
      '<div>' +
        '<button id="tab-visual" onclick="showConfigTab(\'visual\')" class="px-3 py-1 rounded text-sm bg-indigo-700 text-white" style="margin-right:.5rem">Visual</button>' +
        '<button id="tab-raw"    onclick="showConfigTab(\'raw\')"    class="px-3 py-1 rounded text-sm bg-gray-800 text-gray-400">Raw</button>' +
      '</div>' +
    '</div>' +
    '<div id="config-visual"></div>' +
    '<div id="config-raw" class="hidden"></div>';

  renderVisualPanel(parsed);
  renderRawPanel(_originalRaw);
}

function showConfigTab(tab) {
  document.getElementById('config-visual').classList.toggle('hidden', tab !== 'visual');
  document.getElementById('config-raw').classList.toggle('hidden', tab !== 'raw');
  const visCls = tab === 'visual' ? 'bg-indigo-700 text-white' : 'bg-gray-800 text-gray-400';
  const rawCls = tab === 'raw'    ? 'bg-indigo-700 text-white' : 'bg-gray-800 text-gray-400';
  document.getElementById('tab-visual').className = 'px-3 py-1 rounded text-sm ' + visCls;
  document.getElementById('tab-raw').className    = 'px-3 py-1 rounded text-sm ' + rawCls;
}

function renderVisualPanel(parsed) {
  const panel = document.getElementById('config-visual');
  const vhosts = (parsed && parsed.VHosts) ? parsed.VHosts : {};
  const keys = Object.keys(vhosts);
  if (keys.length === 0) {
    panel.innerHTML = '<div class="card text-gray-500 text-sm">No vhosts configured.</div>';
    return;
  }
  let html = '';
  keys.forEach(name => {
    const vh = vhosts[name];
    html += '<div class="card mb-4">';
    html += '<div class="flex items-center mb-3">';
    const nameSpan = document.createElement('span');
    nameSpan.className = 'text-indigo-400 font-semibold';
    nameSpan.textContent = name;
    html += nameSpan.outerHTML;
    html += '</div>';
    html += '<div class="grid grid-cols-2 gap-3 text-sm">';
    // Use DOM creation for all dynamic values to avoid XSS
    html += vhostFieldHtml('Proxy Pass',     'text',     vh.ProxyPass || '', 'proxy_pass_' + name);
    html += vhostFieldHtml('Root Directory', 'text',     vh.Root || '',      'root_' + name);
    html += vhostFieldHtml('Rate Limit',     'number',   (vh.Security && vh.Security.RateLimit && vh.Security.RateLimit.Requests) || 100, 'rate_' + name);
    html += '</div></div>';
  });
  html += '<p class="text-xs text-gray-500 mt-2">Visual panel is read-only. Use Raw tab to edit.</p>';
  panel.innerHTML = html;
}

function vhostFieldHtml(label, type, value, id) {
  const wrapper = document.createElement('label');
  wrapper.className = 'flex flex-col gap-1 text-gray-400';
  const lbl = document.createElement('span');
  lbl.textContent = label;
  const input = document.createElement('input');
  input.type = type;
  input.id = id;
  input.value = value; // value assignment is XSS-safe
  input.className = 'cfg-input mt-1';
  input.readOnly = true;
  wrapper.appendChild(lbl);
  wrapper.appendChild(input);
  return wrapper.outerHTML;
}

function renderRawPanel(raw) {
  const panel = document.getElementById('config-raw');
  panel.innerHTML =
    '<div class="card">' +
      '<textarea id="raw-editor" class="cfg-input h-96 resize-y p-2 text-xs" style="font-family:monospace"></textarea>' +
      '<div id="cfg-error" class="mt-2 text-red-400 text-sm hidden"></div>' +
      '<div id="cfg-diff" class="mt-2 hidden">' +
        '<div class="text-xs text-gray-400 mb-1">Changes:</div>' +
        '<pre id="cfg-diff-pre" class="bg-gray-950 text-xs p-2 rounded border border-gray-700 overflow-auto max-h-48"></pre>' +
        '<div class="flex gap-3 mt-3">' +
          '<button onclick="confirmSave()" class="px-4 py-2 bg-indigo-600 text-white rounded text-sm">Confirm Save</button>' +
          '<button onclick="cancelSave()"  class="px-4 py-2 bg-gray-700 text-white rounded text-sm">Cancel</button>' +
        '</div>' +
      '</div>' +
      '<div id="cfg-save-row" class="mt-3">' +
        '<button onclick="validateAndPreview()" class="px-4 py-2 bg-indigo-600 text-white rounded text-sm">Validate &amp; Save</button>' +
      '</div>' +
    '</div>';

  // Set textarea value safely — no innerHTML injection
  document.getElementById('raw-editor').value = raw;
}

async function validateAndPreview() {
  const newRaw = document.getElementById('raw-editor').value;
  const errEl  = document.getElementById('cfg-error');
  errEl.classList.add('hidden');

  const resp = await fetch('/api/config/validate', { method: 'POST', body: newRaw });
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({ error: 'Validation failed' }));
    errEl.textContent = body.error || 'Validation failed'; // textContent — safe
    errEl.classList.remove('hidden');
    return;
  }

  // Show diff using textContent to avoid XSS
  const diffPre = document.getElementById('cfg-diff-pre');
  diffPre.textContent = simpleDiff(_originalRaw, newRaw);
  document.getElementById('cfg-diff').classList.remove('hidden');
  document.getElementById('cfg-save-row').classList.add('hidden');
}

async function confirmSave() {
  const newRaw = document.getElementById('raw-editor').value;
  const errEl  = document.getElementById('cfg-error');
  const resp   = await fetch('/api/config', { method: 'PUT', body: newRaw });
  if (!resp.ok) {
    const text = await resp.text();
    errEl.textContent = text; // textContent — safe
    errEl.classList.remove('hidden');
    return;
  }
  _originalRaw = newRaw;
  document.getElementById('cfg-diff').classList.add('hidden');
  document.getElementById('cfg-save-row').classList.remove('hidden');
  alert('Config saved and reloaded.');
}

function cancelSave() {
  document.getElementById('cfg-diff').classList.add('hidden');
  document.getElementById('cfg-save-row').classList.remove('hidden');
}

function simpleDiff(oldStr, newStr) {
  const oldLines = (oldStr || '').split('\n');
  const newLines = (newStr || '').split('\n');
  const result = [];
  const maxLen = Math.max(oldLines.length, newLines.length);
  for (let i = 0; i < maxLen; i++) {
    if (oldLines[i] !== newLines[i]) {
      if (oldLines[i] !== undefined) result.push('- ' + oldLines[i]);
      if (newLines[i] !== undefined) result.push('+ ' + newLines[i]);
    }
  }
  return result.length ? result.join('\n') : '(no changes)';
}
```

- [ ] **Step 2: Verify in browser**

Navigate to Config.
- Visual tab: vhost cards shown with correct values, all read-only.
- Raw tab: config file content in textarea.
- Enter invalid config → click "Validate & Save" → expect error message.
- Enter valid config → click "Validate & Save" → expect diff preview.
- Click "Confirm Save" → alert and reload.

- [ ] **Step 3: Run all tests**

```bash
go test ./...
```

Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/dashboard/static/dashboard.js
git commit -m "feat(dashboard): add Config section with visual viewer and raw editor"
```

---

## Spec Coverage Checklist

- [x] `--enable-dashboard` flag (Task 10)
- [x] `--dashboard-port` default 9000 (Task 10)
- [x] `--dashboard-host` localhost default (Task 10)
- [x] Non-localhost requires creds + TLS, startup refusal (Tasks 10, 11)
- [x] `--dashboard-creds` credentials file (Task 10)
- [x] `--dashboard-db` SQLite persistence (Tasks 3, 4, 11)
- [x] `--dashboard-cert`/`--dashboard-key` TLS override (Tasks 9, 10)
- [x] `dashboard passwd` subcommand (Task 12)
- [x] `stats.Collector` non-blocking channel (Task 2)
- [x] `stats.DB` schema + batch writer + 30-day pruning (Task 3)
- [x] `stats.DB` QueryStats + QueryLogs (Task 4)
- [x] `logring.Buffer` ring buffer + Write + Recent (Task 5)
- [x] SSE fan-out via Subscribe/Unsubscribe (Task 5)
- [x] Auth middleware with bcrypt + per-IP rate limiter (Task 6)
- [x] Config API: GET, validate, PUT atomic write + SIGHUP (Task 7)
- [x] Stats API `/api/stats` with window param (Task 8)
- [x] Logs API `/api/logs` with filters + `/api/logs/stream` SSE (Task 8)
- [x] `dashboard.Server` with embed, mux, TLS, auth wiring (Task 9)
- [x] `recovery.go` middleware on dashboard handler (Task 9)
- [x] `responseWriter` wrapper (Task 11)
- [x] `VHostHandler.stats` field + wiring in ServeHTTP (Task 11)
- [x] Log persistence via WriteLogLine (Task 11)
- [x] UI shell with sidebar nav (Task 13)
- [x] UI Overview: stat cards + RPS sparkline, auto-refresh (Task 14)
- [x] UI Traffic: tabbed breakdown + time range selector (Task 15)
- [x] UI Logs: SSE live tail + level filter (Task 16)
- [x] UI Config: visual viewer + raw editor + diff + confirmation (Task 17)
- [x] All dynamic values in innerHTML use DOM methods or `textContent` (XSS prevention)
