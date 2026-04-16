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
			for {
				select {
				case r := <-ch:
					batch = append(batch, r)
				default:
					goto done
				}
			}
		done:
			if len(batch) > 0 {
				if err := d.writeBatch(batch); err != nil {
					log.Printf("dashboard: stats final batch write error: %v", err)
				}
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
		       COALESCE(CAST(SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END) AS REAL) / MAX(CAST(COUNT(*) AS REAL), 1), 0),
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
	if vhost != "" {
		q += ` AND vhost = ?`
		args = append(args, vhost)
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
