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
