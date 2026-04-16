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
