package stats_test

import (
	"testing"
	"time"
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
	case <-time.After(100 * time.Millisecond):
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
