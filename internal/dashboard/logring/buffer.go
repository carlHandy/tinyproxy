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
