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
