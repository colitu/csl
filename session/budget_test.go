package session

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/colitu/csl/frame"
)

func TestMemoryBudgetCountsResizePeakAndReleases(t *testing.T) {
	b := NewMemoryBudget(32 << 10)
	r := newRing(64<<10, b)
	if n := r.Write(bytes.Repeat([]byte{'a'}, 16<<10)); n != 16<<10 || b.Used() != 16<<10 {
		t.Fatalf("first allocation: wrote %d, used %d", n, b.Used())
	}
	// Growing to 32 KiB temporarily needs both allocations. The 32 KiB
	// budget must reject it without changing buffered data.
	if n := r.Write([]byte{'b'}); n != 0 || b.Used() != 16<<10 || r.Len() != 16<<10 {
		t.Fatalf("resize exceeded budget: wrote %d, used %d, len %d", n, b.Used(), r.Len())
	}
	r.Discard(r.Len())
	r.TrimIdle(time.Now().Add(31*time.Second), 30*time.Second)
	if b.Used() != 16<<10 {
		t.Fatalf("small idle allocation unexpectedly changed: %d", b.Used())
	}
	r.Release()
	if b.Used() != 0 {
		t.Fatalf("reservation leaked: %d", b.Used())
	}
}

func TestDatagramsShareMemoryBudget(t *testing.T) {
	b := NewMemoryBudget(16)
	s := New(Config{Budget: b, DgramQueue: 2}, DefaultWindow)
	if err := s.SendDatagram(bytes.Repeat([]byte{'x'}, 10)); err != nil {
		t.Fatal(err)
	}
	if err := s.SendDatagram(bytes.Repeat([]byte{'y'}, 10)); err != nil {
		t.Fatal(err)
	}
	if b.Used() != 10 || len(s.dgramOut) != 1 {
		t.Fatalf("outbound budget: used %d, queued %d", b.Used(), len(s.dgramOut))
	}
	s.mu.Lock()
	if err := s.handleLocked(frame.Frame{Type: frame.TypeDgram, Payload: []byte("abc")}); err != nil {
		t.Fatal(err)
	}
	s.mu.Unlock()
	if b.Used() != 13 {
		t.Fatalf("inbound budget: used %d", b.Used())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if d, err := s.ReceiveDatagram(ctx); err != nil || string(d) != "abc" {
		t.Fatalf("receive datagram: %q, %v", d, err)
	}
	if b.Used() != 10 {
		t.Fatalf("receive did not release reservation: %d", b.Used())
	}
	s.Abort(ErrClosed)
	if b.Used() != 0 {
		t.Fatalf("abort retained datagrams: %d", b.Used())
	}
}

func TestSessionMemoryBudgetFailureAndAbort(t *testing.T) {
	b := NewMemoryBudget(16 << 10)
	s := New(Config{Budget: b}, DefaultWindow)
	if n, err := s.Write([]byte("hello")); err != nil || n != 5 {
		t.Fatalf("first write: %d, %v", n, err)
	}
	if n, err := s.Write(bytes.Repeat([]byte{'x'}, 16<<10)); n != 0 || !errors.Is(err, ErrMemoryBudget) {
		t.Fatalf("expected budget rejection: %d, %v", n, err)
	}
	s.Abort(ErrClosed)
	if b.Used() != 0 {
		t.Fatalf("abort retained %d bytes", b.Used())
	}
}
