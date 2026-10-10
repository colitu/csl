package session

import (
	"runtime"
	"time"
)

// ring is a byte FIFO with a fixed logical limit and storage that grows on demand.
// It is not safe for concurrent use.
type ring struct {
	buf        []byte
	max        int // logical capacity, independent of allocated storage
	head       int // index of the first byte
	n          int // number of stored bytes
	emptySince time.Time
	budget     *MemoryBudget
}

func newRing(size int, budget ...*MemoryBudget) *ring {
	r := &ring{max: size}
	if len(budget) > 0 {
		r.budget = budget[0]
		if r.budget != nil {
			// A graceful close can leave unread bytes for the application.
			// Return their reservation if that application drops the session.
			runtime.SetFinalizer(r, func(r *ring) { r.Release() })
		}
	}
	return r
}

func (r *ring) Len() int  { return r.n }
func (r *ring) Free() int { return r.max - r.n }

func (r *ring) grow(need int) bool {
	if need <= len(r.buf) {
		return true
	}
	size := len(r.buf)
	if size == 0 {
		size = min(r.max, 16<<10)
	}
	for size < need {
		if size > r.max/2 {
			size = r.max
		} else {
			size *= 2
		}
	}
	oldSize := len(r.buf)
	if r.budget != nil && !r.budget.reserve(int64(size)) {
		return false
	}
	buf := make([]byte, size)
	if r.n > 0 {
		r.copyAt(buf[:r.n], 0)
	}
	r.buf = buf
	r.head = 0
	if r.budget != nil {
		r.budget.release(int64(oldSize))
	}
	return true
}

// Write appends as much of p as fits and returns the number of bytes stored.
func (r *ring) Write(p []byte) int {
	p = p[:min(len(p), r.Free())]
	if len(p) == 0 {
		return 0
	}
	if !r.grow(r.n + len(p)) {
		return 0
	}
	r.emptySince = time.Time{}
	total := 0
	for len(p) > 0 {
		tail := (r.head + r.n) % len(r.buf)
		end := len(r.buf)
		if tail < r.head {
			end = r.head
		}
		c := copy(r.buf[tail:end], p)
		r.n += c
		total += c
		p = p[c:]
	}
	return total
}

// Read moves up to len(p) bytes from the front of the ring into p.
func (r *ring) Read(p []byte) int {
	n := min(len(p), r.n)
	r.copyAt(p[:n], 0)
	r.Discard(n)
	return n
}

// Discard drops n bytes from the front of the ring.
func (r *ring) Discard(n int) {
	if n > r.n {
		panic("session: ring discard beyond length")
	}
	if n == 0 {
		return
	}
	r.head = (r.head + n) % len(r.buf)
	r.n -= n
	if r.n == 0 {
		r.head = 0
		r.emptySince = time.Now()
	}
}

// TrimIdle releases large storage only after the ring has stayed empty.
func (r *ring) TrimIdle(now time.Time, after time.Duration) {
	if r.n != 0 || r.emptySince.IsZero() || now.Sub(r.emptySince) < after {
		return
	}
	if len(r.buf) > 16<<10 {
		if r.budget != nil {
			r.budget.release(int64(len(r.buf)))
			r.buf = nil
		} else {
			r.buf = make([]byte, min(r.max, 16<<10))
		}
	}
}

// Release discards all content and returns its allocated bytes to the budget.
func (r *ring) Release() {
	if r.budget != nil {
		r.budget.release(int64(len(r.buf)))
	}
	r.buf = nil
	r.head = 0
	r.n = 0
	r.emptySince = time.Time{}
}

// AppendAt appends n bytes starting at offset off (relative to the front)
// to dst without consuming them.
func (r *ring) AppendAt(dst []byte, off, n int) []byte {
	if off < 0 || n < 0 || off+n > r.n {
		panic("session: ring read out of range")
	}
	l := len(dst)
	dst = append(dst, make([]byte, n)...)
	r.copyAt(dst[l:], off)
	return dst
}

func (r *ring) copyAt(dst []byte, off int) {
	if len(dst) == 0 {
		return
	}
	start := (r.head + off) % len(r.buf)
	c := copy(dst, r.buf[start:])
	if c < len(dst) {
		copy(dst[c:], r.buf)
	}
}
