package session

import "sync/atomic"

// MemoryBudget bounds send and receive ring storage and queued datagram
// payloads shared by many sessions. Ring growth reserves the new allocation
// before the old allocation is released, so resize peaks are accounted for.
type MemoryBudget struct {
	limit int64
	used  atomic.Int64
}

func NewMemoryBudget(limit int64) *MemoryBudget {
	if limit <= 0 {
		panic("session: memory budget must be positive")
	}
	return &MemoryBudget{limit: limit}
}

func (b *MemoryBudget) Limit() int64 { return b.limit }
func (b *MemoryBudget) Used() int64  { return b.used.Load() }

func (b *MemoryBudget) reserve(bytes int64) bool {
	for {
		old := b.used.Load()
		if bytes > b.limit-old {
			return false
		}
		if b.used.CompareAndSwap(old, old+bytes) {
			return true
		}
	}
}

func (b *MemoryBudget) release(bytes int64) { b.used.Add(-bytes) }
