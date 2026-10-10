package mux

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/colitu/csl/internal/dialguard"
	"github.com/colitu/csl/internal/relay"
	"github.com/xtaci/smux"
)

// Open opens a stream to target and waits at most ten seconds for the server.
func Open(s *smux.Session, target string) (*smux.Stream, error) {
	return OpenWithTimeout(s, target, 10*time.Second)
}

// OpenWithTimeout bounds the destination request and status exchange.
func OpenWithTimeout(s *smux.Session, target string, timeout time.Duration) (*smux.Stream, error) {
	st, err := s.OpenStream()
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		st.Close()
		return nil, errors.New("mux: open timeout must be positive")
	}
	if err := st.SetDeadline(time.Now().Add(timeout)); err != nil {
		st.Close()
		return nil, err
	}
	if err := WriteRequest(st, target); err != nil {
		st.Close()
		return nil, err
	}
	if err := ReadStatus(st); err != nil {
		st.Close()
		return nil, err
	}
	if err := st.SetDeadline(time.Time{}); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}

// DialFunc connects a stream's destination on the server.
type DialFunc func(ctx context.Context, target string) (net.Conn, error)

// StreamLimiter bounds the number of active streams shared by many sessions.
type StreamLimiter struct {
	slots chan struct{}
}

func NewStreamLimiter(maxStreams int) *StreamLimiter {
	if maxStreams <= 0 {
		panic("mux: stream limit must be positive")
	}
	return &StreamLimiter{slots: make(chan struct{}, maxStreams)}
}

// Active returns the number of slots currently held by active streams.
func (l *StreamLimiter) Active() int {
	if l == nil {
		return 0
	}
	return len(l.slots)
}

func (l *StreamLimiter) tryAcquire() bool {
	if l == nil {
		return true
	}
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *StreamLimiter) release() {
	if l != nil {
		<-l.slots
	}
}

// Serve accepts streams on s, dials each destination with dial and relays
// data until the session ends.
func Serve(s *smux.Session, dial DialFunc, dialTimeout time.Duration) error {
	return ServeWithLimits(s, dial, dialTimeout, 128, nil)
}

// ServeWithLimits bounds streams in this session and, when total is non-nil,
// across all sessions sharing total. Excess streams are rejected; StatusBusy
// is sent when the peer has not already closed the stream.
func ServeWithLimits(s *smux.Session, dial DialFunc, dialTimeout time.Duration, perSession int, total *StreamLimiter) error {
	return ServeWithLimitGroups(s, dial, dialTimeout, perSession, total)
}

// ServeWithLimitGroups applies each shared limit after the per-session limit.
// For example, a node can pass its global limiter and a user's limiter.
func ServeWithLimitGroups(s *smux.Session, dial DialFunc, dialTimeout time.Duration, perSession int, totals ...*StreamLimiter) error {
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	if perSession <= 0 {
		perSession = 128
	}
	local := NewStreamLimiter(perSession)
	var workers sync.WaitGroup
	for {
		st, err := s.AcceptStream()
		if err != nil {
			workers.Wait()
			return err
		}
		if !local.tryAcquire() {
			WriteStatus(st, StatusBusy)
			st.Close()
			continue
		}
		acquired := 0
		for _, limit := range totals {
			if !limit.tryAcquire() {
				break
			}
			acquired++
		}
		if acquired != len(totals) {
			for i := acquired - 1; i >= 0; i-- {
				totals[i].release()
			}
			local.release()
			WriteStatus(st, StatusBusy)
			st.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer local.release()
			for _, limit := range totals {
				defer limit.release()
			}
			serveStream(st, dial, dialTimeout)
		}()
	}
}

func serveStream(st *smux.Stream, dial DialFunc, timeout time.Duration) {
	st.SetReadDeadline(time.Now().Add(timeout))
	target, err := ReadRequest(st)
	if err != nil {
		WriteStatus(st, StatusBadRequest)
		st.Close()
		return
	}
	st.SetReadDeadline(time.Time{})
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	conn, err := dial(ctx, target)
	cancel()
	if err != nil {
		code := StatusUnreachable
		if errors.Is(err, dialguard.ErrForbidden) {
			code = StatusForbidden
		}
		WriteStatus(st, code)
		st.Close()
		return
	}
	if err := WriteStatus(st, StatusOK); err != nil {
		conn.Close()
		st.Close()
		return
	}
	relay.Pipe(st, conn)
}
