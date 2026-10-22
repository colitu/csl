// Package session implements the resumable CSL session.
//
// A Session is a reliable, ordered byte stream that outlives the carrier
// connections it runs on. Every byte has a stream offset. The sender keeps
// written bytes until the peer's application has consumed them (ACK), so when
// a carrier dies the stream continues on a new carrier from the offset the
// peer reports in the resume handshake. Carriers are themselves reliable
// (TCP, QUIC streams), so data is only ever retransmitted after a resume.
//
// ACKs double as flow control: a sender never has more than the peer's
// advertised window in flight beyond the last ACK, which bounds the
// receiver's buffer without ever blocking the carrier's read loop.
//
// Liveness is receive based. Both sides PING every PingInterval; a carrier
// on which nothing at all arrived for DeadAfter is declared dead. With an
// idle profile (negotiated in the handshake) a session without stream data
// for IdleAfter pings every IdlePingInterval and tolerates IdleDeadAfter of
// silence, which saves battery on phones; the first data switches back, and
// the silence before it does not count against the carrier.
package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/colitu/csl/frame"
)

// Config tunes a Session. Zero fields take the defaults listed below.
type Config struct {
	Window       int           // receive buffer and advertised window (4 MiB)
	SendBuffer   int           // unacknowledged bytes kept for resume (4 MiB)
	PingInterval time.Duration // how often each side pings (500 ms)
	DeadAfter    time.Duration // silence before a carrier is declared dead (1.5 s)
	Linger       time.Duration // lifetime without any carrier (90 s)
	// Idle profile (zero IdleAfter: off). Both sides must use the same
	// values (handshake extension 1).
	IdleAfter        time.Duration // no stream data for this long: idle
	IdlePingInterval time.Duration // ping interval while idle
	IdleDeadAfter    time.Duration // silence tolerated while idle
	CloseTimeout     time.Duration // how long a graceful close may take (5 s)
	WriteTimeout     time.Duration // deadline for a single carrier write (10 s)
	AckDelay         time.Duration // delay before a small ACK is sent (10 ms)
	MaxBatch         int           // bytes gathered into one carrier write (64 KiB)
	DgramQueue       int           // queued outgoing datagrams (128)
	Budget           *MemoryBudget // optional node-wide ring and datagram storage cap

	// OnCarrierLost is called (in its own goroutine) when the active carrier
	// dies on its own. It is not called for carriers replaced by Attach.
	OnCarrierLost func(err error)
	// OnFinish is called (in its own goroutine) once the session has ended.
	OnFinish func(err error)
}

// Defaults.
const (
	DefaultWindow       = 4 << 20
	DefaultSendBuffer   = 4 << 20
	DefaultPingInterval = 500 * time.Millisecond
	DefaultDeadAfter    = 1500 * time.Millisecond
	DefaultLinger       = 90 * time.Second
	DefaultCloseTimeout = 5 * time.Second
	DefaultWriteTimeout = 10 * time.Second
	DefaultAckDelay     = 10 * time.Millisecond
	DefaultMaxBatch     = 64 << 10
	DefaultDgramQueue   = 128

	// MinWindow and MaxWindow bound what a peer may advertise.
	MinWindow = 64 << 10
	MaxWindow = 64 << 20
)

// WithDefaults returns c with every zero field set to its default.
func (c Config) WithDefaults() Config {
	set := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	if c.Window <= 0 {
		c.Window = DefaultWindow
	}
	c.Window = max(MinWindow, min(c.Window, MaxWindow))
	if c.SendBuffer <= 0 {
		c.SendBuffer = DefaultSendBuffer
	}
	if c.MaxBatch <= 0 {
		c.MaxBatch = DefaultMaxBatch
	}
	if c.DgramQueue <= 0 {
		c.DgramQueue = DefaultDgramQueue
	}
	set(&c.PingInterval, DefaultPingInterval)
	set(&c.DeadAfter, DefaultDeadAfter)
	set(&c.Linger, DefaultLinger)
	set(&c.CloseTimeout, DefaultCloseTimeout)
	set(&c.WriteTimeout, DefaultWriteTimeout)
	set(&c.AckDelay, DefaultAckDelay)
	if c.IdleAfter > 0 && (c.IdlePingInterval <= 0 || c.IdleDeadAfter <= 0) {
		c.IdleAfter = 0
	}
	return c
}

// ClampWindow bounds a window advertised by a peer.
func ClampWindow(w uint64) uint64 { return max(MinWindow, min(w, MaxWindow)) }

var (
	ErrClosed         = errors.New("session: closed")
	ErrPeerClosed     = errors.New("session: closed by peer")
	ErrCarrierTimeout = errors.New("session: carrier timed out")
	ErrLingerExpired  = errors.New("session: no carrier within linger period")
	ErrReplaced       = errors.New("session: carrier replaced")
	ErrProtocol       = errors.New("session: protocol violation")
	ErrResumeMismatch = errors.New("session: resume offset out of range")
	ErrDgramTooLarge  = errors.New("session: datagram too large")
	ErrMemoryBudget   = errors.New("session: node buffer memory budget exhausted")
)

// Stats is a snapshot of a session's counters.
type Stats struct {
	BytesSent     uint64        // stream offset written by the application
	BytesReceived uint64        // stream offset received from the peer
	Carriers      int           // carriers attached so far
	RTT           time.Duration // last PING round trip
	Attached      bool          // a carrier is currently attached
	Carrier       string        // label of the current carrier
}

type link struct {
	conn     net.Conn
	r        *frame.Reader
	label    string
	dead     bool
	done     chan struct{}
	lastRecv time.Time
}

// Session is a resumable byte stream. It implements io.ReadWriteCloser.
type Session struct {
	cfg        Config
	peerWindow uint64

	mu   sync.Mutex
	cond *sync.Cond

	// Send side: send holds offsets [sendBase, sendBase+send.Len()).
	send     *ring
	sendBase uint64 // first byte not yet consumed by the peer
	sendNext uint64 // next byte to transmit on the current carrier

	// Receive side.
	recv       *ring
	recvNext   uint64 // next offset expected from the peer
	consumed   uint64 // bytes handed to the application
	ackSent    uint64 // consumed value last reported to the peer
	pendingAck bool
	ackTimer   *time.Timer

	link        *link
	carriers    int
	lingerTimer *time.Timer
	lingerSeq   uint64

	// lastActive is the last time stream data or a datagram moved either
	// way (idle profile).
	lastActive time.Time

	pingDue  bool
	pingID   uint64
	pingSent time.Time
	rtt      time.Duration
	pongs    []uint64

	dgramOut [][]byte
	dgramIn  chan []byte

	localClosed  bool
	closeSent    bool
	closeWritten bool
	remoteClosed bool
	closeTimer   *time.Timer

	finished bool
	err      error
	done     chan struct{}
}

// New returns a session without a carrier. peerWindow is the window the peer
// advertised in the handshake. The linger timer starts immediately.
func New(cfg Config, peerWindow uint64) *Session {
	cfg = cfg.WithDefaults()
	s := &Session{
		cfg:        cfg,
		peerWindow: ClampWindow(peerWindow),
		send:       newRing(cfg.SendBuffer, cfg.Budget),
		recv:       newRing(cfg.Window, cfg.Budget),
		dgramIn:    make(chan []byte, cfg.DgramQueue),
		done:       make(chan struct{}),
		lastActive: time.Now(),
	}
	s.cond = sync.NewCond(&s.mu)
	s.mu.Lock()
	s.startLingerLocked()
	s.mu.Unlock()
	return s
}

// Window returns the receive window this session advertises.
func (s *Session) Window() uint64 { return uint64(s.cfg.Window) }

// Attach makes conn the active carrier. r must be the frame reader used for
// the handshake on conn (it may hold buffered bytes). peerRecvNext is the
// offset the peer expects next: 0 for a new session, or the value from the
// resume handshake. Any previous carrier is closed.
func (s *Session) Attach(conn net.Conn, r *frame.Reader, peerRecvNext uint64, label string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished {
		conn.Close()
		return s.finalErrLocked()
	}
	end := s.sendBase + uint64(s.send.Len())
	if peerRecvNext < s.sendBase || peerRecvNext > end {
		conn.Close()
		s.finishLocked(ErrResumeMismatch)
		return ErrResumeMismatch
	}
	if s.link != nil {
		s.dropLinkLocked(s.link, ErrReplaced, false)
	}
	l := &link{conn: conn, r: r, label: label, done: make(chan struct{}), lastRecv: time.Now()}
	s.link = l
	s.carriers++
	s.sendNext = peerRecvNext
	s.closeSent, s.closeWritten = false, false
	s.pendingAck = true
	s.pingDue = true
	s.stopLingerLocked()
	go s.readLoop(l)
	go s.writeLoop(l)
	go s.monitor(l)
	s.cond.Broadcast()
	return nil
}

// PrepareResume detaches the current carrier, if any, and returns the offset
// this side expects next. Call it right before answering or sending a resume
// handshake so the reported offset cannot move.
func (s *Session) PrepareResume() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished {
		return 0, s.finalErrLocked()
	}
	if s.link != nil {
		s.dropLinkLocked(s.link, ErrReplaced, false)
	}
	return s.recvNext, nil
}

// Read implements io.Reader.
func (s *Session) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.recv.Len() == 0 {
		switch {
		case s.remoteClosed:
			return 0, io.EOF
		case s.localClosed:
			return 0, ErrClosed
		case s.finished:
			if s.err == nil {
				return 0, io.EOF
			}
			return 0, s.err
		}
		s.cond.Wait()
	}
	n := s.recv.Read(p)
	if s.finished && s.recv.Len() == 0 {
		s.recv.Release()
	}
	s.consumed += uint64(n)
	s.maybeAckLocked()
	return n, nil
}

// Write implements io.Writer. It blocks while the send buffer is full.
func (s *Session) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for len(p) > 0 {
		for {
			switch {
			case s.localClosed:
				return total, ErrClosed
			case s.remoteClosed:
				return total, ErrPeerClosed
			case s.finished:
				return total, s.finalErrLocked()
			}
			if s.send.Free() > 0 {
				break
			}
			s.cond.Wait()
		}
		n := s.send.Write(p)
		if n == 0 {
			return total, ErrMemoryBudget
		}
		p = p[n:]
		total += n
		s.cond.Broadcast()
	}
	return total, nil
}

// Close starts a graceful close: buffered data is still delivered, then a
// CLOSE frame is exchanged. It does not block.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.beginCloseLocked()
	return nil
}

// Abort ends the session immediately without delivering buffered data.
func (s *Session) Abort(err error) {
	if err == nil {
		err = ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finishLocked(err)
}

// SendDatagram queues an unreliable datagram. Datagrams are dropped when the
// queue is full or the carrier changes.
func (s *Session) SendDatagram(p []byte) error {
	if len(p) > frame.MaxPayload {
		return ErrDgramTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finished || s.localClosed {
		return ErrClosed
	}
	if len(s.dgramOut) >= s.cfg.DgramQueue {
		return nil
	}
	if s.cfg.Budget != nil && !s.cfg.Budget.reserve(int64(len(p))) {
		return nil // unreliable datagrams are dropped under memory pressure
	}
	s.dgramOut = append(s.dgramOut, append([]byte(nil), p...))
	s.cond.Broadcast()
	return nil
}

// ReceiveDatagram returns the next datagram from the peer.
func (s *Session) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case d := <-s.dgramIn:
		if s.cfg.Budget != nil {
			s.cfg.Budget.release(int64(len(d)))
		}
		return d, nil
	case <-s.done:
		return nil, s.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Done is closed when the session has ended.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err returns why the session ended (nil for a graceful close or while it is
// still running).
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Stats returns a snapshot of the session counters.
func (s *Session) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Stats{
		BytesSent:     s.sendBase + uint64(s.send.Len()),
		BytesReceived: s.recvNext,
		Carriers:      s.carriers,
		RTT:           s.rtt,
		Attached:      s.link != nil,
	}
	if s.link != nil {
		st.Carrier = s.link.label
	}
	return st
}

// Internal state handling. All *Locked methods require s.mu.

func (s *Session) finalErrLocked() error {
	if s.err != nil {
		return s.err
	}
	return ErrClosed
}

func (s *Session) startLingerLocked() {
	if s.lingerTimer != nil {
		return
	}
	s.lingerSeq++
	seq := s.lingerSeq
	s.lingerTimer = time.AfterFunc(s.cfg.Linger, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.lingerSeq == seq && s.link == nil {
			s.finishLocked(ErrLingerExpired)
		}
	})
}

func (s *Session) stopLingerLocked() {
	s.lingerSeq++
	if s.lingerTimer != nil {
		s.lingerTimer.Stop()
		s.lingerTimer = nil
	}
}

func (s *Session) beginCloseLocked() {
	if s.localClosed || s.finished {
		return
	}
	s.localClosed = true
	s.closeTimer = time.AfterFunc(s.cfg.CloseTimeout, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.finishLocked(nil)
	})
	s.cond.Broadcast()
}

func (s *Session) maybeFinishLocked() {
	if s.localClosed && s.closeWritten && s.remoteClosed {
		s.finishLocked(nil)
	}
}

func (s *Session) finishLocked(err error) {
	if s.finished {
		return
	}
	s.finished = true
	s.err = err
	if s.link != nil {
		s.dropLinkLocked(s.link, err, false)
	}
	s.stopLingerLocked()
	if s.ackTimer != nil {
		s.ackTimer.Stop()
	}
	if s.closeTimer != nil {
		s.closeTimer.Stop()
	}
	s.send.Release()
	if err != nil || s.recv.Len() == 0 {
		s.recv.Release()
	}
	s.clearOutboundDatagramsLocked()
	for {
		select {
		case d := <-s.dgramIn:
			if s.cfg.Budget != nil {
				s.cfg.Budget.release(int64(len(d)))
			}
		default:
			goto datagramsDrained
		}
	}
datagramsDrained:
	close(s.done)
	s.cond.Broadcast()
	if s.cfg.OnFinish != nil {
		go s.cfg.OnFinish(err)
	}
}

// dropLinkLocked closes l. If l was the active carrier the session starts
// lingering and, when notify is set, reports the loss.
func (s *Session) dropLinkLocked(l *link, err error, notify bool) {
	if l.dead {
		return
	}
	l.dead = true
	close(l.done)
	l.conn.Close()
	if s.link == l {
		s.link = nil
		s.clearOutboundDatagramsLocked()
		s.send.TrimIdle(time.Now(), 0)
		s.recv.TrimIdle(time.Now(), 0)
		if !s.finished {
			s.startLingerLocked()
			if notify && s.cfg.OnCarrierLost != nil {
				go s.cfg.OnCarrierLost(err)
			}
		}
	}
	s.cond.Broadcast()
}

func (s *Session) clearOutboundDatagramsLocked() {
	if s.cfg.Budget != nil {
		for _, d := range s.dgramOut {
			s.cfg.Budget.release(int64(len(d)))
		}
	}
	s.dgramOut = nil
}

func (s *Session) killLink(l *link, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropLinkLocked(l, err, true)
}

func (s *Session) maybeAckLocked() {
	delta := s.consumed - s.ackSent
	if delta == 0 {
		return
	}
	if delta >= uint64(s.cfg.Window/8) {
		s.pendingAck = true
		s.cond.Broadcast()
		return
	}
	if s.ackTimer == nil {
		s.ackTimer = time.AfterFunc(s.cfg.AckDelay, func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.ackTimer = nil
			if !s.finished && s.consumed > s.ackSent {
				s.pendingAck = true
				s.cond.Broadcast()
			}
		})
	}
}

func (s *Session) sendEndLocked() uint64 { return s.sendBase + uint64(s.send.Len()) }

func (s *Session) canSendDataLocked() bool {
	return !s.remoteClosed && !s.closeSent &&
		s.sendNext < s.sendEndLocked() &&
		s.sendNext-s.sendBase < s.peerWindow
}

func (s *Session) closeReadyLocked() bool {
	return s.localClosed && !s.closeSent && (s.remoteClosed || s.sendNext == s.sendEndLocked())
}

func (s *Session) hasWorkLocked() bool {
	return s.pendingAck || s.pingDue || len(s.pongs) > 0 || len(s.dgramOut) > 0 ||
		s.canSendDataLocked() || s.closeReadyLocked()
}

// buildBatchLocked gathers pending frames into b. It reports whether the
// batch contains this side's CLOSE.
func (s *Session) buildBatchLocked(b []byte) ([]byte, bool) {
	if s.pendingAck {
		b = frame.AppendHeader(b, frame.TypeAck, 0, s.consumed, 0)
		s.ackSent = s.consumed
		s.pendingAck = false
	}
	for _, id := range s.pongs {
		b = frame.AppendHeader(b, frame.TypePong, 0, id, 0)
	}
	s.pongs = s.pongs[:0]
	if s.pingDue {
		s.pingID++
		s.pingSent = time.Now()
		b = frame.AppendHeader(b, frame.TypePing, 0, s.pingID, 0)
		s.pingDue = false
	}
	for len(s.dgramOut) > 0 && len(b) < s.cfg.MaxBatch {
		d := s.dgramOut[0]
		b = frame.AppendHeader(b, frame.TypeDgram, 0, 0, len(d))
		b = append(b, d...)
		s.lastActive = time.Now()
		if s.cfg.Budget != nil {
			s.cfg.Budget.release(int64(len(d)))
		}
		s.dgramOut = s.dgramOut[1:]
	}
	if len(s.dgramOut) == 0 {
		s.dgramOut = nil
	}
	for len(b) < s.cfg.MaxBatch && s.canSendDataLocked() {
		limit := min(s.sendEndLocked(), s.sendBase+s.peerWindow)
		n := int(min(uint64(frame.MaxPayload), limit-s.sendNext))
		b = frame.AppendHeader(b, frame.TypeData, 0, s.sendNext, n)
		b = s.send.AppendAt(b, int(s.sendNext-s.sendBase), n)
		s.sendNext += uint64(n)
		s.lastActive = time.Now()
	}
	if s.closeReadyLocked() {
		b = frame.AppendHeader(b, frame.TypeClose, 0, s.sendNext, 0)
		s.closeSent = true
		return b, true
	}
	return b, false
}

func (s *Session) writeLoop(l *link) {
	batch := make([]byte, 0, s.cfg.MaxBatch+frame.MaxFrame)
	for {
		s.mu.Lock()
		for !l.dead && !(s.link == l && s.hasWorkLocked()) {
			s.cond.Wait()
		}
		if l.dead {
			s.mu.Unlock()
			return
		}
		var hasClose bool
		batch, hasClose = s.buildBatchLocked(batch[:0])
		s.mu.Unlock()

		l.conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))
		if _, err := l.conn.Write(batch); err != nil {
			s.killLink(l, err)
			return
		}
		if hasClose {
			s.mu.Lock()
			if !l.dead && s.closeSent {
				s.closeWritten = true
				s.maybeFinishLocked()
			}
			s.mu.Unlock()
		}
	}
}

func (s *Session) readLoop(l *link) {
	for {
		fr, err := l.r.Read()
		if err != nil {
			s.killLink(l, err)
			return
		}
		s.mu.Lock()
		if l.dead {
			s.mu.Unlock()
			return
		}
		l.lastRecv = time.Now()
		if err := s.handleLocked(fr); err != nil {
			s.finishLocked(err)
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
	}
}

func (s *Session) handleLocked(fr frame.Frame) error {
	switch fr.Type {
	case frame.TypeData:
		if s.remoteClosed {
			return nil
		}
		if fr.Seq > s.recvNext {
			return fmt.Errorf("%w: data gap at %d, expected %d", ErrProtocol, fr.Seq, s.recvNext)
		}
		skip := s.recvNext - fr.Seq
		if skip >= uint64(len(fr.Payload)) {
			return nil // already received before a resume
		}
		data := fr.Payload[skip:]
		if len(data) > s.recv.Free() {
			return fmt.Errorf("%w: peer exceeded receive window", ErrProtocol)
		}
		if s.recv.Write(data) != len(data) {
			return ErrMemoryBudget
		}
		s.recvNext += uint64(len(data))
		s.lastActive = time.Now()
		s.cond.Broadcast()

	case frame.TypeAck:
		if fr.Seq > s.sendEndLocked() {
			return fmt.Errorf("%w: ack beyond sent data", ErrProtocol)
		}
		if fr.Seq > s.sendBase {
			s.send.Discard(int(fr.Seq - s.sendBase))
			s.sendBase = fr.Seq
			if s.sendNext < s.sendBase {
				s.sendNext = s.sendBase
			}
			s.cond.Broadcast()
		}

	case frame.TypePing:
		if len(s.pongs) < 16 {
			s.pongs = append(s.pongs, fr.Seq)
			s.cond.Broadcast()
		}

	case frame.TypePong:
		if fr.Seq == s.pingID && !s.pingSent.IsZero() {
			s.rtt = time.Since(s.pingSent)
			s.pingSent = time.Time{}
		}

	case frame.TypeDgram:
		s.lastActive = time.Now()
		if s.cfg.Budget != nil && !s.cfg.Budget.reserve(int64(len(fr.Payload))) {
			return nil // unreliable datagrams are dropped under memory pressure
		}
		select {
		case s.dgramIn <- append([]byte(nil), fr.Payload...):
		default: // receiver is not keeping up; datagrams are unreliable
			if s.cfg.Budget != nil {
				s.cfg.Budget.release(int64(len(fr.Payload)))
			}
		}

	case frame.TypeClose:
		if fr.Seq > s.recvNext {
			return fmt.Errorf("%w: close beyond received data", ErrProtocol)
		}
		if !s.remoteClosed {
			s.remoteClosed = true
			s.beginCloseLocked()
			s.cond.Broadcast()
			s.maybeFinishLocked()
		}

	default:
		// PAD and unknown frame types are ignored for forward compatibility.
	}
	return nil
}

// monitor pings every PingInterval and checks for silence more often, so a
// dead carrier is noticed at most DeadAfter/6 late.
//
// Idle profile: a side relaxes its own silence limit DeadAfter before it
// slows its pings, so the peer (whose idle clock may lag by the one-way
// delay) never sees the slower pings with the strict limit. When data
// moves again the silence limit counts from that moment ("wake"), because
// the peer may still be on the slow ping interval for a moment.
func (s *Session) monitor(l *link) {
	activeTick := max(min(s.cfg.PingInterval, s.cfg.DeadAfter/6), 10*time.Millisecond)
	idleTick := activeTick
	if s.cfg.IdleAfter > 0 {
		idleTick = max(min(time.Second, s.cfg.IdlePingInterval, s.cfg.IdleDeadAfter/6), activeTick)
	}
	t := time.NewTicker(activeTick)
	defer t.Stop()
	lastPing := time.Now()
	relaxed, slowed := false, false
	var wake time.Time
	for {
		select {
		case <-l.done:
			return
		case now := <-t.C:
			s.mu.Lock()
			s.send.TrimIdle(now, 30*time.Second)
			s.recv.TrimIdle(now, 30*time.Second)
			if l.dead {
				s.mu.Unlock()
				return
			}
			nowRelaxed, nowSlowed := s.idleLocked(now)
			if relaxed && !nowRelaxed {
				wake = now
				lastPing = time.Time{} // ping at once: the peer answers and refreshes lastRecv
			}
			if nowSlowed != slowed {
				if nowSlowed {
					t.Reset(idleTick)
				} else {
					t.Reset(activeTick)
				}
			}
			relaxed, slowed = nowRelaxed, nowSlowed
			ping, dead := s.cfg.PingInterval, s.cfg.DeadAfter
			if slowed {
				ping = s.cfg.IdlePingInterval
			}
			if relaxed {
				dead = s.cfg.IdleDeadAfter
			}
			silentSince := l.lastRecv
			if wake.After(silentSince) {
				silentSince = wake
			}
			if now.Sub(silentSince) > dead {
				s.dropLinkLocked(l, ErrCarrierTimeout, true)
				s.mu.Unlock()
				return
			}
			if s.link == l && now.Sub(lastPing) >= ping {
				lastPing = now
				s.pingDue = true
				s.cond.Broadcast()
			}
			s.mu.Unlock()
		}
	}
}

// idleLocked reports the idle profile's two stages: relaxed (the idle
// silence limit applies) and slowed (idle pings), relaxed starting
// DeadAfter earlier.
func (s *Session) idleLocked(now time.Time) (relaxed, slowed bool) {
	if s.cfg.IdleAfter <= 0 {
		return false, false
	}
	quiet := now.Sub(s.lastActive)
	return quiet >= max(s.cfg.IdleAfter-s.cfg.DeadAfter, 0), quiet >= s.cfg.IdleAfter
}
