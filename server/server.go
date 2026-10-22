// Package server accepts CSL carriers, runs the server side of the
// handshake and keeps the table of live sessions.
//
// The node runs it behind the existing cores: it listens on loopback and is
// reached through Xray or sing-box, so carriers are already encrypted and
// authenticated by the time they arrive here.
package server

import (
	"crypto/sha256"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/colitu/csl/frame"
	"github.com/colitu/csl/handshake"
	"github.com/colitu/csl/session"
)

// Config tunes a Server.
type Config struct {
	Session session.Config

	// HandshakeTimeout bounds the absolute pending lifetime between greeting
	// and request. Parked warm spares are rotated before this deadline (2 min).
	HandshakeTimeout time.Duration
	// MaxSessions limits live sessions (4096).
	MaxSessions int
	// Authenticate maps an opaque HELLO credential to a trusted identity.
	// When set, every new session must authenticate successfully.
	Authenticate func([]byte) (string, error)
	// MaxSessionsPerIdentity limits authenticated sessions for one identity.
	// It defaults to 4 when Authenticate is set.
	MaxSessionsPerIdentity int
	// MaxPendingCarriers limits carriers waiting for a HELLO or RESUME request.
	// This includes parked warm spares but not carriers attached to sessions.
	MaxPendingCarriers int
	// OnSession is called in its own goroutine for every new session.
	OnSession func(id handshake.ID, s *session.Session)
	// OnAuthenticatedSession receives the verified identity as well. When set,
	// it replaces OnSession.
	OnAuthenticatedSession func(id handshake.ID, identity string, s *session.Session)
	// Logf receives diagnostic messages. It must not log user traffic.
	Logf func(format string, args ...any)
	// NoIdle refuses the clients' idle liveness profile (handshake extension
	// 1); by default a valid profile is accepted and echoed.
	NoIdle bool
}

// Server is a CSL server.
type Server struct {
	cfg Config

	mu       sync.Mutex
	sessions map[handshake.ID]*entry
	pending  map[net.Conn]struct{}
	closed   bool
	lns      []net.Listener
}

type entry struct {
	sess           *session.Session
	secret         handshake.Secret
	identity       string
	credentialHash [sha256.Size]byte
}

// New returns a server.
func New(cfg Config) *Server {
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 2 * time.Minute
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 4096
	}
	if cfg.Authenticate != nil && cfg.MaxSessionsPerIdentity <= 0 {
		cfg.MaxSessionsPerIdentity = 4
	}
	if cfg.MaxPendingCarriers <= 0 {
		cfg.MaxPendingCarriers = 1024
		if cfg.MaxSessions < 960 {
			cfg.MaxPendingCarriers = cfg.MaxSessions + 64
		}
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Server{cfg: cfg, sessions: make(map[handshake.ID]*entry), pending: make(map[net.Conn]struct{})}
}

// Serve accepts carriers on ln until ln is closed.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.lns = append(s.lns, ln)
	s.mu.Unlock()
	for {
		conn, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		if !s.registerPending(conn) {
			conn.Close()
			continue
		}
		go func() {
			defer s.unregisterPending(conn)
			s.handleCarrier(conn)
		}()
	}
}

// Close stops all listeners and aborts every session.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	lns := s.lns
	var sessions []*session.Session
	for _, e := range s.sessions {
		sessions = append(sessions, e.sess)
	}
	var pending []net.Conn
	for conn := range s.pending {
		pending = append(pending, conn)
	}
	s.mu.Unlock()
	for _, ln := range lns {
		ln.Close()
	}
	for _, conn := range pending {
		conn.Close()
	}
	for _, sess := range sessions {
		sess.Abort(session.ErrClosed)
	}
	return nil
}

// Sessions returns the number of live sessions.
func (s *Server) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// PendingCarriers returns the number of greeted or not-yet-greeted carriers
// waiting for HELLO or RESUME.
func (s *Server) PendingCarriers() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// RevokeCredentialHash closes sessions created with a credential whose
// SHA-256 hash has been removed or reassigned by the identity provider.
func (s *Server) RevokeCredentialHash(hash [sha256.Size]byte) {
	s.mu.Lock()
	var revoked []*session.Session
	for _, e := range s.sessions {
		if e.credentialHash == hash {
			revoked = append(revoked, e.sess)
		}
	}
	s.mu.Unlock()
	for _, sess := range revoked {
		sess.Abort(session.ErrClosed)
	}
}

func (s *Server) registerPending(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.pending) >= s.cfg.MaxPendingCarriers {
		return false
	}
	s.pending[conn] = struct{}{}
	return true
}

func (s *Server) unregisterPending(conn net.Conn) {
	s.mu.Lock()
	delete(s.pending, conn)
	s.mu.Unlock()
}

// HandleCarrier runs the handshake on a new carrier and attaches it to a new
// or existing session. It takes ownership of conn.
func (s *Server) HandleCarrier(conn net.Conn) {
	if !s.registerPending(conn) {
		conn.Close()
		return
	}
	defer s.unregisterPending(conn)
	s.handleCarrier(conn)
}

func (s *Server) handleCarrier(conn net.Conn) {
	label := conn.RemoteAddr().String()
	nonce, err := handshake.NewNonce()
	if err != nil {
		conn.Close()
		return
	}
	conn.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	if err := frame.Write(conn, handshake.Greeting{Version: handshake.Version, Nonce: nonce}.Frame()); err != nil {
		conn.Close()
		return
	}
	r := frame.NewReader(conn)
	req, err := handshake.ReadRequestWithKeepalive(r, conn, s.cfg.HandshakeTimeout)
	if err != nil {
		reason := handshake.ReasonProtocol
		if errors.Is(err, handshake.ErrVersion) {
			reason = handshake.ReasonVersion
		}
		s.reject(conn, reason)
		return
	}
	// Answer quickly from here on: the client is waiting.
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if req.Hello != nil {
		s.newSession(conn, r, *req.Hello, label)
	} else {
		s.resume(conn, r, nonce, *req.Resume, label)
	}
}

func (s *Server) reject(conn net.Conn, reason handshake.Reason) {
	frame.Write(conn, handshake.RejectFrame(reason))
	conn.Close()
}

func (s *Server) newSession(conn net.Conn, r *frame.Reader, h handshake.Hello, label string) {
	identity := ""
	if s.cfg.Authenticate != nil {
		var err error
		identity, err = s.cfg.Authenticate(h.Credential)
		if err != nil || identity == "" {
			s.reject(conn, handshake.ReasonDenied)
			return
		}
	} else if len(h.Credential) != 0 || s.cfg.MaxSessionsPerIdentity > 0 {
		s.reject(conn, handshake.ReasonDenied)
		return
	}
	id, secret, err := handshake.NewCredentials()
	if err != nil {
		conn.Close()
		return
	}
	cfg := s.cfg.Session
	var idle *handshake.Idle
	if h.Idle != nil && !s.cfg.NoIdle {
		idle = h.Idle
		cfg.IdleAfter, cfg.IdlePingInterval, cfg.IdleDeadAfter = idle.After, idle.Ping, idle.Dead
	}
	cfg.OnFinish = func(err error) {
		s.mu.Lock()
		delete(s.sessions, id)
		s.mu.Unlock()
		s.cfg.Logf("session %s ended: %v", id, err)
	}
	cfg.OnCarrierLost = nil // the client drives recovery
	sess := session.New(cfg, h.Window)

	s.mu.Lock()
	if s.closed || len(s.sessions) >= s.cfg.MaxSessions {
		s.mu.Unlock()
		sess.Abort(session.ErrClosed)
		s.reject(conn, handshake.ReasonBusy)
		return
	}
	if s.cfg.MaxSessionsPerIdentity > 0 {
		count := 0
		for _, e := range s.sessions {
			if e.identity == identity {
				count++
			}
		}
		if count >= s.cfg.MaxSessionsPerIdentity {
			s.mu.Unlock()
			sess.Abort(session.ErrClosed)
			s.reject(conn, handshake.ReasonBusy)
			return
		}
	}
	s.sessions[id] = &entry{sess: sess, secret: secret, identity: identity, credentialHash: sha256.Sum256(h.Credential)}
	s.mu.Unlock()

	welcome := handshake.Welcome{ID: id, Secret: secret, Window: sess.Window(), Idle: idle, Extended: h.Extended()}
	if err := frame.Write(conn, welcome.Frame()); err != nil {
		conn.Close()
		sess.Abort(err)
		return
	}
	conn.SetDeadline(time.Time{})
	if err := sess.Attach(conn, r, 0, label); err != nil {
		return
	}
	s.cfg.Logf("session %s started", id)
	if s.cfg.OnAuthenticatedSession != nil {
		go s.cfg.OnAuthenticatedSession(id, identity, sess)
	} else if s.cfg.OnSession != nil {
		go s.cfg.OnSession(id, sess)
	}
}

func (s *Server) resume(conn net.Conn, r *frame.Reader, nonce handshake.Nonce, req handshake.ResumeRequest, label string) {
	s.mu.Lock()
	e := s.sessions[req.ID]
	s.mu.Unlock()
	// Unknown sessions and bad proofs get the same answer.
	if e == nil || !handshake.VerifyMAC(e.secret, nonce, req) {
		s.reject(conn, handshake.ReasonDenied)
		return
	}
	recvNext, err := e.sess.PrepareResume()
	if err != nil {
		s.reject(conn, handshake.ReasonExpired)
		return
	}
	if err := frame.Write(conn, handshake.ResumeAccept{RecvNext: recvNext}.Frame()); err != nil {
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{})
	if err := e.sess.Attach(conn, r, req.RecvNext, label); err != nil {
		s.cfg.Logf("session %s resume failed: %v", req.ID, err)
		return
	}
	s.cfg.Logf("session %s resumed", req.ID)
}
