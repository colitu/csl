package server

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/colitu/csl/frame"
	"github.com/colitu/csl/handshake"
	"github.com/colitu/csl/session"
)

func startServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := New(Config{Session: session.Config{Linger: 5 * time.Second}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	t.Cleanup(func() { s.Close() })
	return s, ln.Addr().String()
}

func TestAuthenticatedSessionLimit(t *testing.T) {
	s := New(Config{MaxSessionsPerIdentity: 1, Authenticate: func(credential []byte) (string, error) {
		switch {
		case bytes.Equal(credential, []byte("alice-token")):
			return "alice", nil
		case bytes.Equal(credential, []byte("bob-token")):
			return "bob", nil
		default:
			return "", errors.New("unknown credential")
		}
	}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	defer s.Close()
	addr := ln.Addr().String()
	hello := func(token string) error {
		c := dial(t, addr)
		_, err := handshake.ClientHello(c, c.r, handshake.Hello{Version: handshake.Version, Window: session.DefaultWindow, Credential: []byte(token)})
		return err
	}
	if err := hello("alice-token"); err != nil {
		t.Fatal(err)
	}
	var rejected *handshake.RejectError
	if err := hello("alice-token"); !errors.As(err, &rejected) || rejected.Reason != handshake.ReasonBusy {
		t.Fatalf("second Alice session = %v, want busy", err)
	}
	if err := hello("bob-token"); err != nil {
		t.Fatalf("Bob's first session = %v", err)
	}
	if err := hello(""); !errors.As(err, &rejected) || rejected.Reason != handshake.ReasonDenied {
		t.Fatalf("missing credential = %v, want denied", err)
	}
}

func TestCredentialRevocationClosesSession(t *testing.T) {
	s := New(Config{Authenticate: func([]byte) (string, error) { return "alice", nil }})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	defer s.Close()
	c := dial(t, ln.Addr().String())
	credential := []byte("alice-device-credential")
	if _, err := handshake.ClientHello(c, c.r, handshake.Hello{Version: handshake.Version, Window: session.DefaultWindow, Credential: credential}); err != nil {
		t.Fatal(err)
	}
	s.RevokeCredentialHash(sha256.Sum256(credential))
	deadline := time.Now().Add(time.Second)
	for s.Sessions() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.Sessions() != 0 {
		t.Fatal("revoked credential left a live session")
	}
}

type rawConn struct {
	net.Conn
	r *frame.Reader
	g handshake.Greeting
}

func dial(t *testing.T, addr string) *rawConn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { c.Close() })
	r := frame.NewReader(c)
	g, err := handshake.ReadGreeting(r)
	if err != nil {
		t.Fatal(err)
	}
	return &rawConn{Conn: c, r: r, g: g}
}

func TestNewSessionAndResume(t *testing.T) {
	s, addr := startServer(t)
	c1 := dial(t, addr)
	w, err := handshake.ClientHello(c1, c1.r, handshake.Hello{Version: handshake.Version, Window: session.DefaultWindow})
	if err != nil {
		t.Fatal(err)
	}
	if s.Sessions() != 1 {
		t.Fatalf("sessions = %d", s.Sessions())
	}
	c2 := dial(t, addr)
	if c2.g.Nonce == c1.g.Nonce {
		t.Fatal("nonce reused across carriers")
	}
	acc, err := handshake.ClientResume(c2, c2.r, c2.g, w.ID, w.Secret, 0)
	if err != nil {
		t.Fatal(err)
	}
	if acc.RecvNext != 0 {
		t.Fatalf("recvNext = %d", acc.RecvNext)
	}
}

// TestReplayRejected records a valid RESUME frame and replays it on a new
// carrier: the server's fresh nonce must make it fail.
func TestReplayRejected(t *testing.T) {
	_, addr := startServer(t)
	c1 := dial(t, addr)
	w, err := handshake.ClientHello(c1, c1.r, handshake.Hello{Version: handshake.Version, Window: session.DefaultWindow})
	if err != nil {
		t.Fatal(err)
	}
	c2 := dial(t, addr)
	recorded := handshake.ResumeRequest{Version: handshake.Version, ID: w.ID, RecvNext: 0}
	recorded.MAC = handshake.ComputeMAC(w.Secret, c2.g.Nonce, w.ID, 0)
	if err := frame.Write(c2, recorded.Frame()); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.r.Read(); err != nil {
		t.Fatal(err) // the original resume is accepted
	}

	c3 := dial(t, addr) // the attacker replays the same bytes
	if err := frame.Write(c3, recorded.Frame()); err != nil {
		t.Fatal(err)
	}
	fr, err := c3.r.Read()
	if err != nil {
		t.Fatal(err)
	}
	if fr.Type != frame.TypeClose || len(fr.Payload) == 0 || handshake.Reason(fr.Payload[0]) != handshake.ReasonDenied {
		t.Fatalf("replay answered with %v %v", fr.Type, fr.Payload)
	}
}

func TestParkedCarrierPingBeforeHello(t *testing.T) {
	_, addr := startServer(t)
	c := dial(t, addr)
	if err := frame.Write(c, frame.Frame{Type: frame.TypePing, Seq: 42}); err != nil {
		t.Fatal(err)
	}
	reply, err := c.r.Read()
	if err != nil || reply.Type != frame.TypePong || reply.Seq != 42 {
		t.Fatalf("parked carrier PONG = %v, %v", reply, err)
	}
	if _, err := handshake.ClientHello(c, c.r, handshake.Hello{Version: handshake.Version, Window: session.DefaultWindow}); err != nil {
		t.Fatalf("HELLO after PING: %v", err)
	}
}

func TestUnknownSessionDenied(t *testing.T) {
	_, addr := startServer(t)
	c := dial(t, addr)
	var id handshake.ID
	var secret handshake.Secret
	_, err := handshake.ClientResume(c, c.r, c.g, id, secret, 0)
	var rej *handshake.RejectError
	if !errors.As(err, &rej) || rej.Reason != handshake.ReasonDenied {
		t.Fatalf("want denied, got %v", err)
	}
}

func TestSessionLimit(t *testing.T) {
	s := New(Config{MaxSessions: 1})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go s.Serve(ln)
	defer s.Close()
	c1 := dial(t, ln.Addr().String())
	if _, err := handshake.ClientHello(c1, c1.r, handshake.Hello{Version: handshake.Version, Window: session.DefaultWindow}); err != nil {
		t.Fatal(err)
	}
	c2 := dial(t, ln.Addr().String())
	_, err := handshake.ClientHello(c2, c2.r, handshake.Hello{Version: handshake.Version, Window: session.DefaultWindow})
	var rej *handshake.RejectError
	if !errors.As(err, &rej) || rej.Reason != handshake.ReasonBusy {
		t.Fatalf("want busy, got %v", err)
	}
}

func TestPendingCarrierLimitAndClose(t *testing.T) {
	s := New(Config{MaxPendingCarriers: 1, HandshakeTimeout: 5 * time.Second})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	defer s.Close()

	first := dial(t, ln.Addr().String()) // parked after the server greeting
	second, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := frame.NewReader(second).Read(); err == nil {
		t.Fatal("pending carrier limit was not enforced")
	}

	s.Close()
	first.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := first.r.Read(); err == nil {
		t.Fatal("server close left the parked carrier open")
	}
}
