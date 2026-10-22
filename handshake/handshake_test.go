package handshake

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/colitu/csl/frame"
	"time"
)

func TestNewSessionAndResume(t *testing.T) {
	id, secret, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	cr, sr := frame.NewReader(c), frame.NewReader(s)

	// New session.
	nonce, _ := NewNonce()
	done := make(chan error, 1)
	go func() {
		if err := frame.Write(s, Greeting{Version: Version, Nonce: nonce}.Frame()); err != nil {
			done <- err
			return
		}
		req, err := ReadRequest(sr)
		if err != nil {
			done <- err
			return
		}
		if req.Hello == nil || req.Hello.Window != 4<<20 {
			done <- errors.New("bad hello")
			return
		}
		done <- frame.Write(s, Welcome{ID: id, Secret: secret, Window: 1 << 20}.Frame())
	}()
	g, err := ReadGreeting(cr)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ClientHello(c, cr, Hello{Version: Version, Window: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if w.ID != id || w.Secret != secret || w.Window != 1<<20 || g.Nonce != nonce {
		t.Fatal("welcome mismatch")
	}

	// Resume with a valid proof.
	nonce2, _ := NewNonce()
	go func() {
		if err := frame.Write(s, Greeting{Version: Version, Nonce: nonce2}.Frame()); err != nil {
			done <- err
			return
		}
		req, err := ReadRequest(sr)
		if err != nil {
			done <- err
			return
		}
		if req.Resume == nil || !VerifyMAC(secret, nonce2, *req.Resume) || req.Resume.RecvNext != 777 {
			done <- errors.New("bad resume")
			return
		}
		done <- frame.Write(s, ResumeAccept{RecvNext: 555}.Frame())
	}()
	g2, err := ReadGreeting(cr)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := ClientResume(c, cr, g2, id, secret, 777)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if acc.RecvNext != 555 {
		t.Fatalf("recvNext %d", acc.RecvNext)
	}
}

func TestHelloCredentialEncoding(t *testing.T) {
	h := Hello{Version: Version, Window: 4 << 20, Credential: []byte("opaque-token")}
	parsed, err := parseHello(h.Frame())
	if err != nil || parsed.Window != h.Window || !bytes.Equal(parsed.Credential, h.Credential) {
		t.Fatalf("parsed HELLO = %+v, %v", parsed, err)
	}
	if _, err := parseHello(Hello{Version: Version, Window: 4 << 20, Credential: bytes.Repeat([]byte("x"), 257)}.Frame()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("oversized credential = %v", err)
	}
}

func TestReplayedProofFails(t *testing.T) {
	id, secret, _ := NewCredentials()
	n1, _ := NewNonce()
	n2, _ := NewNonce()
	req := ResumeRequest{Version: Version, ID: id, RecvNext: 10}
	req.MAC = ComputeMAC(secret, n1, id, 10)
	if !VerifyMAC(secret, n1, req) {
		t.Fatal("valid proof rejected")
	}
	if VerifyMAC(secret, n2, req) {
		t.Fatal("proof accepted under a different nonce")
	}
	req.RecvNext = 11
	if VerifyMAC(secret, n1, req) {
		t.Fatal("proof accepted for a different offset")
	}
	var other Secret
	req.RecvNext = 10
	if VerifyMAC(other, n1, req) {
		t.Fatal("proof accepted under a different secret")
	}
}

func TestRejectIsReported(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() {
		frame.NewReader(s).Read()
		frame.Write(s, RejectFrame(ReasonDenied))
	}()
	_, err := ClientResume(c, frame.NewReader(c), Greeting{}, ID{}, Secret{}, 0)
	var rej *RejectError
	if !errors.As(err, &rej) || rej.Reason != ReasonDenied {
		t.Fatalf("want denied, got %v", err)
	}
}

func TestMalformed(t *testing.T) {
	bad := []frame.Frame{
		{Type: frame.TypeHello, Payload: []byte{Version}},
		{Type: frame.TypeHello, Payload: []byte{Version, 0x80}},
		{Type: frame.TypeResume, Payload: make([]byte, 10)},
		{Type: frame.TypeData},
		{Type: frame.TypeHello, Flags: frame.FlagServer, Payload: []byte{Version, 1}},
	}
	for i, fr := range bad {
		c, s := net.Pipe()
		go frame.Write(c, fr)
		if _, err := ReadRequest(frame.NewReader(s)); err == nil {
			t.Fatalf("case %d accepted", i)
		}
		c.Close()
		s.Close()
	}
}

func TestHelloIdleExtension(t *testing.T) {
	idle := &Idle{After: 10 * time.Second, Ping: 5 * time.Second, Dead: 15 * time.Second}
	for _, credential := range [][]byte{nil, []byte("opaque-token-123")} {
		h := Hello{Version: Version, Window: 4 << 20, Credential: credential, Idle: idle}
		parsed, err := parseHello(h.Frame())
		if err != nil || !parsed.Extended() || parsed.Idle == nil || *parsed.Idle != *idle || !bytes.Equal(parsed.Credential, credential) {
			t.Fatalf("credential %q: parsed %+v %v", credential, parsed, err)
		}
	}
	// The pre-extension format is unchanged and not extended.
	plain, err := parseHello(Hello{Version: Version, Window: 1 << 20, Credential: []byte("opaque-token")}.Frame())
	if err != nil || plain.Extended() || plain.Idle != nil {
		t.Fatalf("plain HELLO %+v %v", plain, err)
	}
	if got := (Hello{Version: Version, Window: 1 << 20}).Frame().Payload; len(got) != 1+3 {
		t.Fatalf("HELLO without credential or extensions grew: % x", got)
	}
	// credLen 0 with nothing after it is still malformed.
	if _, err := parseHello(frame.Frame{Type: frame.TypeHello, Payload: []byte{Version, 1, 0}}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty credential without extensions = %v", err)
	}
	// Unknown extensions are skipped; an out-of-range profile is ignored.
	unknown := append([]byte{Version, 1, 0}, 9, 2, 0xAA, 0xBB)
	if h, err := parseHello(frame.Frame{Type: frame.TypeHello, Payload: unknown}); err != nil || h.Idle != nil || !h.Extended() {
		t.Fatalf("unknown extension: %+v %v", h, err)
	}
	tooFast := Hello{Version: Version, Window: 1, Idle: &Idle{After: 10 * time.Second, Ping: 100 * time.Millisecond, Dead: time.Second}}
	if h, err := parseHello(tooFast.Frame()); err != nil || h.Idle != nil {
		t.Fatalf("out-of-range profile: %+v %v", h, err)
	}
	// A truncated record is malformed.
	if _, err := parseHello(frame.Frame{Type: frame.TypeHello, Payload: []byte{Version, 1, 0, 1, 5, 1}}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("truncated extension = %v", err)
	}
}

func TestWelcomeIdleExtension(t *testing.T) {
	idle := &Idle{After: 10 * time.Second, Ping: 5 * time.Second, Dead: 15 * time.Second}
	w := Welcome{Window: 2 << 20, Idle: idle, Extended: true}
	parsed, err := parseWelcome(w.Frame())
	if err != nil || parsed.Idle == nil || *parsed.Idle != *idle || parsed.Window != w.Window {
		t.Fatalf("parsed WELCOME %+v %v", parsed, err)
	}
	// Clients that sent no extensions get the short WELCOME, even if a
	// profile was set by mistake.
	short := Welcome{Window: 2 << 20, Idle: idle}.Frame()
	if len(short.Payload) != len(Welcome{Window: 2 << 20}.Frame().Payload) {
		t.Fatalf("WELCOME for a plain HELLO carries extensions: %d bytes", len(short.Payload))
	}
	// Extended HELLO, profile refused: an extended WELCOME without records.
	refused, err := parseWelcome(Welcome{Window: 2 << 20, Extended: true}.Frame())
	if err != nil || refused.Idle != nil {
		t.Fatalf("refused profile %+v %v", refused, err)
	}
}
