package handshake

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/colitu/csl/frame"
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
