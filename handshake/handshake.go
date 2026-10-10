// Package handshake implements the CSL session handshake.
//
// The server speaks first on every new carrier:
//
//	S -> C  HELLO  [FlagServer]            version | nonce(32)
//
// A new session:
//
//	C -> S  HELLO                          version | window(uvarint)
//	S -> C  HELLO  [FlagServer|FlagAccept] session id(16) | secret(32) | window(uvarint)
//
// Resuming an existing session on a new carrier:
//
//	C -> S  RESUME                         version | session id(16) | recvNext(uvarint) | mac(32)
//	S -> C  RESUME [FlagServer|FlagAccept] recvNext(uvarint)
//
// mac = HMAC-SHA256(secret, "colitu-csl/1 resume" | nonce | id | uvarint(recvNext)).
// The nonce is fresh for every carrier, so a recorded RESUME cannot be replayed.
// Any refusal is a CLOSE frame whose payload starts with a Reason byte.
//
// The secret travels inside the encrypted carrier; server authenticity is
// provided by the carrier (for example Reality), not by CSL.
package handshake

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/colitu/csl/frame"
)

// Version is the protocol version spoken by this implementation.
const Version = 1

const (
	IDSize     = 16
	SecretSize = 32
	NonceSize  = 32
	MACSize    = sha256.Size
)

const macLabel = "colitu-csl/1 resume"

// ID identifies a session.
type ID [IDSize]byte

func (id ID) String() string { return hex.EncodeToString(id[:4]) }

// Secret authenticates resume requests for one session.
type Secret [SecretSize]byte

// Nonce is the per-carrier server challenge.
type Nonce [NonceSize]byte

// Reason explains why a peer closed a carrier or a session.
type Reason uint8

const (
	ReasonNormal   Reason = 0
	ReasonVersion  Reason = 1 // unsupported protocol version
	ReasonDenied   Reason = 2 // unknown session or bad proof
	ReasonBusy     Reason = 3 // server is at its session limit
	ReasonProtocol Reason = 4 // malformed or unexpected frame
	ReasonExpired  Reason = 5 // session lingered too long without a carrier
)

func (r Reason) String() string {
	switch r {
	case ReasonNormal:
		return "normal"
	case ReasonVersion:
		return "version"
	case ReasonDenied:
		return "denied"
	case ReasonBusy:
		return "busy"
	case ReasonProtocol:
		return "protocol"
	case ReasonExpired:
		return "expired"
	}
	return fmt.Sprintf("reason(%d)", uint8(r))
}

// RejectError is returned when the peer refuses the handshake.
type RejectError struct{ Reason Reason }

func (e *RejectError) Error() string { return "handshake: rejected: " + e.Reason.String() }

var (
	ErrMalformed  = errors.New("handshake: malformed message")
	ErrUnexpected = errors.New("handshake: unexpected frame")
	ErrVersion    = errors.New("handshake: unsupported version")
)

// Greeting is the first frame on every carrier, sent by the server.
type Greeting struct {
	Version uint8
	Nonce   Nonce
}

// Hello asks the server for a new session.
type Hello struct {
	Version    uint8
	Window     uint64 // receive window the client advertises
	Credential []byte // optional opaque identity credential, at most 256 bytes
}

// Welcome creates a new session.
type Welcome struct {
	ID     ID
	Secret Secret
	Window uint64 // receive window the server advertises
}

// ResumeRequest re-attaches an existing session to a new carrier.
type ResumeRequest struct {
	Version  uint8
	ID       ID
	RecvNext uint64 // next stream offset the client expects
	MAC      [MACSize]byte
}

// ResumeAccept confirms a resume.
type ResumeAccept struct {
	RecvNext uint64 // next stream offset the server expects
}

// NewNonce returns a random nonce.
func NewNonce() (Nonce, error) {
	var n Nonce
	_, err := rand.Read(n[:])
	return n, err
}

// NewCredentials returns a random session id and secret.
func NewCredentials() (ID, Secret, error) {
	var id ID
	var s Secret
	if _, err := rand.Read(id[:]); err != nil {
		return id, s, err
	}
	_, err := rand.Read(s[:])
	return id, s, err
}

// ComputeMAC returns the resume proof for the given carrier nonce.
func ComputeMAC(secret Secret, nonce Nonce, id ID, recvNext uint64) [MACSize]byte {
	m := hmac.New(sha256.New, secret[:])
	m.Write([]byte(macLabel))
	m.Write(nonce[:])
	m.Write(id[:])
	m.Write(binary.AppendUvarint(nil, recvNext))
	var out [MACSize]byte
	copy(out[:], m.Sum(nil))
	return out
}

// VerifyMAC checks a resume proof in constant time.
func VerifyMAC(secret Secret, nonce Nonce, req ResumeRequest) bool {
	want := ComputeMAC(secret, nonce, req.ID, req.RecvNext)
	return hmac.Equal(want[:], req.MAC[:])
}

// Frame encodings.

func (g Greeting) Frame() frame.Frame {
	p := make([]byte, 0, 1+NonceSize)
	p = append(p, g.Version)
	p = append(p, g.Nonce[:]...)
	return frame.Frame{Type: frame.TypeHello, Flags: frame.FlagServer, Payload: p}
}

func (h Hello) Frame() frame.Frame {
	p := append([]byte{h.Version}, binary.AppendUvarint(nil, h.Window)...)
	if len(h.Credential) > 0 {
		p = binary.AppendUvarint(p, uint64(len(h.Credential)))
		p = append(p, h.Credential...)
	}
	return frame.Frame{Type: frame.TypeHello, Payload: p}
}

func (w Welcome) Frame() frame.Frame {
	p := make([]byte, 0, IDSize+SecretSize+binary.MaxVarintLen64)
	p = append(p, w.ID[:]...)
	p = append(p, w.Secret[:]...)
	p = binary.AppendUvarint(p, w.Window)
	return frame.Frame{Type: frame.TypeHello, Flags: frame.FlagServer | frame.FlagAccept, Payload: p}
}

func (r ResumeRequest) Frame() frame.Frame {
	p := make([]byte, 0, 1+IDSize+binary.MaxVarintLen64+MACSize)
	p = append(p, r.Version)
	p = append(p, r.ID[:]...)
	p = binary.AppendUvarint(p, r.RecvNext)
	p = append(p, r.MAC[:]...)
	return frame.Frame{Type: frame.TypeResume, Payload: p}
}

func (a ResumeAccept) Frame() frame.Frame {
	return frame.Frame{Type: frame.TypeResume, Flags: frame.FlagServer | frame.FlagAccept, Payload: binary.AppendUvarint(nil, a.RecvNext)}
}

// RejectFrame returns the CLOSE frame used to refuse a handshake.
func RejectFrame(r Reason) frame.Frame {
	return frame.Frame{Type: frame.TypeClose, Payload: []byte{byte(r)}}
}

// Decoders.

func parseGreeting(fr frame.Frame) (Greeting, error) {
	var g Greeting
	if fr.Type != frame.TypeHello || fr.Flags != frame.FlagServer {
		return g, unexpected(fr)
	}
	if len(fr.Payload) != 1+NonceSize {
		return g, ErrMalformed
	}
	g.Version = fr.Payload[0]
	copy(g.Nonce[:], fr.Payload[1:])
	return g, nil
}

func parseHello(fr frame.Frame) (Hello, error) {
	var h Hello
	if len(fr.Payload) < 2 {
		return h, ErrMalformed
	}
	h.Version = fr.Payload[0]
	w, n := binary.Uvarint(fr.Payload[1:])
	if n <= 0 {
		return h, ErrMalformed
	}
	h.Window = w
	if tail := fr.Payload[1+n:]; len(tail) > 0 {
		length, m := binary.Uvarint(tail)
		if m <= 0 || length == 0 || length > 256 || uint64(len(tail[m:])) != length {
			return h, ErrMalformed
		}
		h.Credential = append([]byte(nil), tail[m:]...)
	}
	return h, nil
}

func parseWelcome(fr frame.Frame) (Welcome, error) {
	var w Welcome
	if fr.Type != frame.TypeHello || fr.Flags != frame.FlagServer|frame.FlagAccept {
		return w, unexpected(fr)
	}
	p := fr.Payload
	if len(p) < IDSize+SecretSize+1 {
		return w, ErrMalformed
	}
	copy(w.ID[:], p)
	copy(w.Secret[:], p[IDSize:])
	win, n := binary.Uvarint(p[IDSize+SecretSize:])
	if n <= 0 || IDSize+SecretSize+n != len(p) {
		return w, ErrMalformed
	}
	w.Window = win
	return w, nil
}

func parseResumeRequest(fr frame.Frame) (ResumeRequest, error) {
	var r ResumeRequest
	p := fr.Payload
	if len(p) < 1+IDSize+1+MACSize {
		return r, ErrMalformed
	}
	r.Version = p[0]
	copy(r.ID[:], p[1:])
	next, n := binary.Uvarint(p[1+IDSize:])
	if n <= 0 || 1+IDSize+n+MACSize != len(p) {
		return r, ErrMalformed
	}
	r.RecvNext = next
	copy(r.MAC[:], p[1+IDSize+n:])
	return r, nil
}

func parseResumeAccept(fr frame.Frame) (ResumeAccept, error) {
	var a ResumeAccept
	if fr.Type != frame.TypeResume || fr.Flags != frame.FlagServer|frame.FlagAccept {
		return a, unexpected(fr)
	}
	next, n := binary.Uvarint(fr.Payload)
	if n <= 0 || n != len(fr.Payload) {
		return a, ErrMalformed
	}
	a.RecvNext = next
	return a, nil
}

func unexpected(fr frame.Frame) error {
	if fr.Type == frame.TypeClose {
		r := ReasonProtocol
		if len(fr.Payload) > 0 {
			r = Reason(fr.Payload[0])
		}
		return &RejectError{Reason: r}
	}
	return fmt.Errorf("%w: %v flags=%d", ErrUnexpected, fr.Type, fr.Flags)
}

// Client side.

// ReadGreeting reads the server greeting that opens every carrier.
func ReadGreeting(r *frame.Reader) (Greeting, error) {
	fr, err := r.Read()
	if err != nil {
		return Greeting{}, err
	}
	g, err := parseGreeting(fr)
	if err != nil {
		return g, err
	}
	if g.Version != Version {
		return g, ErrVersion
	}
	return g, nil
}

// ClientHello asks for a new session.
func ClientHello(w io.Writer, r *frame.Reader, h Hello) (Welcome, error) {
	if len(h.Credential) > 256 {
		return Welcome{}, ErrMalformed
	}
	if err := frame.Write(w, h.Frame()); err != nil {
		return Welcome{}, err
	}
	fr, err := r.Read()
	if err != nil {
		return Welcome{}, err
	}
	return parseWelcome(fr)
}

// ClientResume re-attaches a session on the carrier that sent g.
func ClientResume(w io.Writer, r *frame.Reader, g Greeting, id ID, secret Secret, recvNext uint64) (ResumeAccept, error) {
	req := ResumeRequest{Version: Version, ID: id, RecvNext: recvNext}
	req.MAC = ComputeMAC(secret, g.Nonce, id, recvNext)
	if err := frame.Write(w, req.Frame()); err != nil {
		return ResumeAccept{}, err
	}
	fr, err := r.Read()
	if err != nil {
		return ResumeAccept{}, err
	}
	return parseResumeAccept(fr)
}

// Server side.

// Request is what a client asked for after the greeting: exactly one of
// Hello or Resume is set.
type Request struct {
	Hello  *Hello
	Resume *ResumeRequest
}

// ReadRequest reads the client's first frame.
func ReadRequest(r *frame.Reader) (Request, error) {
	fr, err := r.Read()
	if err != nil {
		return Request{}, err
	}
	return parseRequest(fr)
}

// ReadRequestWithKeepalive lets a parked carrier exchange PING/PONG before
// sending HELLO or RESUME. Pings cannot extend the absolute pending lifetime.
func ReadRequestWithKeepalive(r *frame.Reader, conn interface {
	io.Writer
	SetDeadline(time.Time) error
}, timeout time.Duration) (Request, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return Request{}, err
	}
	probeBytes := 0
	pings := 0
	for {
		fr, err := r.Read()
		if err != nil {
			return Request{}, err
		}
		if fr.Type == frame.TypePing && fr.Flags == 0 {
			pings++
			probeBytes += len(fr.Payload)
			if pings > 16 || probeBytes > 64<<10 {
				return Request{}, ErrMalformed
			}
			if err := frame.Write(conn, frame.Frame{Type: frame.TypePong, Seq: fr.Seq, Payload: fr.Payload}); err != nil {
				return Request{}, err
			}
			continue
		}
		return parseRequest(fr)
	}
}

func parseRequest(fr frame.Frame) (Request, error) {
	if fr.Flags != 0 {
		return Request{}, unexpected(fr)
	}
	switch fr.Type {
	case frame.TypeHello:
		h, err := parseHello(fr)
		if err != nil {
			return Request{}, err
		}
		if h.Version != Version {
			return Request{}, ErrVersion
		}
		return Request{Hello: &h}, nil
	case frame.TypeResume:
		req, err := parseResumeRequest(fr)
		if err != nil {
			return Request{}, err
		}
		if req.Version != Version {
			return Request{}, ErrVersion
		}
		return Request{Resume: &req}, nil
	}
	return Request{}, unexpected(fr)
}
