// Package mux multiplexes many TCP streams over one CSL session using smux.
//
// Each stream starts with a small request that names its destination, and
// the server answers with one status byte once it has dialed it:
//
//	C -> S  len(uint8) | "host:port"
//	S -> C  status(uint8)                 0 = connected
package mux

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/xtaci/smux"
)

// Config returns the smux configuration used by CSL. smux keepalives are
// disabled: the session layer does its own liveness checks, and a smux
// keepalive would tear the session down while it waits for a resume.
func Config() *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2
	c.KeepAliveDisabled = true
	c.MaxFrameSize = 32 << 10
	c.MaxReceiveBuffer = 4 << 20
	c.MaxStreamBuffer = 1 << 20
	return c
}

// Client starts the client side of the multiplexer on conn.
func Client(conn io.ReadWriteCloser) (*smux.Session, error) { return smux.Client(conn, Config()) }

// Server starts the server side of the multiplexer on conn.
func Server(conn io.ReadWriteCloser) (*smux.Session, error) { return smux.Server(conn, Config()) }

// Status codes answered by the server.
const (
	StatusOK          byte = 0
	StatusFailed      byte = 1
	StatusForbidden   byte = 2
	StatusUnreachable byte = 3
	StatusBadRequest  byte = 4
	StatusBusy        byte = 5
)

// StatusError reports a failed stream request.
type StatusError struct{ Code byte }

func (e *StatusError) Error() string {
	switch e.Code {
	case StatusForbidden:
		return "mux: destination forbidden"
	case StatusUnreachable:
		return "mux: destination unreachable"
	case StatusBadRequest:
		return "mux: bad request"
	case StatusBusy:
		return "mux: stream limit reached"
	}
	return fmt.Sprintf("mux: connect failed (status %d)", e.Code)
}

// WriteRequest sends the destination of a new stream.
func WriteRequest(w io.Writer, target string) error {
	if _, _, err := net.SplitHostPort(target); err != nil {
		return err
	}
	if len(target) > 255 {
		return errors.New("mux: target too long")
	}
	_, err := w.Write(append([]byte{byte(len(target))}, target...))
	return err
}

// ReadRequest reads the destination of a new stream.
func ReadRequest(r io.Reader) (string, error) {
	var l [1]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return "", err
	}
	b := make([]byte, l[0])
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	target := string(b)
	if _, _, err := net.SplitHostPort(target); err != nil {
		return "", err
	}
	return target, nil
}

// WriteStatus answers a stream request.
func WriteStatus(w io.Writer, code byte) error {
	_, err := w.Write([]byte{code})
	return err
}

// ReadStatus waits for the server's answer to a stream request.
func ReadStatus(r io.Reader) error {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	if b[0] != StatusOK {
		return &StatusError{Code: b[0]}
	}
	return nil
}
