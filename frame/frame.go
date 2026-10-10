// Package frame implements the CSL wire framing.
//
// Every frame on a carrier has the same layout:
//
//	type    uint8
//	flags   uint8
//	seq     uvarint   (meaning depends on type)
//	length  uvarint   (payload length, at most MaxPayload)
//	payload [length]byte
//
// The framing carries no cryptography of its own: CSL always runs inside an
// already encrypted carrier (VLESS-Reality, Trojan, Shadowsocks, ...).
package frame

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Type identifies what a frame carries.
type Type uint8

const (
	TypeHello  Type = 1 // handshake: greeting, new session request, welcome
	TypeResume Type = 2 // handshake: resume request and acceptance
	TypeData   Type = 3 // seq = stream offset of the first payload byte
	TypeAck    Type = 4 // seq = bytes consumed by the receiving application
	TypeDgram  Type = 5 // unreliable datagram, never retransmitted
	TypePing   Type = 6 // seq = ping id
	TypePong   Type = 7 // seq = echoed ping id
	TypePad    Type = 8 // ignored, used for traffic shaping
	TypeClose  Type = 9 // seq = final stream offset, payload = reason
)

func (t Type) String() string {
	switch t {
	case TypeHello:
		return "HELLO"
	case TypeResume:
		return "RESUME"
	case TypeData:
		return "DATA"
	case TypeAck:
		return "ACK"
	case TypeDgram:
		return "DGRAM"
	case TypePing:
		return "PING"
	case TypePong:
		return "PONG"
	case TypePad:
		return "PAD"
	case TypeClose:
		return "CLOSE"
	}
	return fmt.Sprintf("TYPE(%d)", uint8(t))
}

// Flags modify the meaning of a frame. Only handshake frames use them today.
type Flags uint8

const (
	FlagServer Flags = 1 << 0 // frame was sent by the server
	FlagAccept Flags = 1 << 1 // handshake request was accepted
)

const (
	// MaxPayload is the largest payload a single frame may carry.
	MaxPayload = 16 << 10
	// MaxHeader is the largest possible encoded header.
	MaxHeader = 2 + 2*binary.MaxVarintLen64
	// MaxFrame is the largest possible encoded frame.
	MaxFrame = MaxHeader + MaxPayload
)

var (
	ErrTooLarge    = errors.New("frame: payload too large")
	ErrInvalidType = errors.New("frame: invalid type")
	ErrShort       = errors.New("frame: short buffer")
	errBadVarint   = errors.New("frame: bad varint")
)

// Frame is one decoded frame. Payload may alias a reader's internal buffer.
type Frame struct {
	Type    Type
	Flags   Flags
	Seq     uint64
	Payload []byte
}

// AppendHeader appends a frame header for a payload of n bytes to b.
func AppendHeader(b []byte, t Type, f Flags, seq uint64, n int) []byte {
	b = append(b, byte(t), byte(f))
	b = binary.AppendUvarint(b, seq)
	return binary.AppendUvarint(b, uint64(n))
}

// Append appends the encoded frame to b.
func Append(b []byte, fr Frame) ([]byte, error) {
	if len(fr.Payload) > MaxPayload {
		return b, ErrTooLarge
	}
	if fr.Type == 0 {
		return b, ErrInvalidType
	}
	b = AppendHeader(b, fr.Type, fr.Flags, fr.Seq, len(fr.Payload))
	return append(b, fr.Payload...), nil
}

// Write encodes fr and writes it to w in a single Write call.
func Write(w io.Writer, fr Frame) error {
	var stack [256]byte
	b, err := Append(stack[:0], fr)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// Parse decodes one frame from the front of b and returns it with the number
// of bytes consumed. It returns ErrShort when b holds an incomplete frame.
// The returned payload aliases b.
func Parse(b []byte) (Frame, int, error) {
	if len(b) < 2 {
		return Frame{}, 0, ErrShort
	}
	fr := Frame{Type: Type(b[0]), Flags: Flags(b[1])}
	if fr.Type == 0 {
		return Frame{}, 0, ErrInvalidType
	}
	off := 2
	seq, n := binary.Uvarint(b[off:])
	if n == 0 {
		return Frame{}, 0, ErrShort
	}
	if n < 0 {
		return Frame{}, 0, errBadVarint
	}
	off += n
	length, n := binary.Uvarint(b[off:])
	if n == 0 {
		return Frame{}, 0, ErrShort
	}
	if n < 0 {
		return Frame{}, 0, errBadVarint
	}
	off += n
	if length > MaxPayload {
		return Frame{}, 0, ErrTooLarge
	}
	if uint64(len(b)-off) < length {
		return Frame{}, 0, ErrShort
	}
	fr.Seq = seq
	fr.Payload = b[off : off+int(length)]
	return fr, off + int(length), nil
}

// Reader reads frames from a byte stream.
type Reader struct {
	r   *bufio.Reader
	buf []byte
}

// NewReader returns a Reader that buffers r.
func NewReader(r io.Reader) *Reader {
	return &Reader{r: bufio.NewReaderSize(r, 64<<10), buf: make([]byte, MaxPayload)}
}

// Read returns the next frame. The payload is only valid until the next call.
func (r *Reader) Read() (Frame, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r.r, hdr[:]); err != nil {
		return Frame{}, err
	}
	fr := Frame{Type: Type(hdr[0]), Flags: Flags(hdr[1])}
	if fr.Type == 0 {
		return Frame{}, ErrInvalidType
	}
	seq, err := binary.ReadUvarint(r.r)
	if err != nil {
		return Frame{}, unexpected(err)
	}
	length, err := binary.ReadUvarint(r.r)
	if err != nil {
		return Frame{}, unexpected(err)
	}
	if length > MaxPayload {
		return Frame{}, ErrTooLarge
	}
	fr.Seq = seq
	fr.Payload = r.buf[:length]
	if _, err := io.ReadFull(r.r, fr.Payload); err != nil {
		return Frame{}, unexpected(err)
	}
	return fr, nil
}

func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
