package frame

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	frames := []Frame{
		{Type: TypeHello, Payload: []byte{1}},
		{Type: TypeData, Seq: 1 << 40, Payload: bytes.Repeat([]byte{7}, MaxPayload)},
		{Type: TypeAck, Seq: 12345},
		{Type: TypeResume, Flags: FlagServer | FlagAccept, Payload: []byte("x")},
		{Type: TypeClose, Seq: ^uint64(0), Payload: []byte{0}},
	}
	var buf bytes.Buffer
	for _, fr := range frames {
		if err := Write(&buf, fr); err != nil {
			t.Fatal(err)
		}
	}
	raw := append([]byte(nil), buf.Bytes()...)

	r := NewReader(&buf)
	for i, want := range frames {
		got, err := r.Read()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if got.Type != want.Type || got.Flags != want.Flags || got.Seq != want.Seq || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("frame %d mismatch: got %v/%v/%d/%d bytes", i, got.Type, got.Flags, got.Seq, len(got.Payload))
		}
	}
	if _, err := r.Read(); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}

	// Parse must agree with Reader.
	for i, want := range frames {
		got, n, err := Parse(raw)
		if err != nil {
			t.Fatalf("parse %d: %v", i, err)
		}
		if got.Seq != want.Seq || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("parse %d mismatch", i)
		}
		raw = raw[n:]
	}
}

func TestRejects(t *testing.T) {
	if _, err := Append(nil, Frame{Type: TypeData, Payload: make([]byte, MaxPayload+1)}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized payload: %v", err)
	}
	if _, err := Append(nil, Frame{}); !errors.Is(err, ErrInvalidType) {
		t.Fatalf("zero type: %v", err)
	}
	// A header that announces a payload above the limit.
	bad := AppendHeader(nil, TypeData, 0, 0, MaxPayload+1)
	if _, err := NewReader(bytes.NewReader(bad)).Read(); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("reader oversized: %v", err)
	}
	if _, _, err := Parse(bad); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("parse oversized: %v", err)
	}
	// A truncated frame.
	ok, _ := Append(nil, Frame{Type: TypeData, Payload: []byte("hello")})
	if _, err := NewReader(bytes.NewReader(ok[:len(ok)-1])).Read(); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated: %v", err)
	}
	if _, _, err := Parse(ok[:len(ok)-1]); !errors.Is(err, ErrShort) {
		t.Fatalf("parse truncated: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	seed, _ := Append(nil, Frame{Type: TypeData, Seq: 99, Payload: []byte("seed")})
	f.Add(seed)
	f.Add([]byte{3, 0, 0x80})
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, n, err := Parse(b)
		if err != nil {
			return
		}
		if n > len(b) || len(fr.Payload) > MaxPayload {
			t.Fatalf("bad parse result n=%d payload=%d", n, len(fr.Payload))
		}
		// Re-encoding a parsed frame and parsing it again must be stable.
		again, err := Append(nil, fr)
		if err != nil {
			t.Fatal(err)
		}
		fr2, _, err := Parse(again)
		if err != nil || fr2.Seq != fr.Seq || fr2.Type != fr.Type || !bytes.Equal(fr2.Payload, fr.Payload) {
			t.Fatalf("unstable round trip: %v", err)
		}
		// The streaming reader must accept the same bytes.
		fr3, err := NewReader(bytes.NewReader(b[:n])).Read()
		if err != nil || fr3.Seq != fr.Seq || !bytes.Equal(fr3.Payload, fr.Payload) {
			t.Fatalf("reader disagrees with Parse: %v", err)
		}
	})
}
