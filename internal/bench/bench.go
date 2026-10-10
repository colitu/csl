// Package bench provides the traffic source and the verifying download used
// by cslbench and the integration tests.
//
// A download asks the source for size bytes at a given rate; the source
// answers with a deterministic, position-dependent byte pattern, so any
// lost, duplicated or reordered byte is detected by the reader.
package bench

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Pattern fills p with the stream bytes starting at offset off.
func Pattern(off uint64, p []byte) {
	for i := range p {
		x := off + uint64(i)
		p[i] = byte(x ^ x>>8 ^ x>>16 ^ x>>24 ^ x>>32)
	}
}

// Source serves pattern downloads.
type Source struct{ ln net.Listener }

// StartSource listens on addr and serves downloads until closed.
func StartSource(addr string) (*Source, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Source{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
	return s, nil
}

// Addr returns the listening address.
func (s *Source) Addr() string { return s.ln.Addr().String() }

// Close stops the source.
func (s *Source) Close() error { return s.ln.Close() }

// request: size uint64 | rate uint64 (bytes per second, 0 = unlimited)
func serve(c net.Conn) {
	defer c.Close()
	var req [16]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	size := binary.BigEndian.Uint64(req[:8])
	rate := binary.BigEndian.Uint64(req[8:])
	buf := make([]byte, 32<<10)
	start := time.Now()
	for off := uint64(0); off < size; {
		n := int(min(uint64(len(buf)), size-off))
		Pattern(off, buf[:n])
		if _, err := c.Write(buf[:n]); err != nil {
			return
		}
		off += uint64(n)
		if rate > 0 {
			due := start.Add(time.Duration(float64(off) / float64(rate) * float64(time.Second)))
			if d := time.Until(due); d > 0 {
				time.Sleep(d)
			}
		}
	}
}

// Result describes one download.
type Result struct {
	Bytes    uint64        `json:"bytes"`
	Duration time.Duration `json:"duration_ns"`
	Mbps     float64       `json:"mbps"`
	MaxStall time.Duration `json:"max_stall_ns"` // longest gap between reads
	OK       bool          `json:"ok"`
	Error    string        `json:"error,omitempty"`
}

func (r Result) String() string {
	status := "OK"
	if !r.OK {
		status = "BROKEN: " + r.Error
	}
	return fmt.Sprintf("%d bytes in %v (%.1f Mbit/s), longest stall %v, %s",
		r.Bytes, r.Duration.Round(time.Millisecond), r.Mbps, r.MaxStall.Round(time.Millisecond), status)
}

// ErrCorrupt is reported when received bytes do not match the pattern.
var ErrCorrupt = errors.New("bench: corrupted stream")

// Download requests size bytes at rate over rw and verifies them. The
// caller sets any deadline on rw.
func Download(rw io.ReadWriter, size, rate uint64) Result {
	var req [16]byte
	binary.BigEndian.PutUint64(req[:8], size)
	binary.BigEndian.PutUint64(req[8:], rate)
	start := time.Now()
	res := Result{}
	if _, err := rw.Write(req[:]); err != nil {
		res.Error = err.Error()
		return res
	}
	buf := make([]byte, 64<<10)
	want := make([]byte, len(buf))
	last := start
	for res.Bytes < size {
		n, err := rw.Read(buf[:min(uint64(len(buf)), size-res.Bytes)])
		if n > 0 {
			now := time.Now()
			res.MaxStall = max(res.MaxStall, now.Sub(last))
			last = now
			Pattern(res.Bytes, want[:n])
			for i := range n {
				if buf[i] != want[i] {
					res.Error = fmt.Sprintf("%v at offset %d", ErrCorrupt, res.Bytes+uint64(i))
					res.Duration = time.Since(start)
					return res
				}
			}
			res.Bytes += uint64(n)
		}
		if err != nil && res.Bytes < size {
			res.Error = err.Error()
			res.Duration = time.Since(start)
			return res
		}
	}
	res.Duration = time.Since(start)
	res.Mbps = float64(res.Bytes) * 8 / res.Duration.Seconds() / 1e6
	res.OK = true
	return res
}
