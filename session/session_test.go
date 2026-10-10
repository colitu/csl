package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/colitu/csl/frame"
)

func TestRing(t *testing.T) {
	r := newRing(8)
	if r.Write([]byte("abcdef")) != 6 {
		t.Fatal("write")
	}
	r.Discard(4) // "ef"
	if r.Write([]byte("ghijklm")) != 6 {
		t.Fatal("wrapped write")
	}
	if got := string(r.AppendAt(nil, 1, 5)); got != "fghij" {
		t.Fatalf("AppendAt %q", got)
	}
	p := make([]byte, 10)
	if n := r.Read(p); string(p[:n]) != "efghijkl" {
		t.Fatalf("read %q", p[:n])
	}
	if r.Len() != 0 || r.Free() != 8 {
		t.Fatal("not empty")
	}
}

func TestRingGrowsAndReleasesStorage(t *testing.T) {
	r := newRing(DefaultWindow)
	if len(r.buf) != 0 || r.Free() != DefaultWindow {
		t.Fatal("new ring allocated its full window")
	}
	first := bytes.Repeat([]byte("a"), 1024)
	if r.Write(first) != len(first) || len(r.buf) > 16<<10 {
		t.Fatal("small write allocated too much storage")
	}
	second := bytes.Repeat([]byte("b"), 32<<10)
	if r.Write(second) != len(second) {
		t.Fatal("ring did not grow")
	}
	got := r.AppendAt(nil, 0, r.Len())
	if !bytes.Equal(got, append(first, second...)) {
		t.Fatal("ring contents changed while growing")
	}
	r.Discard(r.Len())
	if len(r.buf) < len(first)+len(second) {
		t.Fatal("ring shrank before it became idle")
	}
	r.TrimIdle(time.Now().Add(31*time.Second), 30*time.Second)
	if len(r.buf) > 16<<10 || r.Free() != DefaultWindow {
		t.Fatal("empty ring retained a large buffer")
	}
}

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ch <- c
	}()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return a, <-ch
}

// connect attaches a fresh carrier to both sessions, performing the offset
// exchange a real resume handshake would do.
func connect(t testing.TB, a, b *Session) (net.Conn, net.Conn) {
	t.Helper()
	aNext, err := a.PrepareResume()
	if err != nil {
		return nil, nil
	}
	bNext, err := b.PrepareResume()
	if err != nil {
		return nil, nil
	}
	ca, cb := tcpPair(t)
	if a.Attach(ca, frame.NewReader(ca), bNext, "test") != nil || b.Attach(cb, frame.NewReader(cb), aNext, "test") != nil {
		return nil, nil
	}
	return ca, cb
}

func pattern(off uint64, p []byte) {
	for i := range p {
		x := off + uint64(i)
		p[i] = byte(x ^ x>>8 ^ x>>16 ^ x>>24)
	}
}

// pump writes n pattern bytes to w and checks n pattern bytes read from r.
func pump(t testing.TB, w io.Writer, r io.Reader, n int) error {
	return pumpPaced(t, w, r, n, 0)
}

// pumpPaced is pump with a pause after every MiB written.
func pumpPaced(t testing.TB, w io.Writer, r io.Reader, n int, pause time.Duration) error {
	errc := make(chan error, 2)
	go func() {
		buf := make([]byte, 50_000)
		for off := 0; off < n; {
			c := min(len(buf), n-off)
			pattern(uint64(off), buf[:c])
			if _, err := w.Write(buf[:c]); err != nil {
				errc <- err
				return
			}
			if pause > 0 && (off+c)>>20 != off>>20 {
				time.Sleep(pause)
			}
			off += c
		}
		errc <- nil
	}()
	go func() {
		buf := make([]byte, 37_000)
		want := make([]byte, len(buf))
		for off := 0; off < n; {
			c, err := r.Read(buf[:min(len(buf), n-off)])
			if err != nil {
				errc <- err
				return
			}
			pattern(uint64(off), want[:c])
			if !bytes.Equal(buf[:c], want[:c]) {
				errc <- errors.New("corrupted stream")
				return
			}
			off += c
		}
		errc <- nil
	}()
	for range 2 {
		if err := <-errc; err != nil {
			return err
		}
	}
	return nil
}

func testConfig() Config {
	return Config{PingInterval: 50 * time.Millisecond, DeadAfter: 300 * time.Millisecond, Linger: 5 * time.Second}
}

func TestTransfer(t *testing.T) {
	a := New(testConfig(), DefaultWindow)
	b := New(testConfig(), DefaultWindow)
	connect(t, a, b)
	errc := make(chan error, 2)
	go func() { errc <- pump(t, a, b, 8<<20) }()
	go func() { errc <- pump(t, b, a, 8<<20) }()
	for range 2 {
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	}
	if st := a.Stats(); st.BytesSent != 8<<20 || st.BytesReceived != 8<<20 {
		t.Fatalf("stats %+v", st)
	}
}

// TestSurvivesCarrierKills kills the carrier every few milliseconds while
// streams flow in both directions, and checks that every byte arrives once
// and in order.
func TestSurvivesCarrierKills(t *testing.T) {
	lost := make(chan struct{}, 1)
	cfg := testConfig()
	cfg.OnCarrierLost = func(error) {
		select {
		case lost <- struct{}{}:
		default:
		}
	}
	a := New(cfg, DefaultWindow)
	b := New(testConfig(), DefaultWindow)

	var mu sync.Mutex
	var cur [2]net.Conn
	reconnect := func() {
		ca, cb := connect(t, a, b)
		mu.Lock()
		cur = [2]net.Conn{ca, cb}
		mu.Unlock()
	}
	reconnect()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // chaos: hard-close the active carrier
		defer wg.Done()
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				mu.Lock()
				if c, ok := cur[0].(*net.TCPConn); ok {
					c.SetLinger(0)
					c.Close()
				}
				mu.Unlock()
			}
		}
	}()
	go func() { // recovery: resume on a new carrier whenever A loses one
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-lost:
				reconnect()
			}
		}
	}()

	errc := make(chan error, 2)
	go func() { errc <- pumpPaced(t, a, b, 24<<20, 10*time.Millisecond) }()
	go func() { errc <- pumpPaced(t, b, a, 24<<20, 10*time.Millisecond) }()
	for range 2 {
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	if c := a.Stats().Carriers; c < 20 {
		t.Fatalf("only %d carriers used; chaos did not run", c)
	}
	t.Logf("carriers used: %d", a.Stats().Carriers)
}

func TestDeadCarrierDetected(t *testing.T) {
	lost := make(chan error, 1)
	cfg := testConfig()
	cfg.OnCarrierLost = func(err error) { lost <- err }
	a := New(cfg, DefaultWindow)
	ca, cb := tcpPair(t)
	defer cb.Close() // peer that never answers: a silent black hole
	a.Attach(ca, frame.NewReader(ca), 0, "silent")
	select {
	case err := <-lost:
		if !errors.Is(err, ErrCarrierTimeout) {
			t.Fatalf("want timeout, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dead carrier not detected")
	}
	if a.Stats().Attached {
		t.Fatal("still attached")
	}
}

func TestLingerExpires(t *testing.T) {
	cfg := testConfig()
	cfg.Linger = 100 * time.Millisecond
	a := New(cfg, DefaultWindow)
	select {
	case <-a.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("linger did not expire")
	}
	if _, err := a.Read(make([]byte, 1)); !errors.Is(err, ErrLingerExpired) {
		t.Fatalf("read after expiry: %v", err)
	}
	if _, err := a.Write([]byte{1}); !errors.Is(err, ErrLingerExpired) {
		t.Fatalf("write after expiry: %v", err)
	}
}

func TestGracefulClose(t *testing.T) {
	a := New(testConfig(), DefaultWindow)
	b := New(testConfig(), DefaultWindow)
	connect(t, a, b)
	msg := bytes.Repeat([]byte("colitu"), 200_000)
	if _, err := a.Write(msg); err != nil {
		t.Fatal(err)
	}
	a.Close()
	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %d bytes, want %d", len(got), len(msg))
	}
	for _, s := range []*Session{a, b} {
		select {
		case <-s.Done():
			if s.Err() != nil {
				t.Fatalf("close error: %v", s.Err())
			}
		case <-time.After(2 * time.Second):
			t.Fatal("session did not finish")
		}
	}
	if _, err := b.Write([]byte("x")); err == nil {
		t.Fatal("write after peer close succeeded")
	}
}

func TestResumeMismatch(t *testing.T) {
	a := New(testConfig(), DefaultWindow)
	a.Write([]byte("hello"))
	ca, cb := tcpPair(t)
	defer cb.Close()
	if err := a.Attach(ca, frame.NewReader(ca), 6, "bad"); !errors.Is(err, ErrResumeMismatch) {
		t.Fatalf("want mismatch, got %v", err)
	}
}

func TestWindowViolation(t *testing.T) {
	a := New(Config{Window: MinWindow, PingInterval: time.Second, DeadAfter: 5 * time.Second}, DefaultWindow)
	ca, cb := tcpPair(t)
	defer cb.Close()
	a.Attach(ca, frame.NewReader(ca), 0, "evil")
	chunk := make([]byte, frame.MaxPayload)
	for off := uint64(0); off <= MinWindow; off += uint64(len(chunk)) {
		frame.Write(cb, frame.Frame{Type: frame.TypeData, Seq: off, Payload: chunk})
	}
	select {
	case <-a.Done():
		if !errors.Is(a.Err(), ErrProtocol) {
			t.Fatalf("want protocol error, got %v", a.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("window violation not detected")
	}
}

func TestDatagram(t *testing.T) {
	a := New(testConfig(), DefaultWindow)
	b := New(testConfig(), DefaultWindow)
	connect(t, a, b)
	if err := a.SendDatagram([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d, err := b.ReceiveDatagram(ctx)
	if err != nil || string(d) != "ping" {
		t.Fatalf("got %q, %v", d, err)
	}
	if err := a.SendDatagram(make([]byte, frame.MaxPayload+1)); !errors.Is(err, ErrDgramTooLarge) {
		t.Fatalf("oversized datagram: %v", err)
	}
}
