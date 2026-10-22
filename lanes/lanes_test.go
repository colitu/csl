package lanes

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/colitu/csl/carrier"
	"github.com/colitu/csl/frame"
	"github.com/colitu/csl/handshake"
	"github.com/colitu/csl/server"
)

type delayedDialer struct {
	name   string
	family carrier.Family
	delay  time.Duration
	addr   string
}

func TestInitialSelectionFallsBackForLegacyServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(server.Config{})
	defer srv.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		nonce, err := handshake.NewNonce()
		if err == nil {
			_ = frame.Write(conn, handshake.Greeting{Version: handshake.Version, Nonce: nonce}.Frame())
			_, _ = frame.NewReader(conn).Read()
			_ = frame.Write(conn, handshake.RejectFrame(handshake.ReasonProtocol))
		}
		_ = conn.Close()
		_ = srv.Serve(ln)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := Dial(ctx, Config{Carriers: []carrier.Dialer{&carrier.TCP{Label: "legacy", Addr: ln.Addr().String()}}, NoSpare: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.Active(); got != "legacy" {
		t.Fatalf("active = %q, want legacy", got)
	}
}

func (d *delayedDialer) Name() string           { return d.name }
func (d *delayedDialer) Family() carrier.Family { return d.family }
func (d *delayedDialer) Dial(ctx context.Context) (net.Conn, error) {
	t := time.NewTimer(d.delay)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.addr)
}

func TestInitialSelectionAndDifferentFamilySpare(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(server.Config{})
	go srv.Serve(ln)
	defer srv.Close()
	addr := ln.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := Dial(ctx, Config{
		SelectionWindow: 300 * time.Millisecond,
		Carriers: []carrier.Dialer{
			&delayedDialer{name: "slow-tcp", family: carrier.FamilyTCP, delay: 80 * time.Millisecond, addr: addr},
			&delayedDialer{name: "fast-udp", family: carrier.FamilyUDP, delay: 10 * time.Millisecond, addr: addr},
			&delayedDialer{name: "backup-tcp", family: carrier.FamilyTCP, delay: 20 * time.Millisecond, addr: addr},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.Active(); got != "fast-udp" {
		t.Fatalf("active = %q, want fast-udp", got)
	}
	c.mu.Lock()
	spare := c.spare
	c.mu.Unlock()
	if spare == nil || spare.d.Name() != "backup-tcp" {
		t.Fatalf("spare = %v, want backup-tcp", spare)
	}
	c.mu.Lock()
	spare.lastCheck = time.Now().Add(-time.Minute)
	c.mu.Unlock()
	c.checkSpare()
	c.mu.Lock()
	stillReady := c.spare == spare && time.Since(spare.lastCheck) < time.Second
	c.mu.Unlock()
	if !stillReady {
		t.Fatal("parked spare did not answer PING")
	}
}

func TestInitialSelectionRetriesUntilCarrierListens(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	srv := server.New(server.Config{})
	defer srv.Close()
	go func() {
		time.Sleep(700 * time.Millisecond)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return
		}
		_ = srv.Serve(ln)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, Config{Carriers: []carrier.Dialer{&carrier.TCP{Label: "late", Addr: addr}}, NoSpare: true})
	if err != nil {
		t.Fatalf("dial while carrier starts: %v", err)
	}
	defer c.Close()
	if got := c.Active(); got != "late" {
		t.Fatalf("active = %q, want late", got)
	}
}

func TestInitialSelectionGivesUpAtDeadline(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Dial(ctx, Config{Carriers: []carrier.Dialer{&carrier.TCP{Label: "dead", Addr: addr}}, NoSpare: true}); err == nil {
		t.Fatal("dial succeeded without a listener")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("gave up after %v", elapsed)
	}
}

func TestIdleProfileNegotiation(t *testing.T) {
	idle := &handshake.Idle{After: 10 * time.Second, Ping: 5 * time.Second, Dead: 15 * time.Second}
	for _, refuse := range []bool{false, true} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := server.New(server.Config{NoIdle: refuse})
		go srv.Serve(ln)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		c, err := Dial(ctx, Config{Carriers: []carrier.Dialer{&carrier.TCP{Label: "a", Addr: ln.Addr().String()}}, NoSpare: true, Idle: idle})
		cancel()
		if err != nil {
			t.Fatalf("refuse=%t: %v", refuse, err)
		}
		got := c.Idle()
		if refuse && got != nil || !refuse && (got == nil || *got != *idle) {
			t.Fatalf("refuse=%t: accepted profile %+v", refuse, got)
		}
		c.Close()
		srv.Close()
	}
}
