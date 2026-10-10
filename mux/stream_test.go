package mux

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

func muxPair(t *testing.T) (*smux.Session, *smux.Session) {
	t.Helper()
	a, b := net.Pipe()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	b.SetDeadline(time.Now().Add(3 * time.Second))
	server, err := Server(b)
	if err != nil {
		t.Fatal(err)
	}
	client, err := Client(a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close(); a.Close(); b.Close() })
	return client, server
}

func TestOpenTimesOutWhenServerDoesNotAnswer(t *testing.T) {
	client, server := muxPair(t)
	go func() {
		st, err := server.AcceptStream()
		if err == nil {
			defer st.Close()
			<-time.After(300 * time.Millisecond)
		}
	}()
	start := time.Now()
	st, err := OpenWithTimeout(client, "example.com:443", 50*time.Millisecond)
	if st != nil {
		st.Close()
	}
	if err == nil || time.Since(start) > 250*time.Millisecond {
		t.Fatalf("unresponsive server was not bounded: %v", err)
	}
}

func TestStreamLimits(t *testing.T) {
	tests := []struct {
		name       string
		perSession int
		total      int
	}{
		{name: "per session", perSession: 1, total: 2},
		{name: "global", perSession: 2, total: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := muxPair(t)
			upstream := make(chan net.Conn, 1)
			dial := func(context.Context, string) (net.Conn, error) {
				a, b := net.Pipe()
				upstream <- b
				return a, nil
			}
			go ServeWithLimits(server, dial, time.Second, tt.perSession, NewStreamLimiter(tt.total))
			first, err := Open(client, "example.com:443")
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			peer := <-upstream
			defer peer.Close()
			second, err := Open(client, "example.com:443")
			if second != nil {
				second.Close()
			}
			if err == nil {
				t.Fatal("second stream passed the limit")
			}
			var status *StatusError
			if errors.As(err, &status) && status.Code != StatusBusy {
				t.Fatalf("second stream: got status %d, want busy", status.Code)
			}
		})
	}
}

func TestSharedUserLimitAcrossSessions(t *testing.T) {
	firstClient, firstServer := muxPair(t)
	secondClient, secondServer := muxPair(t)
	upstream := make(chan net.Conn, 2)
	dial := func(context.Context, string) (net.Conn, error) {
		a, b := net.Pipe()
		upstream <- b
		return a, nil
	}
	global := NewStreamLimiter(4)
	user := NewStreamLimiter(1)
	go ServeWithLimitGroups(firstServer, dial, time.Second, 2, global, user)
	go ServeWithLimitGroups(secondServer, dial, time.Second, 2, global, user)
	first, err := Open(firstClient, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	peer := <-upstream
	defer peer.Close()
	second, err := Open(secondClient, "example.com:443")
	if second != nil {
		second.Close()
	}
	if err == nil {
		t.Fatal("second session exceeded shared user stream limit")
	}
}
