package socks5

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestClientServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for _, target := range []string{"example.com:443", "10.1.2.3:80", "[2001:db8::1]:8443"} {
		got := make(chan string, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			addr, err := ServerHandshake(c)
			if err != nil {
				got <- "error: " + err.Error()
				return
			}
			Reply(c, ReplySucceeded)
			got <- addr
			io.Copy(c, c) // echo
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err := Dial(ctx, ln.Addr().String(), target, nil)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if a := <-got; a != target {
			t.Fatalf("server saw %q, want %q", a, target)
		}
		conn.Write([]byte("hi"))
		buf := make([]byte, 2)
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hi" {
			t.Fatalf("echo: %q %v", buf, err)
		}
		conn.Close()
	}
}

func TestConnectRefused(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		ServerHandshake(c)
		Reply(c, ReplyConnectionRefused)
		c.Close()
	}()
	if _, err := Dial(context.Background(), ln.Addr().String(), "a.b:1", nil); err == nil {
		t.Fatal("refused connect reported success")
	}
}

func TestServerRequiresCredentials(t *testing.T) {
	want := &Auth{User: "csl", Password: "s3cret-local"}
	for _, tc := range []struct {
		name string
		auth *Auth
		ok   bool
	}{{"right", want, true}, {"wrong password", &Auth{User: "csl", Password: "nope"}, false}, {"no auth", nil, false}} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		got := make(chan error, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				got <- err
				return
			}
			defer c.Close()
			_, err = ServerHandshakeAuth(c, want)
			if err == nil {
				Reply(c, ReplySucceeded)
			}
			got <- err
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err := Dial(ctx, ln.Addr().String(), "example.com:443", tc.auth)
		cancel()
		serverErr := <-got
		ln.Close()
		if tc.ok && (err != nil || serverErr != nil) {
			t.Fatalf("%s: client %v, server %v", tc.name, err, serverErr)
		}
		if !tc.ok && (err == nil || serverErr == nil) {
			t.Fatalf("%s: accepted (client %v, server %v)", tc.name, err, serverErr)
		}
		if conn != nil {
			conn.Close()
		}
	}
}
