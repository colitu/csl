package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/colitu/csl/internal/dialguard"
	"github.com/colitu/csl/internal/socks5"
)

func TestIdentityStreamLimitsRelease(t *testing.T) {
	limits := newIdentityStreamLimits(2)
	first, releaseFirst := limits.acquire("alice")
	second, releaseSecond := limits.acquire("alice")
	other, releaseOther := limits.acquire("bob")
	if first != second || first == other {
		t.Fatal("user stream limits were not shared by identity")
	}
	releaseFirst()
	if limits.entries["alice"] == nil {
		t.Fatal("removed a limit while another session still uses it")
	}
	releaseSecond()
	releaseOther()
	if len(limits.entries) != 0 {
		t.Fatalf("retained %d unused user limits", len(limits.entries))
	}
}

func TestIdentityProviderReload(t *testing.T) {
	credential := []byte("a-long-device-credential")
	sum := sha256.Sum256(credential)
	key := hex.EncodeToString(sum[:])
	p := &identityProvider{entries: map[string]string{key: "alice"}}
	if user, err := p.authenticate(credential); err != nil || user != "alice" {
		t.Fatalf("initial identity = %q, %v", user, err)
	}
	p.update(nil, errors.New("invalid update"))
	if _, err := p.authenticate(credential); err == nil {
		t.Fatal("invalid update accepted a new session")
	}
	p.update(map[string]string{}, nil)
	if _, err := p.authenticate(credential); err == nil {
		t.Fatal("revoked credential accepted a new session")
	}
}

func TestIdentityFileValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identities.json")
	sum := sha256.Sum256([]byte("a-long-device-credential"))
	key := hex.EncodeToString(sum[:])
	if err := os.WriteFile(path, []byte(`{"`+key+`":"alice"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	identities, err := loadIdentities(path)
	if err != nil || identities[key] != "alice" {
		t.Fatalf("valid identities = %v, %v", identities, err)
	}
	if err := os.WriteFile(path, []byte(`{"bad hash":"alice"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentities(path); err == nil {
		t.Fatal("invalid identity hash accepted")
	}
}

func TestUpstreamOnlyLoopbackSocks(t *testing.T) {
	for raw, ok := range map[string]bool{
		"socks5://127.0.0.1:9441":      true,
		"socks5://[::1]:9441":          true,
		"socks5://10.0.0.1:9441":       false,
		"socks5://example.com:9441":    false,
		"http://127.0.0.1:9441":        false,
		"socks5://u:p@127.0.0.1:9441":  false,
		"socks5://127.0.0.1:0":         false,
		"socks5://127.0.0.1:9441/path": false,
	} {
		if _, err := parseUpstream(raw); (err == nil) != ok {
			t.Errorf("%s: err %v, want ok=%v", raw, err, ok)
		}
	}
}

func TestUpstreamRefusesPrivateTargetsBeforeDialing(t *testing.T) {
	dial := upstreamDialer("127.0.0.1:1", false)
	for _, target := range []string{"127.0.0.1:10085", "[::ffff:127.0.0.1]:10085", "10.1.2.3:80", "localhost:80", "a.localhost:80"} {
		if _, err := dial(context.Background(), target); !errors.Is(err, dialguard.ErrForbidden) {
			t.Errorf("%s: %v, want forbidden", target, err)
		}
	}
}

func TestUpstreamDialsThroughTheProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	seen := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		target, err := socks5.ServerHandshake(c)
		if err != nil {
			return
		}
		seen <- target
		socks5.Reply(c, socks5.ReplySucceeded)
		io.Copy(c, c)
	}()
	conn, err := upstreamDialer(ln.Addr().String(), false)(context.Background(), "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := <-seen; got != "example.com:443" {
		t.Fatalf("proxy saw %q", got)
	}
	conn.Write([]byte("ok"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("relay: %q %v", buf, err)
	}
}
