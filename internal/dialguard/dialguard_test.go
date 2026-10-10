package dialguard

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestAllowed(t *testing.T) {
	for addr, want := range map[string]bool{
		"1.1.1.1":          true,
		"2606:4700::1111":  true,
		"127.0.0.1":        false,
		"10.0.0.5":         false,
		"172.16.3.4":       false,
		"192.168.1.1":      false,
		"169.254.169.254":  false, // cloud metadata
		"100.64.1.1":       false,
		"0.0.0.0":          false,
		"::1":              false,
		"fe80::1":          false,
		"fd00::1":          false,
		"::ffff:127.0.0.1": false,
		"224.0.0.1":        false,
	} {
		if got := Allowed(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Allowed(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestDialRefusesLoopback(t *testing.T) {
	var d Dialer
	for _, target := range []string{"127.0.0.1:22", "localhost:22", "[::1]:22"} {
		if _, err := d.Dial(context.Background(), target); !errors.Is(err, ErrForbidden) {
			t.Errorf("%s: want ErrForbidden, got %v", target, err)
		}
	}
}
