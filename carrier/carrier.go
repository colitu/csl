// Package carrier defines how CSL opens carrier connections.
//
// A carrier is any reliable byte stream that reaches the CSL server. In F1
// there are two kinds:
//
//	tcp://host:port                         direct TCP (lab and tests)
//	socks5://[user:pass@]proxy:port/host:port
//	                                        through a local Xray or sing-box
//	                                        SOCKS inbound; host:port is the CSL
//	                                        server address as seen from the node
//
// An optional #name fragment labels the carrier in logs and statistics,
// for example socks5://127.0.0.1:10808/127.0.0.1:9440#reality.
// SOCKS5 specs may set ?family=tcp or ?family=udp before the fragment. This
// describes the underlying tunnel and helps choose a different-family spare.
package carrier

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/colitu/csl/internal/socks5"
)

// Dialer opens one kind of carrier.
type Dialer interface {
	// Name labels the carrier (for example "reality" or "trojan").
	Name() string
	// Dial opens a new carrier connection.
	Dial(ctx context.Context) (net.Conn, error)
}

// Family identifies the underlying transport. SOCKS5 itself is TCP, but a
// SOCKS5 inbound may carry a UDP-based tunnel such as Hysteria2.
type Family string

const (
	FamilyUnknown Family = "unknown"
	FamilyTCP     Family = "tcp"
	FamilyUDP     Family = "udp"
)

// FamilyOf returns the transport family when a dialer exposes it.
func FamilyOf(d Dialer) Family {
	if f, ok := d.(interface{ Family() Family }); ok {
		return f.Family()
	}
	return FamilyUnknown
}

// TCP dials the CSL server directly.
type TCP struct {
	Label string
	Addr  string
}

func (t *TCP) Name() string   { return t.Label }
func (t *TCP) Family() Family { return FamilyTCP }

func (t *TCP) Dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", t.Addr)
}

// SOCKS5 dials the CSL server through a SOCKS5 proxy, normally the local
// inbound of an Xray or sing-box core that is connected to a node.
type SOCKS5 struct {
	Label           string
	Proxy           string
	Target          string
	Auth            *socks5.Auth
	TransportFamily Family
}

func (s *SOCKS5) Name() string   { return s.Label }
func (s *SOCKS5) Family() Family { return s.TransportFamily }

func (s *SOCKS5) Dial(ctx context.Context) (net.Conn, error) {
	return socks5.Dial(ctx, s.Proxy, s.Target, s.Auth)
}

// Parse builds a Dialer from a carrier spec (see the package comment).
func Parse(spec string) (Dialer, error) {
	u, err := url.Parse(spec)
	if err != nil {
		return nil, fmt.Errorf("carrier %q: %w", spec, err)
	}
	label := u.Fragment
	if label == "" {
		label = u.Scheme + "://" + u.Host
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return nil, fmt.Errorf("carrier %q: %w", spec, err)
	}
	switch u.Scheme {
	case "tcp":
		if u.Path != "" && u.Path != "/" {
			return nil, fmt.Errorf("carrier %q: tcp carriers take no path", spec)
		}
		return &TCP{Label: label, Addr: u.Host}, nil
	case "socks5":
		family := FamilyUnknown
		if raw := u.Query().Get("family"); raw != "" {
			family = Family(strings.ToLower(raw))
			if family != FamilyTCP && family != FamilyUDP {
				return nil, fmt.Errorf("carrier %q: family must be tcp or udp", spec)
			}
		} else if strings.Contains(strings.ToLower(label), "hysteria") || strings.Contains(strings.ToLower(label), "hy2") {
			family = FamilyUDP
		}
		target := strings.TrimPrefix(u.Path, "/")
		if _, _, err := net.SplitHostPort(target); err != nil {
			return nil, fmt.Errorf("carrier %q: missing target host:port after the proxy: %w", spec, err)
		}
		d := &SOCKS5{Label: label, Proxy: u.Host, Target: target, TransportFamily: family}
		if u.User != nil {
			pw, _ := u.User.Password()
			d.Auth = &socks5.Auth{User: u.User.Username(), Password: pw}
		}
		return d, nil
	}
	return nil, fmt.Errorf("carrier %q: unknown scheme %q", spec, u.Scheme)
}
