// Package dialguard dials outbound targets for the CSL server while refusing
// addresses that must never be reachable through the tunnel: loopback,
// private, link-local and other non-public ranges. A node runs management
// services on loopback, so without this check any user could reach them.
//
// The host name is resolved once and the checked IP is dialed directly, so a
// DNS answer cannot change between the check and the connection.
package dialguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// ErrForbidden is returned for targets in a blocked range.
var ErrForbidden = errors.New("dialguard: destination not allowed")

// Dialer dials TCP targets.
type Dialer struct {
	// AllowPrivate disables the address check (lab use only).
	AllowPrivate bool
	Resolver     *net.Resolver
	Dialer       net.Dialer
}

// Dial connects to hostport ("host:port").
func (d *Dialer) Dial(ctx context.Context, hostport string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		r := d.Resolver
		if r == nil {
			r = net.DefaultResolver
		}
		addrs, err = r.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	var lastErr error = fmt.Errorf("dialguard: no addresses for %q", host)
	for _, ip := range addrs {
		ip = ip.Unmap()
		if !d.AllowPrivate && !Allowed(ip) {
			lastErr = fmt.Errorf("%w: %s", ErrForbidden, ip)
			continue
		}
		conn, err := d.Dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

var blocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// Allowed reports whether ip is a public unicast address.
func Allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() {
		return false
	}
	for _, p := range blocked {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
