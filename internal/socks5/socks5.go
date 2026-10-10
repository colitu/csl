// Package socks5 implements the small part of SOCKS5 (RFC 1928, RFC 1929)
// CSL needs: a CONNECT-only server for local applications and a CONNECT
// client for dialing through Xray or sing-box inbounds.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const version = 5

// Reply codes.
const (
	ReplySucceeded          byte = 0
	ReplyGeneralFailure     byte = 1
	ReplyNotAllowed         byte = 2
	ReplyNetworkUnreachable byte = 3
	ReplyHostUnreachable    byte = 4
	ReplyConnectionRefused  byte = 5
	ReplyTTLExpired         byte = 6
	ReplyCommandUnsupported byte = 7
	ReplyAddressUnsupported byte = 8
)

const (
	cmdConnect = 1
	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4

	methodNoAuth       = 0
	methodUserPass     = 2
	methodNoAcceptable = 0xff
)

var ErrUnsupported = errors.New("socks5: unsupported request")

// ServerHandshake reads a CONNECT request from a local client (no
// authentication) and returns the requested "host:port". The caller must
// answer with Reply.
func ServerHandshake(rw io.ReadWriter) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(rw, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0] != version {
		return "", fmt.Errorf("socks5: bad version %d", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(rw, methods); err != nil {
		return "", err
	}
	ok := false
	for _, m := range methods {
		if m == methodNoAuth {
			ok = true
		}
	}
	if !ok {
		rw.Write([]byte{version, methodNoAcceptable})
		return "", ErrUnsupported
	}
	if _, err := rw.Write([]byte{version, methodNoAuth}); err != nil {
		return "", err
	}
	var req [3]byte
	if _, err := io.ReadFull(rw, req[:]); err != nil {
		return "", err
	}
	addr, err := readAddr(rw)
	if err != nil {
		return "", err
	}
	if req[0] != version || req[1] != cmdConnect {
		Reply(rw, ReplyCommandUnsupported)
		return "", ErrUnsupported
	}
	return addr, nil
}

// Reply sends a reply with an empty bound address.
func Reply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{version, code, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// Auth holds optional username/password credentials.
type Auth struct{ User, Password string }

// Dial connects to target ("host:port") through the SOCKS5 proxy at proxy.
func Dial(ctx context.Context, proxy, target string, auth *Auth) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	err = clientHandshake(conn, target, auth)
	if !stop() && err == nil {
		err = ctx.Err()
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(timeZero)
	return conn, nil
}

func clientHandshake(rw io.ReadWriter, target string, auth *Auth) error {
	method := byte(methodNoAuth)
	if auth != nil {
		method = methodUserPass
	}
	if _, err := rw.Write([]byte{version, 1, method}); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(rw, resp[:]); err != nil {
		return err
	}
	if resp[0] != version || resp[1] != method {
		return errors.New("socks5: proxy refused authentication method")
	}
	if auth != nil {
		if len(auth.User) > 255 || len(auth.Password) > 255 {
			return errors.New("socks5: credentials too long")
		}
		b := []byte{1, byte(len(auth.User))}
		b = append(b, auth.User...)
		b = append(b, byte(len(auth.Password)))
		b = append(b, auth.Password...)
		if _, err := rw.Write(b); err != nil {
			return err
		}
		if _, err := io.ReadFull(rw, resp[:]); err != nil {
			return err
		}
		if resp[1] != 0 {
			return errors.New("socks5: authentication failed")
		}
	}
	req := []byte{version, cmdConnect, 0}
	req, err := appendAddr(req, target)
	if err != nil {
		return err
	}
	if _, err := rw.Write(req); err != nil {
		return err
	}
	var rep [3]byte
	if _, err := io.ReadFull(rw, rep[:]); err != nil {
		return err
	}
	if _, err := readAddr(rw); err != nil {
		return err
	}
	if rep[1] != ReplySucceeded {
		return fmt.Errorf("socks5: connect failed with code %d", rep[1])
	}
	return nil
}

func appendAddr(b []byte, hostport string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("socks5: bad port %q", portStr)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b = append(append(b, atypIPv4), ip4...)
		} else {
			b = append(append(b, atypIPv6), ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("socks5: bad host name")
		}
		b = append(b, atypDomain, byte(len(host)))
		b = append(b, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

func readAddr(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", err
	}
	var host string
	switch atyp[0] {
	case atypIPv4, atypIPv6:
		n := net.IPv4len
		if atyp[0] == atypIPv6 {
			n = net.IPv6len
		}
		ip := make(net.IP, n)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", err
		}
		host = ip.String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		return "", ErrUnsupported
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}
