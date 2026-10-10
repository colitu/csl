// Package faultnet is a TCP proxy that injects the failures CSL must
// survive. It stands in for the censor's middlebox in tests and in the
// in-process lab (cslbench lab):
//
//   - KillAll: reset every connection (abrupt drop, RST)
//   - SetPaused: stop forwarding without closing anything (outage, black hole)
//   - SetFreezeAfter: freeze a connection for good after N downstream bytes,
//     like the "connection hangs after 15-20 KB" blocking reported in Russia
//   - SetRefuse: reset new connections immediately (blocked endpoint)
package faultnet

import (
	"io"
	"net"
	"sync"
)

// Proxy forwards TCP connections to a fixed target.
type Proxy struct {
	ln     net.Listener
	target string

	mu          sync.Mutex
	cond        *sync.Cond
	paused      bool
	refuse      bool
	freezeAfter int64
	closed      bool
	conns       map[*pconn]struct{}
	accepted    int
}

type pconn struct {
	client, server net.Conn
	down           int64 // bytes forwarded server -> client
	frozen         bool
	closed         bool
}

// Listen starts a proxy on addr that forwards to target.
func Listen(addr, target string) (*Proxy, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	p := &Proxy{ln: ln, target: target, conns: make(map[*pconn]struct{})}
	p.cond = sync.NewCond(&p.mu)
	go p.acceptLoop()
	return p, nil
}

// Addr returns the proxy's listening address.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// Accepted returns how many connections the proxy has accepted.
func (p *Proxy) Accepted() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accepted
}

// Conns returns the number of open connections.
func (p *Proxy) Conns() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns)
}

// KillAll resets every open connection.
func (p *Proxy) KillAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for c := range p.conns {
		p.killLocked(c)
	}
}

// SetPaused stops (true) or resumes (false) all forwarding. Connections stay
// open; new connections are accepted but do not forward while paused.
func (p *Proxy) SetPaused(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paused = on
	p.cond.Broadcast()
}

// SetFreezeAfter freezes each connection permanently once n bytes have gone
// from the server to the client. Zero disables freezing for new traffic.
func (p *Proxy) SetFreezeAfter(n int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.freezeAfter = n
}

// SetRefuse makes the proxy reset new connections immediately.
func (p *Proxy) SetRefuse(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refuse = on
}

// Close stops the proxy and resets all connections.
func (p *Proxy) Close() error {
	p.mu.Lock()
	p.closed = true
	for c := range p.conns {
		p.killLocked(c)
	}
	p.cond.Broadcast()
	p.mu.Unlock()
	return p.ln.Close()
}

func (p *Proxy) killLocked(c *pconn) {
	if c.closed {
		return
	}
	c.closed = true
	for _, conn := range []net.Conn{c.client, c.server} {
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		conn.Close()
	}
	delete(p.conns, c)
	p.cond.Broadcast()
}

func (p *Proxy) acceptLoop() {
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		p.accepted++
		refuse := p.refuse || p.closed
		p.mu.Unlock()
		if refuse {
			if tc, ok := client.(*net.TCPConn); ok {
				tc.SetLinger(0)
			}
			client.Close()
			continue
		}
		go p.handle(client)
	}
}

func (p *Proxy) handle(client net.Conn) {
	server, err := net.Dial("tcp", p.target)
	if err != nil {
		client.Close()
		return
	}
	c := &pconn{client: client, server: server}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		client.Close()
		server.Close()
		return
	}
	p.conns[c] = struct{}{}
	p.mu.Unlock()
	go p.pump(c, client, server, false)
	p.pump(c, server, client, true)
}

// pump copies src to dst, holding data while the proxy is paused or the
// connection is frozen.
func (p *Proxy) pump(c *pconn, src, dst net.Conn, downstream bool) {
	buf := make([]byte, 16<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			data := buf[:n]
			p.mu.Lock()
			for (p.paused || c.frozen) && !c.closed {
				p.cond.Wait()
			}
			if c.closed {
				p.mu.Unlock()
				return
			}
			if downstream && p.freezeAfter > 0 && c.down+int64(len(data)) >= p.freezeAfter {
				data = data[:max(0, p.freezeAfter-c.down)]
				c.frozen = true // everything after this point is held forever
			}
			if downstream {
				c.down += int64(len(data))
			}
			p.mu.Unlock()
			if len(data) > 0 {
				if _, werr := dst.Write(data); werr != nil {
					p.closeConn(c)
					return
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				if tc, ok := dst.(*net.TCPConn); ok {
					tc.CloseWrite()
					return
				}
			}
			p.closeConn(c)
			return
		}
	}
}

func (p *Proxy) closeConn(c *pconn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	c.client.Close()
	c.server.Close()
	delete(p.conns, c)
	p.cond.Broadcast()
}
