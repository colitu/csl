// Package lanes is the client side of CSL: it opens carriers, keeps a warm
// spare, and moves the session to a new carrier when the active one dies.
//
// Recovery order when the active carrier is lost:
//
//  1. resume on the warm spare (one round trip, the spare is already
//     connected and greeted);
//  2. otherwise race all carriers, starting one every Stagger, and resume on
//     the first that answers;
//  3. retry with backoff until the session's linger period runs out.
//
// A carrier that fails is penalized for an exponentially growing period so
// that a transport which is being blocked is not retried immediately.
package lanes

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/colitu/csl/carrier"
	"github.com/colitu/csl/frame"
	"github.com/colitu/csl/handshake"
	"github.com/colitu/csl/session"
)

// Config tunes a Client.
type Config struct {
	// Carriers in priority order. At least one is required.
	Carriers   []carrier.Dialer
	Session    session.Config
	Credential []byte // optional opaque HELLO credential for node admission

	DialTimeout       time.Duration // connect + greeting + handshake (5 s)
	SelectionWindow   time.Duration // maximum initial carrier measurement round (3 s)
	Stagger           time.Duration // delay between racing dials (250 ms)
	SpareMaxAge       time.Duration // a parked spare is replaced after this (60 s)
	SparePingInterval time.Duration // parked spare health check (15 s)
	SparePingTimeout  time.Duration // maximum time for a parked spare PONG (1 s)
	NoSpare           bool          // disable the warm spare
	PenaltyBase       time.Duration // first penalty after a failure (5 s)
	PenaltyMax        time.Duration // penalty cap (2 min)

	// OnEvent receives carrier events, for logging and measurements.
	OnEvent func(Event)
}

// EventKind classifies an Event.
type EventKind string

const (
	EventAttached     EventKind = "attached"      // a carrier became active
	EventLost         EventKind = "lost"          // the active carrier died
	EventResumeFailed EventKind = "resume-failed" // a resume attempt failed
	EventSpareReady   EventKind = "spare-ready"   // a warm spare is parked
	EventSpareLost    EventKind = "spare-lost"    // a parked warm spare failed its health check
)

// Event describes something that happened to a carrier.
type Event struct {
	Kind    EventKind
	Carrier string
	Err     error
	// Took is set on EventAttached after a loss: time from the loss to the
	// new carrier being active.
	Took time.Duration
}

// ErrSessionLost is returned when the server no longer knows the session.
var ErrSessionLost = errors.New("lanes: server rejected resume, session lost")
var errLegacyProbe = errors.New("lanes: server does not support pre-request probes")

type laneState struct {
	failures       int
	penaltyUntil   time.Time
	latency        time.Duration
	probeSupported bool
}

// pending is a connected and greeted carrier that has not sent its request.
type pending struct {
	d              carrier.Dialer
	conn           net.Conn
	r              *frame.Reader
	g              handshake.Greeting
	since          time.Time
	latency        time.Duration
	lastCheck      time.Time
	probeSupported bool
}

// Client owns one CSL session and the carriers under it.
type Client struct {
	cfg    Config
	sess   *session.Session
	id     handshake.ID
	secret handshake.Secret

	lost    chan error
	spareCh chan *pending

	mu           sync.Mutex
	lanes        map[carrier.Dialer]*laneState
	active       carrier.Dialer
	spare        *pending
	spareDialing bool
}

func (c Config) withDefaults() Config {
	if c.DialTimeout <= 0 {
		c.DialTimeout = 5 * time.Second
	}
	if c.SelectionWindow <= 0 {
		c.SelectionWindow = 3 * time.Second
	}
	if c.Stagger <= 0 {
		c.Stagger = 250 * time.Millisecond
	}
	if c.SpareMaxAge <= 0 {
		c.SpareMaxAge = 60 * time.Second
	}
	if c.SparePingInterval <= 0 {
		c.SparePingInterval = 15 * time.Second
	}
	if c.SparePingTimeout <= 0 {
		c.SparePingTimeout = time.Second
	}
	if c.PenaltyBase <= 0 {
		c.PenaltyBase = 5 * time.Second
	}
	if c.PenaltyMax <= 0 {
		c.PenaltyMax = 2 * time.Minute
	}
	if c.OnEvent == nil {
		c.OnEvent = func(Event) {}
	}
	c.Session = c.Session.WithDefaults()
	return c
}

// Dial opens the first carrier, creates a session and starts carrier
// management in the background.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if len(cfg.Carriers) == 0 {
		return nil, errors.New("lanes: no carriers configured")
	}
	cfg = cfg.withDefaults()
	c := &Client{
		cfg:     cfg,
		lost:    make(chan error, 1),
		spareCh: make(chan *pending, 1),
		lanes:   make(map[carrier.Dialer]*laneState),
	}
	for _, d := range cfg.Carriers {
		c.lanes[d] = &laneState{}
	}

	p, spare, err := c.selectInitial(ctx)
	if err != nil {
		return nil, err
	}
	c.spare = spare
	p.conn.SetDeadline(time.Now().Add(cfg.DialTimeout))
	w, err := handshake.ClientHello(p.conn, p.r, handshake.Hello{Version: handshake.Version, Window: uint64(cfg.Session.Window), Credential: cfg.Credential})
	if err != nil {
		p.conn.Close()
		c.dropSpare()
		return nil, fmt.Errorf("lanes: hello on %s: %w", p.d.Name(), err)
	}
	p.conn.SetDeadline(time.Time{})

	scfg := cfg.Session
	scfg.OnCarrierLost = c.onLost
	c.sess = session.New(scfg, w.Window)
	c.id, c.secret = w.ID, w.Secret
	if err := c.sess.Attach(p.conn, p.r, 0, p.d.Name()); err != nil {
		c.dropSpare()
		return nil, err
	}
	c.succeeded(p.d, p.latency)
	c.cfg.OnEvent(Event{Kind: EventAttached, Carrier: p.d.Name()})
	go c.loop()
	return c, nil
}

// Session returns the underlying session (an io.ReadWriteCloser).
func (c *Client) Session() *session.Session { return c.sess }

// Close closes the session gracefully.
func (c *Client) Close() error { return c.sess.Close() }

// Active returns the name of the active carrier, or "" while recovering.
func (c *Client) Active() string {
	if st := c.sess.Stats(); st.Attached {
		return st.Carrier
	}
	return ""
}

func (c *Client) onLost(err error) {
	select {
	case c.lost <- err:
	default:
	}
}

func (c *Client) loop() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	defer c.dropSpare()
	c.maintainSpare()
	for {
		select {
		case <-c.sess.Done():
			return
		case err := <-c.lost:
			c.recover(err)
			c.maintainSpare()
		case p := <-c.spareCh:
			c.mu.Lock()
			c.spareDialing = false
			if c.spare != nil {
				c.spare.conn.Close()
			}
			c.spare = p
			c.mu.Unlock()
			if p != nil {
				c.cfg.OnEvent(Event{Kind: EventSpareReady, Carrier: p.d.Name()})
			}
		case <-tick.C:
			c.checkSpare()
			c.maintainSpare()
		}
	}
}

func (c *Client) dropSpare() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.spare != nil {
		c.spare.conn.Close()
		c.spare = nil
	}
}

func (c *Client) checkSpare() {
	c.mu.Lock()
	p := c.spare
	if p == nil || !p.probeSupported || time.Since(p.lastCheck) < c.cfg.SparePingInterval {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	err := p.conn.SetDeadline(time.Now().Add(c.cfg.SparePingTimeout))
	id := uint64(time.Now().UnixNano())
	if err == nil {
		err = frame.Write(p.conn, frame.Frame{Type: frame.TypePing, Seq: id})
	}
	if err == nil {
		var reply frame.Frame
		reply, err = p.r.Read()
		if err == nil && (reply.Type != frame.TypePong || reply.Seq != id || reply.Flags != 0 || len(reply.Payload) != 0) {
			err = handshake.ErrUnexpected
		}
	}
	p.conn.SetDeadline(time.Time{})
	c.mu.Lock()
	if c.spare == p {
		if err == nil {
			p.lastCheck = time.Now()
		} else {
			p.conn.Close()
			c.spare = nil
		}
	}
	c.mu.Unlock()
	if err != nil {
		c.failed(p.d)
		c.cfg.OnEvent(Event{Kind: EventSpareLost, Carrier: p.d.Name(), Err: err})
	}
}

// maintainSpare starts dialing a new spare when there is none or the parked
// one is too old.
func (c *Client) maintainSpare() {
	if c.cfg.NoSpare {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.spareDialing {
		return
	}
	if c.spare != nil {
		if time.Since(c.spare.since) < c.cfg.SpareMaxAge {
			return
		}
	}
	order := c.orderLocked(c.active)
	if len(order) == 0 {
		return
	}
	d := order[0]
	activeFamily := carrier.FamilyOf(c.active)
	for _, candidate := range order {
		family := carrier.FamilyOf(candidate)
		if activeFamily != carrier.FamilyUnknown && family != carrier.FamilyUnknown && family != activeFamily {
			d = candidate
			break
		}
	}
	probeSupported := c.lanes[d].probeSupported
	c.spareDialing = true
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.DialTimeout)
		defer cancel()
		p, err := c.open(ctx, d)
		if err != nil {
			c.failed(d)
			p = nil
		} else {
			p.probeSupported = probeSupported
		}
		select {
		case <-c.sess.Done():
			if p != nil {
				p.conn.Close()
			}
			c.mu.Lock()
			c.spareDialing = false
			c.mu.Unlock()
		case c.spareCh <- p:
		}
	}()
}

// recover moves the session to a new carrier after the active one died.
func (c *Client) recover(lostErr error) {
	start := time.Now()
	c.mu.Lock()
	failed := c.active
	c.active = nil
	c.mu.Unlock()
	if failed != nil {
		c.failed(failed)
		c.cfg.OnEvent(Event{Kind: EventLost, Carrier: failed.Name(), Err: lostErr})
	}

	backoff := 100 * time.Millisecond
	for {
		select {
		case <-c.sess.Done():
			return
		default:
		}
		if c.sess.Stats().Attached {
			return
		}

		c.mu.Lock()
		p := c.spare
		c.spare = nil
		c.mu.Unlock()
		if p == nil {
			ctx, cancel := context.WithTimeout(context.Background(), c.cfg.DialTimeout)
			p, _ = c.race(ctx, c.order(nil))
			cancel()
		}
		if p != nil {
			err := c.resumeOn(p)
			if err == nil {
				c.mu.Lock()
				c.active = p.d
				c.mu.Unlock()
				c.succeeded(p.d, p.latency)
				c.cfg.OnEvent(Event{Kind: EventAttached, Carrier: p.d.Name(), Took: time.Since(start)})
				return
			}
			c.failed(p.d)
			c.cfg.OnEvent(Event{Kind: EventResumeFailed, Carrier: p.d.Name(), Err: err})
			var rej *handshake.RejectError
			if errors.As(err, &rej) && (rej.Reason == handshake.ReasonDenied || rej.Reason == handshake.ReasonExpired) {
				c.sess.Abort(ErrSessionLost)
				return
			}
		}

		select {
		case <-c.sess.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 2*time.Second)
	}
}

func (c *Client) resumeOn(p *pending) error {
	recvNext, err := c.sess.PrepareResume()
	if err != nil {
		p.conn.Close()
		return err
	}
	p.conn.SetDeadline(time.Now().Add(c.cfg.DialTimeout))
	acc, err := handshake.ClientResume(p.conn, p.r, p.g, c.id, c.secret, recvNext)
	if err != nil {
		p.conn.Close()
		return err
	}
	p.conn.SetDeadline(time.Time{})
	return c.sess.Attach(p.conn, p.r, acc.RecvNext, p.d.Name())
}

// open connects d and reads the server greeting.
func (c *Client) open(ctx context.Context, d carrier.Dialer) (*pending, error) {
	start := time.Now()
	conn, err := d.Dial(ctx)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	r := frame.NewReader(conn)
	g, err := handshake.ReadGreeting(r)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if ctx.Err() != nil {
		conn.Close()
		return nil, ctx.Err()
	}
	conn.SetDeadline(time.Time{})
	now := time.Now()
	return &pending{d: d, conn: conn, r: r, g: g, since: now, lastCheck: now, latency: time.Since(start)}, nil
}

// selectInitial measures all configured carriers for at most SelectionWindow.
// The quickest healthy carrier wins, with a small preference for configured
// order. A ready carrier from another transport family becomes the warm spare.
func (c *Client) selectInitial(ctx context.Context) (*pending, *pending, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.SelectionWindow)
	defer cancel()
	type result struct {
		p   *pending
		d   carrier.Dialer
		err error
	}
	results := make(chan result, len(c.cfg.Carriers))
	for _, d := range c.cfg.Carriers {
		go func() {
			start := time.Now()
			p, err := c.open(ctx, d)
			if err == nil {
				err = probeCarrier(ctx, p)
				if err != nil {
					p.conn.Close()
					p = nil
					if errors.Is(err, errLegacyProbe) {
						p, err = c.open(ctx, d)
						if err == nil {
							p.latency = time.Since(start)
						}
					}
				} else {
					p.latency = time.Since(start)
					p.probeSupported = true
				}
			}
			results <- result{p: p, d: d, err: err}
		}()
	}
	var ready []*pending
	var errs []error
	for received := 0; received < len(c.cfg.Carriers); received++ {
		select {
		case r := <-results:
			if r.err != nil {
				c.failed(r.d)
				errs = append(errs, r.err)
			} else {
				ready = append(ready, r.p)
			}
		case <-ctx.Done():
			left := len(c.cfg.Carriers) - received
			go func() {
				for range left {
					if r := <-results; r.p != nil {
						r.p.conn.Close()
					}
				}
			}()
			received = len(c.cfg.Carriers)
		}
	}
	if len(ready) == 0 {
		return nil, nil, errors.Join(append(errs, ctx.Err())...)
	}
	priority := func(d carrier.Dialer) int {
		for i, candidate := range c.cfg.Carriers {
			if d == candidate {
				return i
			}
		}
		return len(c.cfg.Carriers)
	}
	score := func(p *pending) time.Duration { return p.latency + time.Duration(priority(p.d))*25*time.Millisecond }
	for i := 1; i < len(ready); i++ {
		for j := i; j > 0 && score(ready[j]) < score(ready[j-1]); j-- {
			ready[j], ready[j-1] = ready[j-1], ready[j]
		}
	}
	for _, p := range ready {
		c.lanes[p.d].latency = p.latency
		c.lanes[p.d].probeSupported = p.probeSupported
	}
	primary := ready[0]
	var spare *pending
	if !c.cfg.NoSpare {
		primaryFamily := carrier.FamilyOf(primary.d)
		for _, p := range ready[1:] {
			family := carrier.FamilyOf(p.d)
			if primaryFamily != carrier.FamilyUnknown && family != carrier.FamilyUnknown && family != primaryFamily {
				spare = p
				break
			}
		}
		if spare == nil && len(ready) > 1 {
			spare = ready[1]
		}
	}
	for _, p := range ready[1:] {
		if p != spare {
			p.conn.Close()
		}
	}
	return primary, spare, nil
}

// probeCarrier verifies 64 KiB of echoed data on a newly greeted carrier.
// A separate writer lets the test work even with an unbuffered net.Conn.
func probeCarrier(ctx context.Context, p *pending) error {
	payload := make([]byte, frame.MaxPayload)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := p.conn.SetDeadline(deadline); err != nil {
			return err
		}
	}
	defer p.conn.SetDeadline(time.Time{})
	written := make(chan error, 1)
	go func() {
		for id := uint64(1); id <= 4; id++ {
			if err := frame.Write(p.conn, frame.Frame{Type: frame.TypePing, Seq: id, Payload: payload}); err != nil {
				written <- err
				return
			}
		}
		written <- nil
	}()
	for id := uint64(1); id <= 4; id++ {
		reply, err := p.r.Read()
		if err != nil {
			return err
		}
		if id == 1 && reply.Type == frame.TypeClose && len(reply.Payload) == 1 && handshake.Reason(reply.Payload[0]) == handshake.ReasonProtocol {
			return errLegacyProbe
		}
		if reply.Type != frame.TypePong || reply.Flags != 0 || reply.Seq != id || !bytes.Equal(reply.Payload, payload) {
			return handshake.ErrUnexpected
		}
	}
	return <-written
}

// race opens the carriers in order, starting one every Stagger, and returns
// the first that is ready. The others are closed.
func (c *Client) race(ctx context.Context, ds []carrier.Dialer) (*pending, error) {
	if len(ds) == 0 {
		return nil, errors.New("lanes: no carriers")
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.DialTimeout)
	defer cancel()
	type result struct {
		p   *pending
		d   carrier.Dialer
		err error
	}
	results := make(chan result, len(ds))
	for i, d := range ds {
		go func() {
			if i > 0 {
				t := time.NewTimer(time.Duration(i) * c.cfg.Stagger)
				defer t.Stop()
				select {
				case <-t.C:
				case <-ctx.Done():
					results <- result{d: d, err: ctx.Err()}
					return
				}
			}
			p, err := c.open(ctx, d)
			results <- result{p: p, d: d, err: err}
		}()
	}
	var errs []error
	for n := range len(ds) {
		r := <-results
		if r.err == nil {
			cancel()
			go func(left int) { // close the losers as they finish
				for range left {
					if r := <-results; r.p != nil {
						r.p.conn.Close()
					}
				}
			}(len(ds) - n - 1)
			return r.p, nil
		}
		if !errors.Is(r.err, context.Canceled) {
			c.failed(r.d)
		}
		errs = append(errs, fmt.Errorf("%s: %w", r.d.Name(), r.err))
	}
	return nil, errors.Join(errs...)
}

// order returns carriers by preference: unpenalized ones in configured
// order, then penalized ones by how soon their penalty ends.
func (c *Client) order(avoid carrier.Dialer) []carrier.Dialer {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.orderLocked(avoid)
}

// orderLocked is order; avoid is moved to the end unless it is the only
// carrier.
func (c *Client) orderLocked(avoid carrier.Dialer) []carrier.Dialer {
	now := time.Now()
	var ready, penalized []carrier.Dialer
	for _, d := range c.cfg.Carriers {
		if d == avoid {
			continue
		}
		if c.lanes[d].penaltyUntil.After(now) {
			penalized = append(penalized, d)
		} else {
			ready = append(ready, d)
		}
	}
	for i := 1; i < len(penalized); i++ { // insertion sort by penalty end
		for j := i; j > 0 && c.lanes[penalized[j]].penaltyUntil.Before(c.lanes[penalized[j-1]].penaltyUntil); j-- {
			penalized[j], penalized[j-1] = penalized[j-1], penalized[j]
		}
	}
	priority := func(d carrier.Dialer) int {
		for i, candidate := range c.cfg.Carriers {
			if d == candidate {
				return i
			}
		}
		return len(c.cfg.Carriers)
	}
	score := func(d carrier.Dialer) time.Duration {
		latency := c.lanes[d].latency
		if latency == 0 {
			latency = 100 * time.Millisecond
		}
		return latency + time.Duration(priority(d))*25*time.Millisecond
	}
	for i := 1; i < len(ready); i++ {
		for j := i; j > 0 && score(ready[j]) < score(ready[j-1]); j-- {
			ready[j], ready[j-1] = ready[j-1], ready[j]
		}
	}
	out := append(ready, penalized...)
	if avoid != nil {
		out = append(out, avoid)
	}
	return out
}

func (c *Client) failed(d carrier.Dialer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.lanes[d]
	st.failures++
	pen := c.cfg.PenaltyBase << min(st.failures-1, 10)
	st.penaltyUntil = time.Now().Add(min(pen, c.cfg.PenaltyMax))
}

func (c *Client) succeeded(d carrier.Dialer, latency time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active = d
	st := c.lanes[d]
	st.failures = 0
	st.penaltyUntil = time.Time{}
	if latency > 0 {
		st.latency = latency
	}
}
