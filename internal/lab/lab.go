// Package lab runs the F1 acceptance scenarios (gate G1) in one process:
//
//	source <- csl server <- faultnet lane A <- csl client <- download
//	                     <- faultnet lane B <-
//
// Every scenario downloads a verified byte pattern through the client while
// faultnet breaks the lanes, and reports whether the download survived, the
// longest stall the application saw, and how long each carrier switch took.
//
// Loopback has no real latency or bandwidth limit; the throughput figures
// here only show CPU overhead. Latency and loss scenarios (tc netem) run in
// the WSL2 / VPS lab under lab/.
package lab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/colitu/csl/carrier"
	"github.com/colitu/csl/handshake"
	"github.com/colitu/csl/internal/bench"
	"github.com/colitu/csl/internal/dialguard"
	"github.com/colitu/csl/internal/faultnet"
	"github.com/colitu/csl/lanes"
	"github.com/colitu/csl/mux"
	"github.com/colitu/csl/server"
	"github.com/colitu/csl/session"
	"github.com/xtaci/smux"
)

// G1 thresholds from the design document.
const (
	MaxStall       = 2 * time.Second // carrier switch must be invisible beyond this
	MaxThroughLoss = 0.10            // CSL may cost at most 10 % throughput
)

// Options tune the lab.
type Options struct {
	Size    uint64        // bytes per download (64 MiB)
	Rate    uint64        // source rate in bytes/s (16 MiB/s)
	Outage  time.Duration // length of the total outage scenario (10 s)
	Session session.Config
	Logf    func(format string, args ...any)
}

func (o Options) withDefaults() Options {
	if o.Size == 0 {
		o.Size = 64 << 20
	}
	if o.Rate == 0 {
		o.Rate = 16 << 20
	}
	if o.Outage <= 0 {
		o.Outage = 10 * time.Second
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return o
}

// Env is one running lab.
type Env struct {
	opts   Options
	Source *bench.Source
	Server *server.Server
	ln     net.Listener
	LaneA  *faultnet.Proxy
	LaneB  *faultnet.Proxy
	Client *lanes.Client
	Mux    *smux.Session

	mu     sync.Mutex
	events []lanes.Event
}

// Start builds the lab. setup runs before the client connects, so a
// scenario can break a lane from the first byte.
func Start(opts Options, setup func(e *Env)) (*Env, error) {
	opts = opts.withDefaults()
	e := &Env{opts: opts}
	var err error
	if e.Source, err = bench.StartSource("127.0.0.1:0"); err != nil {
		return nil, err
	}
	guard := &dialguard.Dialer{AllowPrivate: true} // the source is on loopback
	e.Server = server.New(server.Config{
		Session: opts.Session,
		OnSession: func(_ handshake.ID, s *session.Session) {
			m, err := mux.Server(s)
			if err != nil {
				s.Abort(err)
				return
			}
			mux.Serve(m, guard.Dial, 0)
		},
	})
	if e.ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		e.Close()
		return nil, err
	}
	go e.Server.Serve(e.ln)
	if e.LaneA, err = faultnet.Listen("127.0.0.1:0", e.ln.Addr().String()); err != nil {
		e.Close()
		return nil, err
	}
	if e.LaneB, err = faultnet.Listen("127.0.0.1:0", e.ln.Addr().String()); err != nil {
		e.Close()
		return nil, err
	}
	if setup != nil {
		setup(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	e.Client, err = lanes.Dial(ctx, lanes.Config{
		Carriers: []carrier.Dialer{
			&carrier.TCP{Label: "A", Addr: e.LaneA.Addr()},
			&carrier.TCP{Label: "B", Addr: e.LaneB.Addr()},
		},
		Session: opts.Session,
		OnEvent: func(ev lanes.Event) {
			e.mu.Lock()
			e.events = append(e.events, ev)
			e.mu.Unlock()
			switch {
			case ev.Err != nil:
				opts.Logf("  [%s] %s: %v", ev.Kind, ev.Carrier, ev.Err)
			case ev.Kind == lanes.EventAttached:
				opts.Logf("  [%s] %s after %v", ev.Kind, ev.Carrier, ev.Took)
			}
		},
	})
	if err != nil {
		e.Close()
		return nil, err
	}
	if e.Mux, err = mux.Client(e.Client.Session()); err != nil {
		e.Close()
		return nil, err
	}
	return e, nil
}

// Close tears the lab down.
func (e *Env) Close() {
	if e.Mux != nil {
		e.Mux.Close()
	}
	if e.Client != nil {
		e.Client.Session().Abort(session.ErrClosed)
	}
	for _, p := range []*faultnet.Proxy{e.LaneA, e.LaneB} {
		if p != nil {
			p.Close()
		}
	}
	if e.Server != nil {
		e.Server.Close()
	}
	if e.Source != nil {
		e.Source.Close()
	}
}

// Download fetches size bytes at rate through CSL.
func (e *Env) Download(size, rate uint64) bench.Result {
	st, err := mux.Open(e.Mux, e.Source.Addr())
	if err != nil {
		return bench.Result{Error: err.Error()}
	}
	defer st.Close()
	return bench.Download(st, size, rate)
}

// DownloadDirect fetches size bytes straight from the source, without CSL.
func (e *Env) DownloadDirect(size, rate uint64) bench.Result {
	c, err := net.Dial("tcp", e.Source.Addr())
	if err != nil {
		return bench.Result{Error: err.Error()}
	}
	defer c.Close()
	return bench.Download(c, size, rate)
}

// ActiveLane returns the proxy carrying the session, or nil while recovering.
func (e *Env) ActiveLane() *faultnet.Proxy {
	switch e.Client.Active() {
	case "A":
		return e.LaneA
	case "B":
		return e.LaneB
	}
	return nil
}

// Switches returns the duration of every recovery so far: each attach
// after the first. Durations below the clock resolution (about 0.5-15 ms on
// Windows) read as zero.
func (e *Env) Switches() []time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []time.Duration{}
	first := true
	for _, ev := range e.events {
		if ev.Kind != lanes.EventAttached {
			continue
		}
		if first {
			first = false
			continue
		}
		out = append(out, ev.Took)
	}
	return out
}

// Result is the outcome of one scenario.
type Result struct {
	Name     string          `json:"name"`
	About    string          `json:"about"`
	Download bench.Result    `json:"download"`
	Direct   *bench.Result   `json:"direct,omitempty"`
	Switches []time.Duration `json:"switches_ns"`
	Pass     bool            `json:"pass"`
	Verdict  string          `json:"verdict"`
}

// Scenario is one G1 check.
type Scenario struct {
	Name  string
	About string
	Run   func(o Options) Result
}

// Scenarios lists the G1 checks in the order they run.
func Scenarios() []Scenario {
	return []Scenario{
		{"throughput", "CSL vs direct download, no faults (CPU overhead on loopback)", runThroughput},
		{"kill", "active carrier is reset (RST) every second", runKill},
		{"blackhole", "active carrier silently stops forwarding", runBlackhole},
		{"freeze16k", "lane A freezes every connection after 16 KB downstream", runFreeze},
		{"outage", "both lanes stop forwarding, then come back", runOutage},
	}
}

// Find returns the scenario with the given name.
func Find(name string) (Scenario, error) {
	for _, s := range Scenarios() {
		if s.Name == name {
			return s, nil
		}
	}
	return Scenario{}, errors.New("lab: unknown scenario " + name)
}

func failed(name string, err error) Result {
	return Result{Name: name, Verdict: "setup failed: " + err.Error()}
}

func finish(r Result, e *Env, gateStall bool) Result {
	r.Switches = e.Switches()
	switch {
	case !r.Download.OK:
		r.Verdict = "download broke: " + r.Download.Error
	case gateStall && r.Download.MaxStall > MaxStall:
		r.Verdict = fmt.Sprintf("stall %v exceeds %v", r.Download.MaxStall.Round(time.Millisecond), MaxStall)
	default:
		r.Pass = true
		r.Verdict = fmt.Sprintf("ok, longest stall %v", r.Download.MaxStall.Round(time.Millisecond))
	}
	return r
}

func runThroughput(o Options) Result {
	o = o.withDefaults()
	r := Result{Name: "throughput"}
	e, err := Start(o, nil)
	if err != nil {
		return failed(r.Name, err)
	}
	defer e.Close()
	// Warm up both paths, then keep the best of three runs each.
	size := 4 * o.Size
	e.DownloadDirect(o.Size, 0)
	e.Download(o.Size, 0)
	var direct bench.Result
	for range 3 {
		if d := e.DownloadDirect(size, 0); d.Mbps > direct.Mbps {
			direct = d
		}
		if c := e.Download(size, 0); !c.OK || c.Mbps > r.Download.Mbps || r.Download.Bytes == 0 {
			r.Download = c
			if !c.OK {
				break
			}
		}
	}
	r.Direct = &direct
	r = finish(r, e, false)
	if r.Pass && direct.Mbps > 0 {
		r.Verdict = fmt.Sprintf("CSL %.0f Mbit/s, direct %.0f Mbit/s (ratio %.2f). Informational: loopback is CPU-bound; the %.0f%% gate is measured under netem.",
			r.Download.Mbps, direct.Mbps, r.Download.Mbps/direct.Mbps, MaxThroughLoss*100)
	}
	return r
}

func runKill(o Options) Result {
	o = o.withDefaults()
	r := Result{Name: "kill"}
	e, err := Start(o, nil)
	if err != nil {
		return failed(r.Name, err)
	}
	defer e.Close()
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if l := e.ActiveLane(); l != nil {
					l.KillAll()
				}
			}
		}
	}()
	r.Download = e.Download(o.Size, o.Rate)
	close(stop)
	return finish(r, e, true)
}

func runBlackhole(o Options) Result {
	o = o.withDefaults()
	r := Result{Name: "blackhole"}
	e, err := Start(o, nil)
	if err != nil {
		return failed(r.Name, err)
	}
	defer e.Close()
	go func() {
		time.Sleep(time.Second)
		if l := e.ActiveLane(); l != nil {
			l.SetPaused(true)
		}
	}()
	r.Download = e.Download(o.Size, o.Rate)
	return finish(r, e, true)
}

func runFreeze(o Options) Result {
	o = o.withDefaults()
	r := Result{Name: "freeze16k"}
	e, err := Start(o, func(e *Env) { e.LaneA.SetFreezeAfter(16 << 10) })
	if err != nil {
		return failed(r.Name, err)
	}
	defer e.Close()
	r.Download = e.Download(o.Size, o.Rate)
	return finish(r, e, true)
}

func runOutage(o Options) Result {
	o = o.withDefaults()
	r := Result{Name: "outage"}
	e, err := Start(o, nil)
	if err != nil {
		return failed(r.Name, err)
	}
	defer e.Close()
	go func() {
		time.Sleep(time.Second)
		e.LaneA.SetPaused(true)
		e.LaneB.SetPaused(true)
		time.Sleep(o.Outage)
		e.LaneA.SetPaused(false)
		e.LaneB.SetPaused(false)
	}()
	// The source keeps the download going past the outage.
	size := o.Size + uint64(o.Outage.Seconds()*float64(o.Rate))/2
	r.Download = e.Download(size, o.Rate)
	r = finish(r, e, false)
	if r.Pass {
		recovery := r.Download.MaxStall - o.Outage
		r.Verdict = fmt.Sprintf("session survived a %v outage; back %v after the network returned", o.Outage, recovery.Round(time.Millisecond))
	}
	return r
}
