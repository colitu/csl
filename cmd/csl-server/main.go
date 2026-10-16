// Command csl-server is the node side of CSL.
//
// It listens on loopback and is reached through the node's Xray or sing-box
// inbounds, so it never faces the internet directly:
//
//	csl-server -listen 127.0.0.1:9440
//
// -listen takes a comma-separated list; the network lab uses one port per
// lane so faults can be applied to each lane separately.
//
// Streams may only reach public addresses unless -allow-private is set.
// On a node, -upstream sends every stream through a loopback SOCKS5 inbound
// of the node's Xray, so CSL traffic gets the same rules as any other
// tunnel traffic (private addresses, BitTorrent, egress domains) instead of
// leaving the node directly.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/colitu/csl/handshake"
	"github.com/colitu/csl/internal/dialguard"
	"github.com/colitu/csl/internal/socks5"
	"github.com/colitu/csl/mux"
	"github.com/colitu/csl/server"
	"github.com/colitu/csl/session"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9440", "comma-separated addresses to accept carriers on (keep them on loopback)")
	allowNonLoopback := flag.Bool("allow-non-loopback", false, "permit listening outside loopback (isolated network lab only)")
	allowPrivate := flag.Bool("allow-private", false, "let streams reach loopback and private addresses (lab only)")
	linger := flag.Duration("linger", session.DefaultLinger, "how long a session survives without a carrier")
	deadAfter := flag.Duration("dead-after", session.DefaultDeadAfter, "carrier silence before it is declared dead")
	maxSessions := flag.Int("max-sessions", 256, "maximum live sessions")
	maxPending := flag.Int("max-pending-carriers", 256, "maximum carriers waiting for a handshake")
	maxStreams := flag.Int("max-streams-per-session", 128, "maximum active streams in one session")
	maxTotalStreams := flag.Int("max-total-streams", 1024, "maximum active streams across all sessions")
	maxUserStreams := flag.Int("max-streams-per-identity", 256, "maximum active streams for one authenticated user across sessions")
	identityFile := flag.String("identity-file", "", "JSON map of credential SHA-256 hashes to user IDs; reloaded for each HELLO")
	maxUserSessions := flag.Int("max-sessions-per-identity", 4, "maximum live CSL sessions for one authenticated user")
	maxBufferMemory := flag.Int("max-buffer-memory-mib", 256, "maximum ring and queued datagram storage across all sessions, in MiB")
	verbose := flag.Bool("v", false, "log session events (never logs addresses or traffic)")
	statsInterval := flag.Duration("stats-interval", 0, "periodically log session, carrier, stream and Go heap counts (0 = off)")
	upstream := flag.String("upstream", "", "dial every stream through this loopback SOCKS5 proxy (socks5://127.0.0.1:PORT) so the node's core applies its rules")
	flag.Parse()
	if *maxStreams <= 0 || *maxTotalStreams <= 0 || *maxUserStreams <= 0 || *maxUserSessions <= 0 {
		log.Fatal("csl-server: stream and user limits must be positive")
	}
	if *maxBufferMemory <= 0 || *maxBufferMemory > 4096 {
		log.Fatal("csl-server: buffer memory limit must be between 1 and 4096 MiB")
	}
	bufferBudget := session.NewMemoryBudget(int64(*maxBufferMemory) << 20)
	var authenticate func([]byte) (string, error)
	perIdentityLimit := 0
	var initialIdentities map[string]string
	var identities *identityProvider
	if *identityFile != "" {
		var err error
		initialIdentities, err = loadIdentities(*identityFile)
		if err != nil {
			log.Fatalf("csl-server: identity file: %v", err)
		}
		identities = &identityProvider{entries: initialIdentities}
		authenticate = identities.authenticate
		perIdentityLimit = *maxUserSessions
	}

	addrs := strings.Split(*listen, ",")
	for _, a := range addrs {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			log.Fatalf("csl-server: bad -listen %q: %v", a, err)
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			if !*allowNonLoopback {
				log.Fatalf("csl-server: refusing non-loopback listener %s (isolated lab: -allow-non-loopback)", a)
			}
			fmt.Fprintf(os.Stderr, "csl-server: warning: non-loopback listener %s enabled for isolated lab\n", a)
		}
	}

	logf := func(string, ...any) {}
	if *verbose {
		logf = log.Printf
	}
	guard := &dialguard.Dialer{AllowPrivate: *allowPrivate}
	guard.Dialer.Timeout = 10 * time.Second
	dial := mux.DialFunc(guard.Dial)
	if *upstream != "" {
		proxy, err := parseUpstream(*upstream)
		if err != nil {
			log.Fatalf("csl-server: -upstream: %v", err)
		}
		dial = upstreamDialer(proxy, *allowPrivate)
	}
	streamLimit := mux.NewStreamLimiter(*maxTotalStreams)
	userLimits := newIdentityStreamLimits(*maxUserStreams)

	srv := server.New(server.Config{
		Session:                session.Config{Linger: *linger, DeadAfter: *deadAfter, Budget: bufferBudget},
		MaxSessions:            *maxSessions,
		MaxPendingCarriers:     *maxPending,
		Authenticate:           authenticate,
		MaxSessionsPerIdentity: perIdentityLimit,
		Logf:                   logf,
		OnAuthenticatedSession: func(id handshake.ID, identity string, s *session.Session) {
			var userLimit *mux.StreamLimiter
			if identity != "" {
				var release func()
				userLimit, release = userLimits.acquire(identity)
				defer release()
			}
			m, err := mux.Server(s)
			if err != nil {
				s.Abort(err)
				return
			}
			go func() {
				<-s.Done()
				m.Close()
			}()
			err = mux.ServeWithLimitGroups(m, dial, 10*time.Second, *maxStreams, streamLimit, userLimit)
			logf("session %s: streams ended: %v", id, err)
			s.Close()
		},
	})
	if *identityFile != "" {
		go watchIdentityFile(*identityFile, initialIdentities, identities, srv)
	}
	if *statsInterval > 0 {
		go func() {
			ticker := time.NewTicker(*statsInterval)
			defer ticker.Stop()
			for range ticker.C {
				var mem runtime.MemStats
				runtime.ReadMemStats(&mem)
				log.Printf("csl-server: sessions=%d pending=%d streams=%d buffers=%d/%dMiB heap=%dMiB heap_sys=%dMiB goroutines=%d",
					srv.Sessions(), srv.PendingCarriers(), streamLimit.Active(), bufferBudget.Used()>>20, bufferBudget.Limit()>>20, mem.HeapAlloc>>20, mem.HeapSys>>20, runtime.NumGoroutine())
			}
		}()
	}

	var lns []net.Listener
	for _, a := range addrs {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			log.Fatalf("csl-server: %v", err)
		}
		log.Printf("csl-server: listening on %s", ln.Addr())
		lns = append(lns, ln)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		log.Printf("csl-server: shutting down")
		srv.Close()
	}()
	errc := make(chan error, len(lns))
	for _, ln := range lns {
		go func() { errc <- srv.Serve(ln) }()
	}
	if err := <-errc; err != nil && !errors.Is(err, net.ErrClosed) {
		log.Fatalf("csl-server: %v", err)
	}
}

type identityProvider struct {
	mu      sync.RWMutex
	entries map[string]string
	err     error
}

func (p *identityProvider) authenticate(credential []byte) (string, error) {
	if len(credential) < 16 || len(credential) > 256 {
		return "", errors.New("invalid credential")
	}
	sum := sha256.Sum256(credential)
	p.mu.RLock()
	identity, err := p.entries[hex.EncodeToString(sum[:])], p.err
	p.mu.RUnlock()
	if err != nil {
		return "", err
	}
	if identity == "" {
		return "", errors.New("invalid credential")
	}
	return identity, nil
}

func (p *identityProvider) update(entries map[string]string, err error) {
	p.mu.Lock()
	p.entries, p.err = entries, err
	p.mu.Unlock()
}

func watchIdentityFile(path string, previous map[string]string, provider *identityProvider, srv *server.Server) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastError := ""
	for range ticker.C {
		current, err := loadIdentities(path)
		if err != nil {
			provider.update(nil, err)
			if err.Error() != lastError {
				log.Printf("csl-server: identity file update failed: %v", err)
				lastError = err.Error()
			}
			continue
		}
		lastError = ""
		provider.update(current, nil)
		for hash, identity := range previous {
			if current[hash] == identity {
				continue
			}
			decoded, _ := hex.DecodeString(hash) // validated by loadIdentities
			var key [sha256.Size]byte
			copy(key[:], decoded)
			srv.RevokeCredentialHash(key)
		}
		previous = current
	}
}

type identityStreamLimits struct {
	mu      sync.Mutex
	max     int
	entries map[string]*identityStreamLimit
}

type identityStreamLimit struct {
	limit *mux.StreamLimiter
	refs  int
}

func newIdentityStreamLimits(max int) *identityStreamLimits {
	return &identityStreamLimits{max: max, entries: make(map[string]*identityStreamLimit)}
}

func (l *identityStreamLimits) acquire(identity string) (*mux.StreamLimiter, func()) {
	l.mu.Lock()
	e := l.entries[identity]
	if e == nil {
		e = &identityStreamLimit{limit: mux.NewStreamLimiter(l.max)}
		l.entries[identity] = e
	}
	e.refs++
	l.mu.Unlock()
	return e.limit, func() {
		l.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(l.entries, identity)
		}
		l.mu.Unlock()
	}
}

func loadIdentities(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New("identity file exceeds 1 MiB")
	}
	var identities map[string]string
	if err := json.Unmarshal(data, &identities); err != nil {
		return nil, err
	}
	if len(identities) == 0 {
		return nil, errors.New("identity file is empty")
	}
	for hash, identity := range identities {
		decoded, err := hex.DecodeString(hash)
		if err != nil || len(decoded) != sha256.Size || hash != strings.ToLower(hash) || strings.TrimSpace(identity) != identity || identity == "" {
			return nil, errors.New("identity file has an invalid hash or user ID")
		}
	}
	return identities, nil
}

// parseUpstream accepts only socks5://<loopback IP>:<port>: the proxy is the
// node's own core, never something on the network.
func parseUpstream(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "socks5" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return "", fmt.Errorf("want socks5://127.0.0.1:PORT, got %q", raw)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "", err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() || port == "" || port == "0" {
		return "", fmt.Errorf("the upstream must be a loopback IP and port, got %q", u.Host)
	}
	return u.Host, nil
}

// upstreamDialer dials targets through the core's SOCKS5 inbound. The core
// resolves names and refuses private destinations itself; literal private
// addresses and localhost names are refused here as well, before any byte
// reaches the core.
func upstreamDialer(proxy string, allowPrivate bool) mux.DialFunc {
	return func(ctx context.Context, target string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(target)
		if err != nil {
			return nil, err
		}
		if !allowPrivate {
			if ip, err := netip.ParseAddr(host); err == nil && !dialguard.Allowed(ip) {
				return nil, fmt.Errorf("%w: %s", dialguard.ErrForbidden, ip)
			}
			if name := strings.TrimSuffix(strings.ToLower(host), "."); name == "localhost" || strings.HasSuffix(name, ".localhost") {
				return nil, fmt.Errorf("%w: %s", dialguard.ErrForbidden, host)
			}
		}
		return socks5.Dial(ctx, proxy, target, nil)
	}
}
