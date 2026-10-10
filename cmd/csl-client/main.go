// Command csl-client is the device side of CSL for F1 testing.
//
// It opens a local SOCKS5 port; applications connect to it and their
// streams travel over one resumable CSL session that survives carrier loss:
//
//	csl-client -socks 127.0.0.1:1080 \
//	    -carrier "socks5://127.0.0.1:10808/127.0.0.1:9440#reality" \
//	    -carrier "socks5://127.0.0.1:10809/127.0.0.1:9440#trojan"
//
// Each -carrier is tried in the order given (see package carrier for the
// syntax). In F1 the client exits when its session ends; the apps will
// re-create sessions in F2.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/colitu/csl/carrier"
	"github.com/colitu/csl/internal/relay"
	"github.com/colitu/csl/internal/socks5"
	"github.com/colitu/csl/lanes"
	"github.com/colitu/csl/mux"
	"github.com/colitu/csl/session"
	"github.com/xtaci/smux"
)

type carrierFlags []string

func (c *carrierFlags) String() string     { return strings.Join(*c, ", ") }
func (c *carrierFlags) Set(v string) error { *c = append(*c, v); return nil }

func main() {
	var specs carrierFlags
	socksAddr := flag.String("socks", "127.0.0.1:1080", "local SOCKS5 address for applications")
	flag.Var(&specs, "carrier", "carrier to the CSL server, repeatable, in priority order")
	deadAfter := flag.Duration("dead-after", session.DefaultDeadAfter, "carrier silence before it is declared dead")
	noSpare := flag.Bool("no-spare", false, "do not keep a warm spare carrier")
	credentialFile := flag.String("credential-file", "", "file containing an opaque node credential (never put it on the command line)")
	verbose := flag.Bool("v", false, "log carrier events")
	flag.Parse()

	if len(specs) == 0 {
		fmt.Fprintln(os.Stderr, "csl-client: at least one -carrier is required")
		flag.Usage()
		os.Exit(2)
	}
	var credential []byte
	if *credentialFile != "" {
		var err error
		credential, err = os.ReadFile(*credentialFile)
		if err != nil {
			log.Fatalf("csl-client: credential file: %v", err)
		}
		credential = []byte(strings.TrimSpace(string(credential)))
		if len(credential) < 16 || len(credential) > 256 {
			log.Fatal("csl-client: credential must contain 16 to 256 bytes")
		}
	}
	var dialers []carrier.Dialer
	for _, s := range specs {
		d, err := carrier.Parse(s)
		if err != nil {
			log.Fatalf("csl-client: %v", err)
		}
		dialers = append(dialers, d)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	client, err := lanes.Dial(ctx, lanes.Config{
		Carriers:   dialers,
		Session:    session.Config{DeadAfter: *deadAfter},
		NoSpare:    *noSpare,
		Credential: credential,
		OnEvent: func(ev lanes.Event) {
			if !*verbose && ev.Kind == lanes.EventSpareReady {
				return
			}
			switch {
			case ev.Err != nil:
				log.Printf("carrier %s: %s: %v", ev.Carrier, ev.Kind, ev.Err)
			case ev.Took > 0:
				log.Printf("carrier %s: %s after %v", ev.Carrier, ev.Kind, ev.Took.Round(time.Millisecond))
			default:
				log.Printf("carrier %s: %s", ev.Carrier, ev.Kind)
			}
		},
	})
	cancel()
	if err != nil {
		log.Fatalf("csl-client: %v", err)
	}
	m, err := mux.Client(client.Session())
	if err != nil {
		log.Fatalf("csl-client: %v", err)
	}

	ln, err := net.Listen("tcp", *socksAddr)
	if err != nil {
		log.Fatalf("csl-client: %v", err)
	}
	log.Printf("csl-client: SOCKS5 on %s", ln.Addr())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sig:
			log.Printf("csl-client: shutting down")
			m.Close()
			client.Close()
		case <-client.Session().Done():
			log.Printf("csl-client: session ended: %v", client.Session().Err())
		}
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-client.Session().Done():
				if err := client.Session().Err(); err != nil {
					os.Exit(1)
				}
				return
			default:
			}
			return
		}
		go handle(conn, m)
	}
}

func handle(conn net.Conn, m *smux.Session) {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	target, err := socks5.ServerHandshake(conn)
	if err != nil {
		conn.Close()
		return
	}
	st, err := mux.Open(m, target)
	if err != nil {
		code := socks5.ReplyGeneralFailure
		if se, ok := err.(*mux.StatusError); ok {
			switch se.Code {
			case mux.StatusForbidden:
				code = socks5.ReplyNotAllowed
			case mux.StatusUnreachable:
				code = socks5.ReplyHostUnreachable
			}
		}
		socks5.Reply(conn, code)
		conn.Close()
		return
	}
	if err := socks5.Reply(conn, socks5.ReplySucceeded); err != nil {
		st.Close()
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{})
	relay.Pipe(conn, st)
}
