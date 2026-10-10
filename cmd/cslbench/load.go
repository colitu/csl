package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/colitu/csl/carrier"
	"github.com/colitu/csl/lanes"
	"github.com/colitu/csl/mux"
	"github.com/xtaci/smux"
)

type loadCarriers []string

func (c *loadCarriers) String() string { return fmt.Sprint([]string(*c)) }
func (c *loadCarriers) Set(value string) error {
	*c = append(*c, value)
	return nil
}

type heldSession struct {
	client *lanes.Client
	mux    *smux.Session
	stream *smux.Stream
}

func (h *heldSession) close() {
	if h.stream != nil {
		h.stream.Close()
	}
	if h.mux != nil {
		h.mux.Close()
	}
	if h.client != nil {
		_ = h.client.Close()
	}
}

func runLoad(args []string) {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	var specs loadCarriers
	fs.Var(&specs, "carrier", "carrier to a CSL server; repeat for a warm spare")
	count := fs.Int("sessions", 50, "number of simultaneous CSL sessions")
	parallel := fs.Int("parallel", 10, "maximum simultaneous handshakes")
	hold := fs.Duration("hold", 30*time.Second, "how long to hold sessions for measurement")
	target := fs.String("target", "", "server-side source address, required with -queued")
	queued := sizeFlag(0)
	fs.Var(&queued, "queued", "unread bytes to request per session (e.g. 256KiB)")
	fs.Parse(args)
	if *count < 1 || *count > 10000 || *parallel < 1 || *parallel > 200 || *hold < 0 || uint64(queued) > 4<<20 || len(specs) == 0 || (queued > 0 && *target == "") {
		fmt.Fprintln(os.Stderr, "load: invalid sessions, parallel, hold, carrier, queued or target value")
		os.Exit(2)
	}
	var dialers []carrier.Dialer
	for _, spec := range specs {
		d, err := carrier.Parse(spec)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		dialers = append(dialers, d)
	}
	held := make([]heldSession, *count)
	jobs := make(chan int)
	errs := make(chan error, *count)
	var workers sync.WaitGroup
	for range *parallel {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range jobs {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				client, err := lanes.Dial(ctx, lanes.Config{Carriers: dialers})
				cancel()
				if err != nil {
					errs <- fmt.Errorf("session %d: %w", i, err)
					continue
				}
				h := heldSession{client: client}
				if queued > 0 {
					h.mux, err = mux.Client(client.Session())
					if err == nil {
						h.stream, err = mux.Open(h.mux, *target)
					}
					if err == nil {
						var request [16]byte
						binary.BigEndian.PutUint64(request[:8], uint64(queued))
						_ = h.stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
						_, err = h.stream.Write(request[:])
						_ = h.stream.SetWriteDeadline(time.Time{})
					}
				}
				if err != nil {
					h.close()
					errs <- fmt.Errorf("session %d: %w", i, err)
					continue
				}
				held[i] = h
			}
		}()
	}
	for i := range *count {
		jobs <- i
	}
	close(jobs)
	workers.Wait()
	close(errs)
	var failures []error
	for err := range errs {
		failures = append(failures, err)
	}
	active := *count - len(failures)
	fmt.Printf("load: %d/%d sessions open, %d queued bytes requested each; holding for %v\n", active, *count, queued, *hold)
	if active > 0 {
		time.Sleep(*hold)
	}
	var closing sync.WaitGroup
	for i := range held {
		closing.Add(1)
		go func(h *heldSession) {
			defer closing.Done()
			h.close()
		}(&held[i])
	}
	closing.Wait()
	if len(failures) > 0 {
		fmt.Fprintln(os.Stderr, errors.Join(failures...))
		os.Exit(1)
	}
}
