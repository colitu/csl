// Command cslbench measures CSL.
//
//	cslbench lab [-run kill,blackhole] [-size 64MiB] [-rate 16MiB] [-outage 10s] [-json out.json]
//	    runs the G1 scenarios in one process (no network needed)
//
//	cslbench source -listen 127.0.0.1:9500
//	    serves verified pattern downloads (run it next to csl-server)
//
//	cslbench get -socks 127.0.0.1:1080 -target 127.0.0.1:9500 [-size 64MiB] [-rate 0]
//	    downloads through a SOCKS5 proxy (csl-client, or Xray for a baseline)
//
//	cslbench load -carrier tcp://127.0.0.1:9440#A -sessions 100 -hold 30s
//	    holds many CSL sessions open for memory and admission measurements
//	    and checks every byte; -direct skips the proxy for a baseline
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/colitu/csl/internal/bench"
	"github.com/colitu/csl/internal/lab"
	"github.com/colitu/csl/internal/socks5"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "lab":
		runLab(os.Args[2:])
	case "source":
		runSource(os.Args[2:])
	case "get":
		runGet(os.Args[2:])
	case "load":
		runLoad(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: cslbench lab|source|get|load [flags]   (cslbench <cmd> -h for flags)")
	os.Exit(2)
}

// sizeFlag parses sizes such as 64MiB, 512KiB, 1GiB or plain bytes.
type sizeFlag uint64

func (s *sizeFlag) String() string { return strconv.FormatUint(uint64(*s), 10) }
func (s *sizeFlag) Set(v string) error {
	mult := uint64(1)
	for suffix, m := range map[string]uint64{"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "KB": 1e3, "MB": 1e6, "GB": 1e9} {
		if strings.HasSuffix(v, suffix) {
			mult = m
			v = strings.TrimSuffix(v, suffix)
			break
		}
	}
	n, err := strconv.ParseUint(v, 10, 64)
	*s = sizeFlag(n * mult)
	return err
}

func runLab(args []string) {
	fs := flag.NewFlagSet("lab", flag.ExitOnError)
	run := fs.String("run", "", "comma-separated scenarios (default: all)")
	size, rate := sizeFlag(64<<20), sizeFlag(16<<20)
	fs.Var(&size, "size", "bytes per download")
	fs.Var(&rate, "rate", "source rate in bytes per second")
	outage := fs.Duration("outage", 10*time.Second, "length of the outage scenario")
	jsonOut := fs.String("json", "", "write results as JSON to this file")
	verbose := fs.Bool("v", false, "log carrier events")
	fs.Parse(args)

	opts := lab.Options{Size: uint64(size), Rate: uint64(rate), Outage: *outage}
	if *verbose {
		opts.Logf = func(f string, a ...any) { fmt.Printf(f+"\n", a...) }
	}
	scenarios := lab.Scenarios()
	if *run != "" {
		scenarios = nil
		for _, name := range strings.Split(*run, ",") {
			sc, err := lab.Find(strings.TrimSpace(name))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			scenarios = append(scenarios, sc)
		}
	}

	var results []lab.Result
	failed := 0
	for _, sc := range scenarios {
		fmt.Printf("== %s: %s\n", sc.Name, sc.About)
		r := sc.Run(opts)
		r.About = sc.About
		mark := "PASS"
		if !r.Pass {
			mark = "FAIL"
			failed++
		}
		fmt.Printf("   %s  %s\n   %s, switches %v\n", mark, r.Verdict, r.Download, r.Switches)
		results = append(results, r)
	}
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(map[string]any{
			"when":      time.Now().UTC().Format(time.RFC3339),
			"gate":      map[string]any{"max_stall_ns": lab.MaxStall, "max_throughput_loss": lab.MaxThroughLoss},
			"scenarios": results,
		}, "", "  ")
		if err := os.WriteFile(*jsonOut, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	fmt.Printf("\n%d/%d scenarios passed\n", len(results)-failed, len(results))
	if failed > 0 {
		os.Exit(1)
	}
}

func runSource(args []string) {
	fs := flag.NewFlagSet("source", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:9500", "address to serve downloads on")
	fs.Parse(args)
	s, err := bench.StartSource(*listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("cslbench source on %s\n", s.Addr())
	select {}
}

func runGet(args []string) {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	proxy := fs.String("socks", "127.0.0.1:1080", "SOCKS5 proxy to download through")
	target := fs.String("target", "127.0.0.1:9500", "cslbench source address, as seen from the server")
	size, rate := sizeFlag(64<<20), sizeFlag(0)
	fs.Var(&size, "size", "bytes to download")
	fs.Var(&rate, "rate", "source rate in bytes per second (0 = unlimited)")
	timeout := fs.Duration("timeout", 10*time.Minute, "give up after this long")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	direct := fs.Bool("direct", false, "connect to -target directly, without the proxy (baseline)")
	fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	var conn net.Conn
	var err error
	if *direct {
		var d net.Dialer
		conn, err = d.DialContext(ctx, "tcp", *target)
	} else {
		conn, err = socks5.Dial(ctx, *proxy, *target, nil)
	}
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(*timeout))
	r := bench.Download(conn, uint64(size), uint64(rate))
	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(r)
	} else {
		fmt.Println(r)
	}
	if !r.OK {
		os.Exit(1)
	}
}
