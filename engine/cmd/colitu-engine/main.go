// Command colitu-engine runs the Adaptive Connect decision engine as a small
// sidecar of the Colitu apps: one JSON request per line on stdin, one JSON
// response per line on stdout (engine.Request / engine.Response). It needs no
// network, keeps no state and exits when stdin closes.
package main

import (
	"bufio"
	"encoding/json"
	"os"

	"github.com/colitu/csl/engine"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 64*1024), 4*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(out)
	for in.Scan() {
		var req engine.Request
		var resp engine.Response
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			resp = engine.Response{Error: "bad request: " + err.Error()}
		} else {
			resp = engine.Handle(req)
		}
		if err := enc.Encode(resp); err != nil {
			os.Exit(1)
		}
		if err := out.Flush(); err != nil {
			os.Exit(1)
		}
	}
}
