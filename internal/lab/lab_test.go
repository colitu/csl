package lab

import (
	"testing"
	"time"
)

func TestScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("lab scenarios take ~20 s")
	}
	opts := Options{Size: 24 << 20, Rate: 8 << 20, Outage: 3 * time.Second, Logf: t.Logf}
	for _, sc := range Scenarios() {
		t.Run(sc.Name, func(t *testing.T) {
			o := opts
			o.Logf = t.Logf
			r := sc.Run(o)
			t.Logf("%s: %s | %s | switches %v", r.Name, r.Verdict, r.Download, r.Switches)
			if !r.Pass {
				t.Fatal(r.Verdict)
			}
		})
	}
}
