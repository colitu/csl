package engine

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestProtocolRankingVectors sends every ranking vector through the line
// protocol (the way the apps call the sidecar) and checks the answer.
func TestProtocolRankingVectors(t *testing.T) {
	var v rankingVectors
	loadVectors(t, "ranking.json", &v)
	for _, c := range v.Cases {
		in := map[string]any{"now_ms": v.NowMs, "network": v.Network, "client_country": c.ClientCountry}
		if c.LastGood != nil {
			in["last_good"] = *c.LastGood
		}
		servers := []map[string]any{}
		for _, s := range c.Servers {
			m := map[string]any{"id": s.ID, "country": s.Country}
			if s.Available != nil {
				m["available"] = *s.Available
			}
			servers = append(servers, m)
		}
		in["servers"] = servers
		pings := map[string]any{}
		for id, p := range c.Pings {
			pings[id] = map[string]any{"ms": p.Ms, "at_ms": v.NowMs - p.AgeS*1000, "network": p.Network}
		}
		in["pings"] = pings
		penalized := []map[string]any{}
		for _, p := range c.Penalized {
			penalized = append(penalized, map[string]any{"id": p.ID, "at_ms": v.NowMs - p.AgeS*1000})
		}
		in["penalized"] = penalized
		raw, _ := json.Marshal(in)
		resp := Handle(Request{ID: 7, Op: "rank", In: raw})
		if resp.Error != "" || resp.ID != 7 {
			t.Fatalf("%s: error %q id %d", c.Name, resp.Error, resp.ID)
		}
		if !reflect.DeepEqual(resp.Out, c.Expect) {
			t.Errorf("%s: expected %v, got %v", c.Name, c.Expect, resp.Out)
		}
	}
}

func TestProtocolErrors(t *testing.T) {
	if resp := Handle(Request{ID: 1, Op: "nope"}); resp.Error == "" {
		t.Fatal("unknown op must be an error")
	}
	if resp := Handle(Request{ID: 2, Op: "rank", In: json.RawMessage(`{"servers":5}`)}); resp.Error == "" {
		t.Fatal("bad input must be an error")
	}
	if resp := Handle(Request{ID: 3, Op: "hinted_start", In: json.RawMessage(`{"offered":["trojan"],"preferred":[],"stalled":[]}`)}); resp.Out != nil || resp.Error != "" {
		t.Fatalf("no hint: null out, got %v %q", resp.Out, resp.Error)
	}
}
