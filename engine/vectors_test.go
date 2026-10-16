package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type rankingVectors struct {
	NowMs   int64  `json:"now_ms"`
	Network string `json:"network"`
	Cases   []struct {
		Name          string  `json:"name"`
		ClientCountry string  `json:"client_country"`
		LastGood      *string `json:"last_good"`
		Servers       []struct {
			ID        string `json:"id"`
			Country   string `json:"country"`
			Available *bool  `json:"available"`
		} `json:"servers"`
		Pings map[string]struct {
			Ms      *int   `json:"ms"`
			AgeS    int64  `json:"age_s"`
			Network string `json:"network"`
		} `json:"pings"`
		Penalized []struct {
			ID   string `json:"id"`
			AgeS int64  `json:"age_s"`
		} `json:"penalized"`
		Expect []string `json:"expect"`
	} `json:"cases"`
}

// TestRankingVectors runs the shared vectors the four apps run too.
func TestRankingVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "ac-vectors", "ranking.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v rankingVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(v.NowMs)
	for _, c := range v.Cases {
		in := RankInput{Network: v.Network, ClientCountry: c.ClientCountry, Now: now, Pings: map[string]Ping{}, PenalizedAt: map[string]time.Time{}}
		if c.LastGood != nil {
			in.LastGood = *c.LastGood
		}
		for _, s := range c.Servers {
			in.Servers = append(in.Servers, Server{ID: s.ID, Country: s.Country, Available: s.Available == nil || *s.Available})
		}
		for id, p := range c.Pings {
			network := p.Network
			if network == "" {
				network = v.Network
			}
			in.Pings[id] = Ping{Ms: p.Ms, At: now.Add(-time.Duration(p.AgeS) * time.Second), Network: network}
		}
		for _, p := range c.Penalized {
			in.PenalizedAt[p.ID] = now.Add(-time.Duration(p.AgeS) * time.Second)
		}
		var got []string
		for _, s := range Rank(in) {
			got = append(got, s.ID)
		}
		if strings.Join(got, ",") != strings.Join(c.Expect, ",") {
			t.Errorf("%s: expected %v, got %v", c.Name, c.Expect, got)
		}
	}
}
