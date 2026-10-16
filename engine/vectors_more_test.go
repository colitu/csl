package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func loadVectors(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "ac-vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}

func TestTransportVectors(t *testing.T) {
	var v struct {
		BaseOrder []struct {
			Name             string
			Offered, Stalled []string
			Expect           []string
		} `json:"base_order"`
		HintedStart []struct {
			Name                        string
			Offered, Preferred, Stalled []string
			LastGood                    *string `json:"last_good"`
			Expect                      []string
		} `json:"hinted_start"`
		MarksIgnored []struct {
			Name             string
			Offered, Stalled []string
			Expect           bool
		} `json:"marks_ignored"`
	}
	loadVectors(t, "transport.json", &v)
	for _, c := range v.BaseOrder {
		if got := BaseOrder(c.Offered, c.Stalled); !reflect.DeepEqual(got, c.Expect) {
			t.Errorf("base_order %s: expected %v, got %v", c.Name, c.Expect, got)
		}
	}
	for _, c := range v.HintedStart {
		lastGood := ""
		if c.LastGood != nil {
			lastGood = *c.LastGood
		}
		if got := HintedStart(c.Offered, c.Preferred, c.Stalled, lastGood); !reflect.DeepEqual(got, c.Expect) {
			t.Errorf("hinted_start %s: expected %v, got %v", c.Name, c.Expect, got)
		}
	}
	for _, c := range v.MarksIgnored {
		if got := MarksIgnored(c.Offered, c.Stalled); got != c.Expect {
			t.Errorf("marks_ignored %s: expected %v, got %v", c.Name, c.Expect, got)
		}
	}
}

func TestHintsVectors(t *testing.T) {
	var v struct {
		Parse []struct {
			Name               string
			Blocked, Preferred []any
			RawExpectBlocked   []string `json:"expect_blocked"`
			RawExpectPreferred []string `json:"expect_preferred"`
		} `json:"parse"`
	}
	loadVectors(t, "hints.json", &v)
	for _, c := range v.Parse {
		blocked, preferred := ParseHints(c.Blocked, c.Preferred)
		if !reflect.DeepEqual(blocked, c.RawExpectBlocked) || !reflect.DeepEqual(preferred, c.RawExpectPreferred) {
			t.Errorf("parse %s: expected %v / %v, got %v / %v", c.Name, c.RawExpectBlocked, c.RawExpectPreferred, blocked, preferred)
		}
	}
}

func TestRecoveryVectors(t *testing.T) {
	var v struct {
		Now    time.Time `json:"now"`
		Decide []struct {
			Name                                                      string
			Automatic, Multihop, ApiUnreachable, CacheUsable, Expired bool
			Expect                                                    string
		} `json:"decide"`
		RefreshDue []struct {
			Name            string
			GeneratedAgeMin *float64 `json:"generated_age_min"`
			AttemptAgeMin   *float64 `json:"attempt_age_min"`
			Expect          bool
		} `json:"refresh_due"`
		SetParse []struct {
			Name          string
			GeneratedAt   *string   `json:"generated_at"`
			RecoveryUntil *string   `json:"recovery_until"`
			Servers       []*string `json:"servers"`
			Expect        []string
		} `json:"set_parse"`
		NextServer []struct {
			Name            string
			Servers, Failed []string
			Expect          *string
		} `json:"next_server"`
	}
	loadVectors(t, "recovery.json", &v)
	// Field names with underscores need explicit tags; decode those again.
	var raw struct {
		Decide []struct {
			ApiUnreachable bool `json:"api_unreachable"`
			CacheUsable    bool `json:"cache_usable"`
		} `json:"decide"`
	}
	loadVectors(t, "recovery.json", &raw)
	for i, c := range v.Decide {
		got := DecideRecovery(c.Automatic, c.Multihop, raw.Decide[i].ApiUnreachable, raw.Decide[i].CacheUsable, c.Expired)
		if string(got) != c.Expect {
			t.Errorf("decide %s: expected %s, got %s", c.Name, c.Expect, got)
		}
	}
	at := func(ageMin *float64) *time.Time {
		if ageMin == nil {
			return nil
		}
		ts := v.Now.Add(-time.Duration(*ageMin * float64(time.Minute)))
		return &ts
	}
	for _, c := range v.RefreshDue {
		if got := RecoveryRefreshDue(at(c.GeneratedAgeMin), at(c.AttemptAgeMin), v.Now); got != c.Expect {
			t.Errorf("refresh_due %s: expected %v, got %v", c.Name, c.Expect, got)
		}
	}
	for _, c := range v.SetParse {
		var got []string
		_, errG := parseTime(c.GeneratedAt)
		_, errU := parseTime(c.RecoveryUntil)
		if errG == nil && errU == nil {
			var ids []string
			for _, s := range c.Servers {
				if s == nil {
					ids = append(ids, "")
				} else {
					ids = append(ids, *s)
				}
			}
			got = RecoveryServers(ids)
		}
		if !reflect.DeepEqual(got, c.Expect) {
			t.Errorf("set_parse %s: expected %v, got %v", c.Name, c.Expect, got)
		}
	}
	for _, c := range v.NextServer {
		want := ""
		if c.Expect != nil {
			want = *c.Expect
		}
		if got := RecoveryNext(c.Servers, c.Failed); got != want {
			t.Errorf("next_server %s: expected %q, got %q", c.Name, want, got)
		}
	}
}

func parseTime(s *string) (time.Time, error) {
	if s == nil {
		return time.Time{}, os.ErrNotExist
	}
	return time.Parse(time.RFC3339, *s)
}
