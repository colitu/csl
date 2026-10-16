package engine

import (
	"encoding/json"
	"fmt"
	"time"
)

// ProtocolVersion is the version of the line protocol of cmd/colitu-engine.
const ProtocolVersion = 1

// Request is one line on the engine's stdin: {"id":1,"op":"rank","in":{...}}.
type Request struct {
	ID int64           `json:"id"`
	Op string          `json:"op"`
	In json.RawMessage `json:"in"`
}

// Response is one line on its stdout: {"id":1,"out":...} or {"id":1,"error":"..."}.
type Response struct {
	ID    int64  `json:"id"`
	Out   any    `json:"out"`
	Error string `json:"error,omitempty"`
}

type rankIn struct {
	NowMs         int64  `json:"now_ms"`
	Network       string `json:"network"`
	ClientCountry string `json:"client_country"`
	LastGood      string `json:"last_good"`
	Servers       []struct {
		ID        string `json:"id"`
		Country   string `json:"country"`
		Available *bool  `json:"available"`
		Multihop  bool   `json:"multihop"`
	} `json:"servers"`
	Pings map[string]struct {
		Ms      *int   `json:"ms"`
		AtMs    int64  `json:"at_ms"`
		Network string `json:"network"`
	} `json:"pings"`
	Penalized []struct {
		ID   string `json:"id"`
		AtMs int64  `json:"at_ms"`
	} `json:"penalized"`
}

type offeredIn struct {
	Offered   []string `json:"offered"`
	Preferred []string `json:"preferred"`
	Stalled   []string `json:"stalled"`
	LastGood  string   `json:"last_good"`
}

// Handle answers one request. Unknown ops and bad input are errors, never panics.
func Handle(req Request) (resp Response) {
	resp.ID = req.ID
	defer func() {
		if r := recover(); r != nil {
			resp.Out, resp.Error = nil, fmt.Sprint("internal error: ", r)
		}
	}()
	decode := func(v any) bool {
		if len(req.In) == 0 {
			return true
		}
		if err := json.Unmarshal(req.In, v); err != nil {
			resp.Error = "bad input: " + err.Error()
			return false
		}
		return true
	}
	ms := func(v int64) time.Time { return time.UnixMilli(v) }
	switch req.Op {
	case "version":
		resp.Out = map[string]any{"protocol": ProtocolVersion, "ops": []string{"version", "rank", "base_order", "hinted_start", "marks_ignored", "parse_hints", "recovery_decide", "recovery_refresh_due", "recovery_servers", "recovery_next"}}
	case "rank":
		var in rankIn
		if !decode(&in) {
			return
		}
		ri := RankInput{Network: in.Network, ClientCountry: in.ClientCountry, LastGood: in.LastGood, Now: ms(in.NowMs),
			Pings: map[string]Ping{}, PenalizedAt: map[string]time.Time{}}
		for _, s := range in.Servers {
			ri.Servers = append(ri.Servers, Server{ID: s.ID, Country: s.Country, Available: s.Available == nil || *s.Available, Multihop: s.Multihop})
		}
		for id, p := range in.Pings {
			network := p.Network
			if network == "" {
				network = in.Network
			}
			ri.Pings[id] = Ping{Ms: p.Ms, At: ms(p.AtMs), Network: network}
		}
		for _, p := range in.Penalized {
			ri.PenalizedAt[p.ID] = ms(p.AtMs)
		}
		ids := []string{}
		for _, s := range Rank(ri) {
			ids = append(ids, s.ID)
		}
		resp.Out = ids
	case "base_order":
		var in offeredIn
		if decode(&in) {
			resp.Out = nonNil(BaseOrder(in.Offered, in.Stalled))
		}
	case "hinted_start":
		var in offeredIn
		if decode(&in) {
			if order := HintedStart(in.Offered, in.Preferred, in.Stalled, in.LastGood); order != nil {
				resp.Out = order
			}
		}
	case "marks_ignored":
		var in offeredIn
		if decode(&in) {
			resp.Out = MarksIgnored(in.Offered, in.Stalled)
		}
	case "parse_hints":
		var in struct {
			Blocked   []any `json:"blocked"`
			Preferred []any `json:"preferred"`
		}
		if decode(&in) {
			blocked, preferred := ParseHints(in.Blocked, in.Preferred)
			resp.Out = map[string][]string{"blocked": blocked, "preferred": preferred}
		}
	case "recovery_decide":
		var in struct {
			Automatic      bool `json:"automatic"`
			Multihop       bool `json:"multihop"`
			APIUnreachable bool `json:"api_unreachable"`
			CacheUsable    bool `json:"cache_usable"`
			Expired        bool `json:"expired"`
		}
		if decode(&in) {
			resp.Out = string(DecideRecovery(in.Automatic, in.Multihop, in.APIUnreachable, in.CacheUsable, in.Expired))
		}
	case "recovery_refresh_due":
		var in struct {
			NowMs         int64  `json:"now_ms"`
			GeneratedAtMs *int64 `json:"generated_at_ms"`
			AttemptMs     *int64 `json:"last_attempt_ms"`
		}
		if decode(&in) {
			var generated, attempt *time.Time
			if in.GeneratedAtMs != nil {
				t := ms(*in.GeneratedAtMs)
				generated = &t
			}
			if in.AttemptMs != nil {
				t := ms(*in.AttemptMs)
				attempt = &t
			}
			resp.Out = RecoveryRefreshDue(generated, attempt, ms(in.NowMs))
		}
	case "recovery_servers":
		var in struct {
			IDs []string `json:"ids"`
		}
		if decode(&in) {
			if out := RecoveryServers(in.IDs); out != nil {
				resp.Out = out
			}
		}
	case "recovery_next":
		var in struct {
			Servers []string `json:"servers"`
			Failed  []string `json:"failed"`
		}
		if decode(&in) {
			if next := RecoveryNext(in.Servers, in.Failed); next != "" {
				resp.Out = next
			}
		}
	default:
		resp.Error = "unknown op: " + req.Op
	}
	return resp
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
