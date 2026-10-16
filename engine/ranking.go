// Package engine is the Adaptive Connect decision engine: the choices every
// Colitu app makes the same way (which server first, which transport first,
// when to give up on a server), written once. The apps run the same test
// vectors (testdata/ac-vectors) against their own code until they call this
// package instead.
package engine

import (
	"sort"
	"strings"
	"time"
)

const (
	// PingFresh: a ping is believed this long, on the network it was taken on.
	PingFresh = 10 * time.Minute
	// PingUsable: a successful ping still orders the servers this long on its
	// network (after a wake-up or a network change the panel order can put a
	// far server first). A failed ping is only believed while fresh.
	PingUsable = 6 * time.Hour
	// MemoryBeatenFraction and MemoryBeatenMs: the last good server yields to a
	// candidate of the same standing at least this much faster, both.
	MemoryBeatenFraction = 0.4
	MemoryBeatenMs       = 60
)

// AutoExcludedCountries are never picked automatically: a Russian exit carries
// the same blocks the user wants to get away from. A manual pick still works.
var AutoExcludedCountries = map[string]bool{"RU": true}

// HomePushbackCountries: clients in these countries get servers in their own
// country after the foreign ones (such a server cannot open what is blocked
// there). Elsewhere a home-country server competes on latency.
var HomePushbackCountries = map[string]bool{
	"RU": true, "BY": true, "KZ": true, "UZ": true, "TM": true, "TJ": true, "KG": true, "AZ": true, "IR": true,
	"CN": true, "TR": true, "VN": true, "PK": true, "EG": true, "SA": true, "AE": true, "ET": true, "MM": true,
}

// Server is one location of the panel's list, in the panel's order.
type Server struct {
	ID        string
	Country   string
	Available bool
	Multihop  bool
}

// Ping is one latency measurement; Ms nil means it failed.
type Ping struct {
	Ms      *int
	At      time.Time
	Network string
}

func (p Ping) age(now time.Time) (time.Duration, bool) {
	age := now.Sub(p.At)
	return age, age >= 0
}

func (p Ping) fresh(network string, now time.Time) bool {
	age, ok := p.age(now)
	return ok && p.Network == network && age < PingFresh
}

func (p Ping) usable(network string, now time.Time) bool {
	age, ok := p.age(now)
	return ok && p.Ms != nil && p.Network == network && age < PingUsable
}

// RankInput is what automatic mode knows when it orders the servers.
type RankInput struct {
	Servers       []Server
	Pings         map[string]Ping
	Network       string
	LastGood      string
	PenalizedAt   map[string]time.Time
	ClientCountry string
	Now           time.Time
}

// Rank returns the servers automatic mode tries, best first:
//  1. penalized on this network last, the oldest penalty first;
//  2. a fresh failed ping after the rest;
//  3. own-country servers after foreign ones, only in HomePushbackCountries;
//  4. the last good server first, unless a candidate of the same standing
//     with a usable ping is MemoryBeatenFraction and MemoryBeatenMs faster;
//  5. usable successful pings, fastest first;
//  6. the rest in panel order.
//
// Multihop routes, unavailable servers and AutoExcludedCountries are left out.
func Rank(in RankInput) []Server {
	country := strings.ToUpper(strings.TrimSpace(in.ClientCountry))
	pushHome := len(country) == 2 && HomePushbackCountries[country]

	type row struct {
		server     Server
		index      int
		penalized  bool
		penaltyAt  time.Time
		failedPing bool
		home       bool
		ms         *int
		lastGood   bool
	}
	var rows []row
	for i, s := range in.Servers {
		code := strings.ToUpper(strings.TrimSpace(s.Country))
		if !s.Available || s.Multihop || AutoExcludedCountries[code] {
			continue
		}
		r := row{server: s, index: i, lastGood: in.LastGood != "" && s.ID == in.LastGood}
		r.penaltyAt, r.penalized = in.PenalizedAt[s.ID]
		if p, ok := in.Pings[s.ID]; ok {
			r.failedPing = p.Ms == nil && p.fresh(in.Network, in.Now)
			if p.usable(in.Network, in.Now) {
				r.ms = p.Ms
			}
		}
		r.home = pushHome && code == country
		rows = append(rows, r)
	}

	sameStanding := func(a, b row) bool {
		return a.penalized == b.penalized && a.failedPing == b.failedPing && a.home == b.home
	}
	memoryBeaten := false
	for _, remembered := range rows {
		if !remembered.lastGood || remembered.ms == nil {
			continue
		}
		rm := *remembered.ms
		for _, other := range rows {
			if other.lastGood || other.ms == nil || !sameStanding(other, remembered) {
				continue
			}
			ms := *other.ms
			if rm-ms >= MemoryBeatenMs && float64(ms) <= float64(rm)*(1-MemoryBeatenFraction) {
				memoryBeaten = true
			}
		}
	}

	key := func(r row) (b1 int, pen int64, b2, b3, b4 int, ms int, idx int) {
		ms = int(^uint(0) >> 1)
		if r.ms != nil {
			ms = *r.ms
		}
		if r.penalized {
			b1, pen = 1, r.penaltyAt.UnixNano()
		}
		if r.failedPing {
			b2 = 1
		}
		if r.home {
			b3 = 1
		}
		if memoryBeaten || !r.lastGood {
			b4 = 1
		}
		return b1, pen, b2, b3, b4, ms, r.index
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a1, ap, a2, a3, a4, ams, ai := key(rows[i])
		b1, bp, b2, b3, b4, bms, bi := key(rows[j])
		switch {
		case a1 != b1:
			return a1 < b1
		case ap != bp:
			return ap < bp
		case a2 != b2:
			return a2 < b2
		case a3 != b3:
			return a3 < b3
		case a4 != b4:
			return a4 < b4
		case ams != bms:
			return ams < bms
		default:
			return ai < bi
		}
	})
	out := make([]Server, len(rows))
	for i, r := range rows {
		out[i] = r.server
	}
	return out
}
