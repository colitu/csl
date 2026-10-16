package engine

import (
	"sort"
	"strings"
)

// transportPreference is the order transports are tried in when nothing
// else is known; anything else goes after them.
var transportPreference = map[string]int{
	"hysteria2":     0,
	"vless-reality": 1,
	"vless-xhttp":   2,
	"trojan":        3,
	"shadowsocks":   4,
}

const unknownTransport = 5

func preferenceOf(protocol string) int {
	if rank, ok := transportPreference[protocol]; ok {
		return rank
	}
	return unknownTransport
}

func setOf(items []string) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, item := range items {
		out[item] = true
	}
	return out
}

// BaseOrder orders the offered transports by preference, the stalled ones
// after every unstalled one; the offered order breaks ties.
func BaseOrder(offered, stalled []string) []string {
	marked := setOf(stalled)
	out := append([]string(nil), offered...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := preferenceOf(out[i]), preferenceOf(out[j])
		if marked[out[i]] {
			a += 10
		}
		if marked[out[j]] {
			b += 10
		}
		return a < b
	})
	return out
}

// HintedStart is the start order from the network hints (AC 3.0) when this
// device has no last good transport here: the preferred transports that are
// offered and not stalled, in the hint's order, then the rest in BaseOrder.
// Nil when the device has its own experience, the hint is empty or nothing
// of it is usable: the usual probe and ranking decide.
func HintedStart(offered, preferred, stalled []string, lastGood string) []string {
	if lastGood != "" || len(preferred) == 0 {
		return nil
	}
	on := setOf(offered)
	marked := setOf(stalled)
	var first []string
	taken := map[string]bool{}
	for _, p := range preferred {
		if on[p] && !marked[p] && !taken[p] {
			first = append(first, p)
			taken[p] = true
		}
	}
	if len(first) == 0 {
		return nil
	}
	var rest []string
	for _, p := range offered {
		if !taken[p] {
			rest = append(rest, p)
		}
	}
	return append(first, BaseOrder(rest, stalled)...)
}

// MarksIgnored: stall marks that leave at most one of two or more offered
// transports describe the network, not the transports; the round ignores them.
func MarksIgnored(offered, stalled []string) bool {
	on := setOf(offered)
	if len(on) < 2 {
		return false
	}
	marked := setOf(stalled)
	unmarked := 0
	for p := range on {
		if !marked[p] {
			unmarked++
		}
	}
	return unmarked <= 1
}

// ParseProtocols normalizes a protocol list of the network hints: strings
// only, trimmed, lowercase, no empties or duplicates, in the given order.
func ParseProtocols(raw []any) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, item := range raw {
		s, ok := item.(string)
		if !ok {
			continue
		}
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ParseHints returns the blocked and preferred lists of network_hints;
// preferred never contains a blocked protocol.
func ParseHints(blocked, preferred []any) (blockedOut, preferredOut []string) {
	blockedOut = ParseProtocols(blocked)
	no := setOf(blockedOut)
	preferredOut = []string{}
	for _, p := range ParseProtocols(preferred) {
		if !no[p] {
			preferredOut = append(preferredOut, p)
		}
	}
	return blockedOut, preferredOut
}
