package engine

import "time"

const (
	// RecoveryMaxServers: a recovery set holds at most this many servers.
	RecoveryMaxServers = 4
	// RecoveryRefreshAfter: a stored set this old is fetched again...
	RecoveryRefreshAfter = 24 * time.Hour
	// RecoveryAttemptEvery: ...but at most once in this time, success or not.
	RecoveryAttemptEvery = 6 * time.Hour
	// clockSkew: a generated_at this far in the future means the clock moved back.
	clockSkew = 5 * time.Minute
)

// RecoveryDecision is what a failed automatic connect does with the set.
type RecoveryDecision string

const (
	RecoveryNone    RecoveryDecision = "none"
	RecoveryExpired RecoveryDecision = "expired"
	RecoveryUse     RecoveryDecision = "use"
)

// DecideRecovery: the set takes over only in automatic mode (never for a
// multihop route), when every API base failed without an HTTP answer and the
// regular cached config cannot connect; an expired set is deleted instead.
func DecideRecovery(automatic, multihop, apiUnreachable, cacheUsable, expired bool) RecoveryDecision {
	if !automatic || multihop || !apiUnreachable || cacheUsable {
		return RecoveryNone
	}
	if expired {
		return RecoveryExpired
	}
	return RecoveryUse
}

// RecoveryRefreshDue: fetch when nothing is stored or the stored set is
// RecoveryRefreshAfter old (or dated in the future: the clock moved back),
// and the last attempt is RecoveryAttemptEvery back. An attempt dated in the
// future is ignored.
func RecoveryRefreshDue(generatedAt, lastAttempt *time.Time, now time.Time) bool {
	if lastAttempt != nil && !lastAttempt.After(now) && now.Sub(*lastAttempt) < RecoveryAttemptEvery {
		return false
	}
	if generatedAt == nil {
		return true
	}
	if generatedAt.Sub(now) > clockSkew {
		return true
	}
	return now.Sub(*generatedAt) >= RecoveryRefreshAfter
}

// RecoveryServers keeps the usable server ids of a set in its order: no
// empties, no duplicates, at most RecoveryMaxServers. Nil when none is left.
func RecoveryServers(ids []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
		if len(out) == RecoveryMaxServers {
			break
		}
	}
	return out
}

// RecoveryNext is the first server of the set that did not fail in this
// connect; "" when every one failed.
func RecoveryNext(servers, failed []string) string {
	no := setOf(failed)
	for _, s := range servers {
		if !no[s] {
			return s
		}
	}
	return ""
}
