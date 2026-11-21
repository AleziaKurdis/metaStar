package server

import (
	"net"
	"sync"
	"time"
)

const (
	queryRatePerSecond = 10.0
	queryBurst         = 30.0
	queryStateTTL      = 2 * time.Minute
	queryMaxSources    = 4096
)

type queryBucket struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

// queryLimiter bounds unauthenticated ICE query relay work by observed source
// IP. The map is capped and idle entries are reclaimed when capacity is needed.
type queryLimiter struct {
	mu      sync.Mutex
	sources map[string]queryBucket
}

func newQueryLimiter() *queryLimiter {
	return &queryLimiter{sources: make(map[string]queryBucket)}
}

func (l *queryLimiter) allow(addr *net.UDPAddr, now time.Time) bool {
	if addr == nil || addr.IP == nil {
		return false
	}
	ip := addr.IP.String()

	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, exists := l.sources[ip]
	if !exists {
		if len(l.sources) >= queryMaxSources {
			for source, stale := range l.sources {
				if now.Sub(stale.lastSeen) > queryStateTTL {
					delete(l.sources, source)
				}
			}
			if len(l.sources) >= queryMaxSources {
				// Do not grow attacker-controlled state without a bound.
				return false
			}
		}
		bucket = queryBucket{tokens: queryBurst, updated: now, lastSeen: now}
	} else {
		if elapsed := now.Sub(bucket.updated).Seconds(); elapsed > 0 {
			bucket.tokens += elapsed * queryRatePerSecond
			if bucket.tokens > queryBurst {
				bucket.tokens = queryBurst
			}
			bucket.updated = now
		}
		bucket.lastSeen = now
	}

	if bucket.tokens < 1 {
		l.sources[ip] = bucket
		return false
	}
	bucket.tokens--
	bucket.lastSeen = now
	l.sources[ip] = bucket
	return true
}