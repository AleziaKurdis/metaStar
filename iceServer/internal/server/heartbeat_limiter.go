package server

import (
	"sync"
	"time"
)

const (
	heartbeatDenialRate  = 50.0
	heartbeatDenialBurst = 100.0
)

// heartbeatDenialLimiter bounds outbound replies to unauthenticated heartbeats
// for unknown domain UUIDs. It is deliberately global rather than per source
// IP: legitimate domains may share a NAT address, and unknown UUIDs are not
// authenticated identities that can safely key per-domain quotas.
type heartbeatDenialLimiter struct {
	mu      sync.Mutex
	tokens  float64
	updated time.Time
}

func newHeartbeatDenialLimiter(now time.Time) *heartbeatDenialLimiter {
	return &heartbeatDenialLimiter{tokens: heartbeatDenialBurst, updated: now}
}

func (l *heartbeatDenialLimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if elapsed := now.Sub(l.updated).Seconds(); elapsed > 0 {
		l.tokens += elapsed * heartbeatDenialRate
		if l.tokens > heartbeatDenialBurst {
			l.tokens = heartbeatDenialBurst
		}
		l.updated = now
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
