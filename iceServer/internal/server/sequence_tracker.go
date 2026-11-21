package server

import (
	"sync"
	"time"
)

const (
	sequenceStateTTL   = 2 * time.Minute
	sequenceMaxTargets = 8192
	sequenceMask       = (1 << 27) - 1
)

type destinationSequence struct {
	lastSent time.Time
	sequence uint32
}

type sequenceTracker struct {
	mu           sync.Mutex
	destinations map[string]destinationSequence
}

func newSequenceTracker() *sequenceTracker {
	return &sequenceTracker{destinations: make(map[string]destinationSequence)}
}

// next reserves the next unreliable sequence number for a destination.
// It never evicts a live destination: if the bounded map is full and no
// entries have expired, a new destination is rejected instead.
func (t *sequenceTracker) next(destination string, now time.Time) (uint32, bool) {
	if destination == "" {
		return 0, false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	state, exists := t.destinations[destination]
	if !exists {
		if len(t.destinations) >= sequenceMaxTargets {
			for key, candidate := range t.destinations {
				if now.Sub(candidate.lastSent) > sequenceStateTTL {
					delete(t.destinations, key)
				}
			}
			if len(t.destinations) >= sequenceMaxTargets {
				return 0, false
			}
		}
		state = destinationSequence{sequence: 1, lastSent: now}
		t.destinations[destination] = state
		return state.sequence, true
	}

	state.sequence = (state.sequence + 1) & sequenceMask
	state.lastSent = now
	t.destinations[destination] = state
	return state.sequence, true
}
