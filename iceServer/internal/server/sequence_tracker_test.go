package server

import (
	"fmt"
	"testing"
	"time"
)

func TestSequenceTrackerUsesIndependentPerDestinationCounters(t *testing.T) {
	tracker := newSequenceTracker()
	now := time.Unix(1000, 0)

	if got, ok := tracker.next("192.0.2.1:1000", now); !ok || got != 1 {
		t.Fatalf("first sequence = %d, %v; want 1, true", got, ok)
	}
	if got, ok := tracker.next("192.0.2.1:1000", now); !ok || got != 2 {
		t.Fatalf("second sequence = %d, %v; want 2, true", got, ok)
	}
	if got, ok := tracker.next("192.0.2.1:2000", now); !ok || got != 1 {
		t.Fatalf("different destination sequence = %d, %v; want 1, true", got, ok)
	}
}

func TestSequenceTrackerWrapsAt27Bits(t *testing.T) {
	tracker := newSequenceTracker()
	now := time.Unix(2000, 0)
	tracker.destinations["192.0.2.2:1000"] = destinationSequence{
		sequence: sequenceMask,
		lastSent: now,
	}

	if got, ok := tracker.next("192.0.2.2:1000", now); !ok || got != 0 {
		t.Fatalf("sequence after wrap = %d, %v; want 0, true", got, ok)
	}
}

func TestSequenceTrackerReclaimsOnlyExpiredDestinations(t *testing.T) {
	tracker := newSequenceTracker()
	now := time.Unix(3000, 0)
	for i := 0; i < sequenceMaxTargets; i++ {
		key := fmt.Sprintf("192.0.%d.%d:1000", (i>>8)&255, i&255)
		tracker.destinations[key] = destinationSequence{sequence: 7, lastSent: now}
	}

	// A live map at capacity rejects a new destination instead of evicting
	// an active counter and causing a future sequence reset.
	if _, ok := tracker.next("203.0.113.1:1000", now); ok {
		t.Fatal("new destination should be rejected while all tracked entries are live")
	}

	// Refresh one existing destination near the expiry boundary; it must
	// survive reclamation while older destinations are removed.
	protected := "192.0.0.1:1000"
	tracker.destinations[protected] = destinationSequence{sequence: 19, lastSent: now.Add(time.Minute)}
	later := now.Add(sequenceStateTTL + time.Second)
	if got, ok := tracker.next("203.0.113.1:1000", later); !ok || got != 1 {
		t.Fatalf("new destination after expiry = %d, %v; want 1, true", got, ok)
	}
	if got, ok := tracker.next(protected, later); !ok || got != 20 {
		t.Fatalf("protected destination sequence = %d, %v; want 20, true", got, ok)
	}
	if len(tracker.destinations) > sequenceMaxTargets {
		t.Fatalf("tracked %d destinations; limit is %d", len(tracker.destinations), sequenceMaxTargets)
	}
}

func TestSequenceTrackerRejectsEmptyDestination(t *testing.T) {
	tracker := newSequenceTracker()
	if _, ok := tracker.next("", time.Now()); ok {
		t.Fatal("empty destination should be rejected")
	}
}
