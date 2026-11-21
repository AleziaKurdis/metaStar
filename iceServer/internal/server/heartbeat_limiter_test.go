package server

import (
	"testing"
	"time"
)

func TestHeartbeatDenialLimiterAllowsBurstThenRefills(t *testing.T) {
	now := time.Unix(1000, 0)
	limiter := newHeartbeatDenialLimiter(now)

	for i := 0; i < int(heartbeatDenialBurst); i++ {
		if !limiter.allow(now) {
			t.Fatalf("denial response %d in initial burst was rejected", i+1)
		}
	}
	if limiter.allow(now) {
		t.Fatal("response beyond burst was allowed")
	}
	if !limiter.allow(now.Add(20 * time.Millisecond)) {
		t.Fatal("one token should refill after 20ms")
	}
	if limiter.allow(now.Add(20 * time.Millisecond)) {
		t.Fatal("response without another refill was allowed")
	}
}

func TestHeartbeatDenialLimiterCapsRefill(t *testing.T) {
	now := time.Unix(2000, 0)
	limiter := newHeartbeatDenialLimiter(now)

	if !limiter.allow(now.Add(24 * time.Hour)) {
		t.Fatal("limiter should permit a response after a long idle period")
	}
	for i := 1; i < int(heartbeatDenialBurst); i++ {
		if !limiter.allow(now.Add(24 * time.Hour)) {
			t.Fatalf("response %d within refilled burst was rejected", i+1)
		}
	}
	if limiter.allow(now.Add(24 * time.Hour)) {
		t.Fatal("refill exceeded configured burst")
	}
}
