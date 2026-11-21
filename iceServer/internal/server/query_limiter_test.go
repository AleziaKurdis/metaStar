package server

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestQueryLimiterAllowsBurstThenRefills(t *testing.T) {
	limiter := newQueryLimiter()
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 40000}
	now := time.Unix(1000, 0)

	for i := 0; i < int(queryBurst); i++ {
		if !limiter.allow(addr, now) {
			t.Fatalf("query %d in initial burst was unexpectedly rejected", i+1)
		}
	}
	if limiter.allow(addr, now) {
		t.Fatal("query beyond burst was allowed")
	}
	if !limiter.allow(addr, now.Add(100*time.Millisecond)) {
		t.Fatal("one token should have refilled after 100ms")
	}
	if limiter.allow(addr, now.Add(100*time.Millisecond)) {
		t.Fatal("second query without refill was allowed")
	}
}

func TestQueryLimiterIsPerSourceIPNotPort(t *testing.T) {
	limiter := newQueryLimiter()
	now := time.Unix(2000, 0)
	first := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 10000}
	secondPort := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 20000}
	otherIP := &net.UDPAddr{IP: net.ParseIP("198.51.100.21"), Port: 10000}

	for i := 0; i < int(queryBurst); i++ {
		if !limiter.allow(first, now) {
			t.Fatalf("query %d was unexpectedly rejected", i+1)
		}
	}
	if limiter.allow(secondPort, now) {
		t.Fatal("changing the UDP source port bypassed the per-IP limit")
	}
	if !limiter.allow(otherIP, now) {
		t.Fatal("a different source IP should have an independent bucket")
	}
}

func TestQueryLimiterBoundsAndReclaimsSourceState(t *testing.T) {
	limiter := newQueryLimiter()
	now := time.Unix(3000, 0)
	for i := 0; i < queryMaxSources; i++ {
		ip := net.ParseIP(fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255))
		if !limiter.allow(&net.UDPAddr{IP: ip, Port: 1000}, now) {
			t.Fatalf("source %d was unexpectedly rejected", i)
		}
	}
	newSource := &net.UDPAddr{IP: net.ParseIP("203.0.113.250"), Port: 1000}
	if limiter.allow(newSource, now) {
		t.Fatal("new source should be rejected while the bounded map is full")
	}
	if !limiter.allow(newSource, now.Add(queryStateTTL+time.Second)) {
		t.Fatal("stale source entries should be reclaimed")
	}
	if got := len(limiter.sources); got > queryMaxSources {
		t.Fatalf("source state grew to %d entries, limit is %d", got, queryMaxSources)
	}
}

func TestQueryLimiterRejectsMissingSource(t *testing.T) {
	limiter := newQueryLimiter()
	if limiter.allow(nil, time.Now()) {
		t.Fatal("nil source address was allowed")
	}
	if limiter.allow(&net.UDPAddr{}, time.Now()) {
		t.Fatal("source without an IP was allowed")
	}
}