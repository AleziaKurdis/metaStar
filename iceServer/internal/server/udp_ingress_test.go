package server

import (
	"bytes"
	"net"
	"testing"
)

func TestEnqueueDatagramIsBoundedOrderedAndOwnsItsData(t *testing.T) {
	queue := make(chan inboundDatagram, 2)
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 7337}

	first := []byte{1, 2, 3}
	if !enqueueDatagram(queue, first, addr) {
		t.Fatal("first datagram was rejected")
	}
	first[0] = 99
	addr.IP[0] = 198
	addr.Port = 9999

	second := []byte{4, 5, 6}
	if !enqueueDatagram(queue, second, &net.UDPAddr{IP: net.ParseIP("192.0.2.20"), Port: 7338}) {
		t.Fatal("second datagram was rejected")
	}
	if enqueueDatagram(queue, []byte{7, 8, 9}, &net.UDPAddr{IP: net.ParseIP("192.0.2.30"), Port: 7339}) {
		t.Fatal("datagram beyond queue capacity was accepted")
	}
	if got := len(queue); got != cap(queue) {
		t.Fatalf("queue length = %d, want bounded capacity %d", got, cap(queue))
	}

	gotFirst := <-queue
	if !bytes.Equal(gotFirst.data, []byte{1, 2, 3}) {
		t.Fatalf("first queued payload changed after source mutation: %v", gotFirst.data)
	}
	if gotFirst.addr.IP.String() != "192.0.2.10" || gotFirst.addr.Port != 7337 {
		t.Fatalf("first queued address changed after source mutation: %v", gotFirst.addr)
	}

	gotSecond := <-queue
	if !bytes.Equal(gotSecond.data, second) {
		t.Fatalf("queue order or second payload mismatch: %v", gotSecond.data)
	}
	if gotSecond.addr.IP.String() != "192.0.2.20" || gotSecond.addr.Port != 7338 {
		t.Fatalf("second queued address mismatch: %v", gotSecond.addr)
	}
}
