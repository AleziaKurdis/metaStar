# UDP ingress queue and overload behavior

## Processing model

The ICE UDP socket reader and packet processor are decoupled by a bounded in-memory queue.

- The queue holds at most 256 datagrams.
- Exactly one worker consumes the queue. It processes packets in receive order, preserving heartbeat ordering and the latest observed NAT endpoint behavior.
- Datagrams are copied into queue-owned buffers and address values; the reusable socket read buffer is never shared with the worker.
- If the queue is full, the newest datagram is dropped. The server does not create a goroutine per packet or grow the queue dynamically.
- Oversized, malformed, unsupported, and wrong-version datagrams are rejected before queue admission.
- Query payloads are parsed and the existing per-source-IP query limiter is applied at ingress, before queue admission.
- Heartbeats for unknown domain UUIDs are handled at ingress under the separate global denial-response budget. They do not occupy worker queue capacity.

## Compatibility choices

A single consumer is intentional. Multiple packet workers could complete signature verification out of order and allow an older heartbeat to overwrite a newer observed public endpoint. The queue changes neither the Overte wire protocol nor the normal heartbeat cadence. Registered-domain heartbeat verification and ACK behavior remain in the existing packet handler.

## Overload behavior and limits

The queue absorbs short processing bursts while keeping memory bounded. Under sustained load, packets are dropped once the queue is full; the newest packet is dropped and already queued packets retain FIFO order.

This is not a complete DDoS defense. A sustained flood of syntactically valid heartbeats claiming registered UUIDs can still consume signature-verification time and queue capacity. The ingress queue bounds memory and prevents socket reception from being synchronously blocked by one verification, but it cannot create additional CPU capacity. Use host/network firewalling and upstream DDoS mitigation for volumetric attacks. Monitor real traffic before changing the queue capacity.

## Validation

Unit tests verify the queue's fixed capacity, FIFO ordering, and ownership of copied payload/address data. The Go race-enabled test suite should be run in CI and on the deployment build before release.
