# Changelog

## 0.3.10-dev

- Cool down successful public-key refreshes triggered by invalid heartbeat signatures, limiting repeated Directory Service fetches to one per domain every 30 seconds.
- Keep initial missing-key retrieval and failed-fetch exponential backoff behavior unchanged.
- Bind cooldown state to the owning Directory Service and clear it when domain ownership changes.
- Add regression coverage for repeated refresh suppression and cooldown expiry.

## 0.3.9-dev

- Decouple UDP socket reception from packet handling with a bounded 256-datagram FIFO queue and one consumer, preserving packet processing order.
- Reject malformed, unsupported, and wrong-version frames before queue admission.
- Apply query rate limiting and unknown-domain heartbeat denial handling at ingress so those floods do not occupy the processing queue.
- Drop newest packets when the queue is full rather than spawning unbounded goroutines or allocating an unbounded backlog.
- Add tests for queue capacity, FIFO ordering, and ownership of copied packet/address data.

## 0.3.8-dev

- Bound outbound denial responses for syntactically valid heartbeats from unknown domain UUIDs with a process-wide token bucket (50 responses/second, burst of 100).
- Keep registered-domain heartbeat ACKs outside the denial budget so legitimate domains sharing a NAT are not penalized.
- Added deterministic limiter tests and documented that this controls response amplification, not inbound packet-processing cost.

## 0.3.7-dev

- Added a dependency-free packet capture inspection command for UDP payloads exported by tshark.
- Report decoded UDT sequence numbers, known ICE packet types, observed and expected versions, and payload lengths.
- Added automated checks for malformed frames, unsupported UDT flags, and packet-version mismatches.
- Documented a safe live-capture procedure and explicit interoperability test matrix; no live Overte interoperability is claimed.

## 0.3.6-dev

- Roll back in-memory directory ownership and credentials when the atomic registry-file save fails.
- Persist a new Directory Service registration and its credential hash in a single write, preventing partial enrollment.
- Added failure-path tests for failed registration updates and failed first-time enrollment.

## 0.3.5-dev

- Evict active peers immediately when Directory Service enrollment or synchronization changes their UUID ownership.
- Serialize heartbeat acceptance and peer queries against ownership updates to prevent stale peers being reintroduced or returned during synchronization.
- Discard an in-flight public-key response if the domain's Directory Service owner or base URL changed while the request was running.
- Added handler-level tests for domain removal and first-time ownership assignment.

## 0.3.4-dev

- Documented Overte's per-destination unreliable UDT sequence-number behavior.
- Added regression tests for first sequence value, counter sharing across packet types, independent destination counters and 27-bit wraparound.
- Confirmed the ICE sender leaves the UDT control, reliable, message and obfuscation flags clear.

## 0.3.3-dev

- Added two-peer UDP exchange coverage for both directions of ICE peer-information delivery.
- Verified that a changed NAT source endpoint learned from a newer valid heartbeat becomes the destination for reverse peer-information delivery.
- Documented the Go observed-address behavior against the original C++ active-socket selection.

## 0.3.2-dev

- Added source-derived Qt QHostAddress/SockAddr wire fixtures for IPv4 and scoped IPv6.
- Decode Qt QString values as UTF-16, including surrogate pairs, for IPv6 scope IDs.
- Documented the exact QHostAddress and SockAddr QDataStream field order and byte order.

## 0.3.1-dev

- Corrected all five Go ICE packet type identifiers to the zero-based values in Overte's `PacketTypeEnum::Value`.
- Refresh the cached Domain Server public key after a heartbeat signature failure, matching the original ICE server's key-rotation behavior.
- Added numeric golden tests and an Overte heartbeat datagram wire-layout fixture so packet type drift cannot be hidden by tests that reuse implementation constants.
- Documented the exact unreliable, unfragmented, unobfuscated UDP data-frame subset used by ICE and the source paths supporting it.
- Clarified that this implementation does not implement Overte's full reliable UDT transport; the reviewed ICE message paths use unreliable packets.

## 0.3.0-dev

- Introduced shared bootstrap enrollment secret and per-directory issued credentials.
- Removed per-directory installer prompt and manual token mapping.
- Allowed zero-domain enrollment and subsequent sync.
- Organized project as `metaStar/iceServer` alongside PHP `metaStar/directoryServer`.
- Preserved existing ICE packet implementation from 0.2.0-dev for interoperability testing.
