# Changelog

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
