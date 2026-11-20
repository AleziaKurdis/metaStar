# Protocol notes from the supplied Overte source

This document records a source-level audit of the ICE packet path. It is not a substitute for live interoperability testing against an unmodified Overte Domain Server and client.

## Source files reviewed

- `ice-server/src/IceServer.cpp` and `ice-server/src/IceServer.h`
- `domain-server/src/DomainServer.cpp`
- `libraries/networking/src/NLPacket.cpp` and `NLPacket.h`
- `libraries/networking/src/NetworkPeer.cpp`
- `libraries/networking/src/SockAddr.cpp` and `SockAddr.h`
- `libraries/networking/src/udt/Packet.cpp`, `PacketHeaders.h`, `PacketHeaders.cpp`, `Socket.cpp`, and `ControlPacket.cpp`
- `tools/ice-client/src/ICEClientApp.cpp`

## Packet identifiers and versions

The numeric packet types are the zero-based values of `PacketTypeEnum::Value` in `PacketHeaders.h`. The prior Go prototype had incorrectly set each ICE packet type one value too high; this has been corrected and is covered by numeric golden tests.

| Packet | Type | Version |
|---|---:|---:|
| ICEServerPeerInformation | 22 | 17 |
| ICEServerQuery | 23 | 17 |
| ICEServerHeartbeat | 38 | 18 |
| ICEServerHeartbeatDenied | 60 | 17 |
| ICEServerHeartbeatACK | 63 | 17 |

The versions are confirmed by `versionForPacketType()` in `PacketHeaders.cpp`.

## UDP framing used by ICE

Overte's `udt::Socket` binds an underlying UDP socket. Its `udt::Packet` data-frame header begins with a 32-bit host-order bitfield. The supported Overte hosts targeted here are little-endian, so the Go implementation currently decodes that field as little-endian.

The 32-bit word contains:

- bit 31: control packet
- bit 30: reliable packet
- bit 29: message-fragment packet
- bits 27–28: obfuscation level
- bits 0–26: sequence number

For an unfragmented ICE data packet, the first four bytes are followed by the one-byte network packet type and one-byte version. ICE packet types are in `getNonSourcedPackets()`, so they have no local-node-ID or MD5-verification fields in the NLPacket header.

### Why a full reliable UDT implementation is not required for this ICE subset

The inspected send paths create/send ICE heartbeats, queries, ACK/denial responses and peer-information responses as unreliable, unfragmented, unobfuscated packets:

- Domain Server heartbeat: `NLPacket::create(PacketType::ICEServerHeartbeat)` and `sendUnreliablePacket()`.
- ICE client query: `NLPacket::create(packetType)` followed by `_socket->writePacket(*icePacket, ...)`; the default packet is unreliable and not fragmented.
- ICE Server ACK/denial: `NLPacket::create(...)` and `writePacket(...)`.
- ICE Server peer information: `NLPacket::create(PacketType::ICEServerPeerInformation)` and `writePacket(...)`.

The UDT socket sends control packets through its own internal control-packet path; those packets are not delivered to the ICE application packet callback. This means the Go implementation only needs the exact unreliable ICE data-frame subset, not Overte's entire reliable transport implementation. The Go decoder rejects control, reliable, fragmented and obfuscated frames rather than misinterpreting them.

This conclusion is based on the reviewed call sites. It should still be verified with real packet captures from Overte binaries.

## Heartbeat payload

The Domain Server writes a Qt `QDataStream` payload containing:

1. Domain UUID
2. Public `SockAddr` (QHostAddress + port)
3. Local `SockAddr` (QHostAddress + port)
4. Signature as a `QByteArray`

The signature covers the serialized bytes of items 1–3, before the signature byte-array field. The original ICE Server verifies RSA/SHA-256. When the key is missing, it requests the public key from the directory API and denies that heartbeat; a subsequent heartbeat can succeed after the key has been loaded.

## Query and peer-information payloads

Query payload:

1. Requesting peer UUID
2. Requesting peer public `SockAddr`
3. Requesting peer local `SockAddr`
4. Target peer UUID

Peer-information payload:

1. Peer UUID
2. Peer public `SockAddr`
3. Peer local `SockAddr`

The original ICE server sends the target peer's information to the requester and the requester's information to the target peer's active socket.

## Multi-directory routing

The existing heartbeat and query packet formats do not carry a Directory Service identifier. Therefore a shared ICE service needs a trusted registry mapping each Domain UUID to the Directory Service that owns it. The ICE service uses that mapping to retrieve the domain's public key from the correct Directory Service.

## Timing

The source clears inactive peers every second and removes a peer after five seconds without a heartbeat.

## Remaining validation

Source review confirms the packet type/version values and the data-frame layout used by ICE. It does **not** prove that the current Go implementation interoperates end-to-end. Remaining checks include:

- Compare captured Overte heartbeat/query datagrams with Go decoder fixtures.
- Verify Qt QDataStream serialization using captured IPv4 and IPv6 socket payloads.
- Run the Go service against an unmodified Domain Server and ICE client.
- Verify both directions of peer-information exchange and NAT hole punching.
