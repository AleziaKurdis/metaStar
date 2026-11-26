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

### Unreliable sequence numbers

Overte's `udt::Socket::writePacket()` increments `_unreliableSequenceNumbers[sockAddr]` before sending. The map is keyed by destination `SockAddr`, and a default-constructed `SequenceNumber` starts at zero, so the first outgoing packet to a destination uses sequence **1**. All outgoing unreliable packet types sent to that same destination share the counter; another destination starts its own counter at **1**.

The sequence field is 27 bits (`0x07FFFFFF`). Overte's `SequenceNumber::operator++()` wraps from `0x07FFFFFF` to `0`. The Go sender mirrors this with a counter per destination UDP address, shared by ACK, denial and peer-information responses. Regression tests cover the initial value, counter sharing, destination separation and wraparound.

The sequence field is written as a little-endian 32-bit word on the supported little-endian Overte hosts. For ICE's unreliable, unfragmented, unobfuscated data packets, all five flag bits above bit 26 remain clear. The Go decoder rejects frames with any of those flags set. It also rejects complete UDP payloads larger than 2,048 bytes. The socket receive loop uses a buffer large enough for the maximum UDP payload before applying that limit; this avoids accepting a valid-looking prefix of a datagram silently truncated by a smaller receive buffer. The limit is intentionally generous relative to the source-reviewed ICE heartbeat, query and peer-information payloads.

### Why a full reliable UDT implementation is not required for this ICE subset

The inspected send paths create/send ICE heartbeats, queries, ACK/denial responses and peer-information responses as unreliable, unfragmented, unobfuscated packets:

- Domain Server heartbeat: `NLPacket::create(PacketType::ICEServerHeartbeat)` and `sendUnreliablePacket()`.
- ICE client query: `NLPacket::create(packetType)` followed by `_socket->writePacket(*icePacket, ...)`; the default packet is unreliable and not fragmented.
- ICE Server ACK/denial: `NLPacket::create(...)` and `writePacket(...)`.
- ICE Server peer information: `NLPacket::create(PacketType::ICEServerPeerInformation)` and `writePacket(...)`.

The UDT socket sends control packets through its own internal control-packet path; those packets are not delivered to the ICE application packet callback. This means the Go implementation only needs the exact unreliable ICE data-frame subset, not Overte's entire reliable transport implementation. The Go decoder rejects control, reliable, fragmented and obfuscated frames rather than misinterpreting them.

This conclusion is based on the reviewed call sites. It should still be verified with real packet captures from Overte binaries.

## Heartbeat payload and public-key bootstrap

The Domain Server writes a Qt `QDataStream` payload containing:

1. Domain UUID
2. Public `SockAddr` (QHostAddress + port)
3. Local `SockAddr` (QHostAddress + port)
4. Signature as a `QByteArray`

The signature covers the serialized bytes of items 1–3, before the signature byte-array field. The original ICE Server verifies RSA/SHA-256. When the key is missing, it requests the public key from the owning Directory Service and denies that heartbeat; a subsequent heartbeat can succeed after the key has been loaded. If a cached key fails signature verification, the original ICE Server requests the key again and denies the heartbeat while the replacement key is fetched.

MetaStar now follows the same response semantics: a heartbeat with no cached key, or one that fails verification against the cached key, receives `ICEServerHeartbeatDenied` while the asynchronous key lookup or refresh runs. The domain is not admitted or updated in the peer registry until a later heartbeat verifies successfully with the fetched key. This behavior is covered by server tests. It remains subject to live confirmation against unmodified Overte binaries.

MetaStar deduplicates concurrent key refresh requests and applies retry backoff after failed Directory Service lookups.

## Qt SockAddr wire serialization

Overte's `SockAddr.cpp` defines its stream operators as:

- write: `dataStream << sockAddr._address << sockAddr._port`
- read: `dataStream >> sockAddr._address >> sockAddr._port`

The socket type is deliberately omitted from ICE packets.

Qt's `QHostAddress` QDataStream operator serializes the network-layer protocol as a signed byte. For IPv4 it then writes the address as a 32-bit integer; for IPv6 it writes the 16 address octets followed by the scope ID as a `QString`. The `SockAddr` operator then writes the port as a 16-bit integer. QDataStream's default byte order is big-endian.

The Go reader follows that layout:

| Address kind | Serialized fields |
|---|---|
| IPv4 | protocol byte `0`, IPv4 `quint32`, port `quint16` |
| IPv6 | protocol byte `1`, 16 address bytes, scope `QString`, port `quint16` |
| Any | protocol byte `2`, port `quint16` |
| Unknown | protocol byte `255` (signed `qint8` value `-1`), port `quint16` |

The Go reader retains the original serialized SockAddr bytes when building peer-information packets, rather than re-encoding them from a display string. IPv6 scope strings are decoded as UTF-16, including surrogate pairs.

MetaStar accepts unspecified addresses and port zero because the Domain Server starts its ICE heartbeat timer immediately while STUN public-socket discovery is still in progress; an early heartbeat can therefore contain an endpoint placeholder. It rejects multicast and IPv4 limited-broadcast addresses in either advertised socket. Those destinations cannot identify an individual peer and should not be relayed to other Overte clients. This is an additional MetaStar input-safety check; it does not alter the serialized format or require client changes. Directed IPv4 broadcast addresses cannot be identified without the sender's subnet mask and are not claimed to be covered.

Regression fixtures cover IPv4, scoped IPv6, a Unicode surrogate pair in a QString, unspecified startup endpoints, multicast/broadcast rejection, and malformed/truncated address data. These are source-derived wire-format fixtures, not captures from a live Overte process.

Relevant Qt serialization references:
- [Qt 6 QHostAddress stream operator source](https://codebrowser.dev/qt6/qtbase/src/network/kernel/qhostaddress.cpp.html)
- [Qt 6 QDataStream default byte order](https://doc.qt.io/qt-6/qdatastream.html)

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

## Active peer socket and NAT rebinding

The original ICE server activates the socket that actually delivered the latest valid heartbeat:

1. It calls `activateMatchingOrNewSymmetricSocket(nlPacket->getSenderSockAddr())`.
2. If the observed sender address matches the peer's advertised public socket, that socket becomes active.
3. If it matches the advertised local socket, the local socket becomes active.
4. Otherwise, the observed sender address is stored as the symmetric socket and becomes active.

When another peer asks for this peer, the ICE server sends the requester's peer information to the target peer's active socket. The Go implementation represents this active destination as the `Observed` source address from the most recent valid heartbeat.

A regression test now models a target peer sending heartbeats from one UDP source endpoint and then a new endpoint (simulating a changed NAT mapping). A separate requester queries the target. The test verifies that:

- the requester receives the target's advertised public and local addresses;
- the target's newest observed endpoint receives the requester's advertised addresses; and
- the superseded endpoint does not receive the reverse peer-information packet.

This exercises the two-way ICE introduction behavior at the local UDP socket level. It does not prove that real Internet NATs will permit the resulting hole punch; that still requires live network testing.

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


## Domain public-key parameters

The current Overte Domain Server generates 2048-bit RSA keypairs with public
exponent 65537. MetaStar accepts Directory Service public keys only with those
parameters, for both PKIX and PKCS#1 DER encodings. This matches the upstream
generator and prevents a trusted Directory Service response from introducing
unexpectedly weak or excessively expensive RSA verification keys. If upstream
Overte changes its key-generation parameters, this compatibility check must be
reviewed alongside that change.


## Public-key fetch concurrency

Heartbeat-triggered Directory Service public-key retrieval is asynchronous and
deduplicated per domain. The ICE service also caps all simultaneous key fetches
at 32, bounding the number of lookup goroutines and outbound HTTPS requests.
When all slots are occupied, a new lookup is not marked pending; the domain's
next heartbeat can retry. This limit is global across enrolled directories and
does not use source IP, so domains behind the same NAT do not share a
per-address quota. It can delay key bootstrap during a large simultaneous
reconnect or key-rotation event; the limit should be reviewed against observed
deployment scale and Directory Service capacity.
