# Protocol notes from the supplied Overte source

Reviewed source files:

- `ice-server/src/IceServer.cpp`
- `ice-server/src/IceServer.h`
- `libraries/networking/src/udt/Packet.cpp`
- `libraries/networking/src/udt/Socket.cpp`
- `libraries/networking/src/udt/PacketHeaders.h`
- `libraries/networking/src/udt/PacketHeaders.cpp`
- `libraries/networking/src/NLPacket.cpp`
- `libraries/networking/src/NetworkPeer.cpp`
- `libraries/networking/src/SockAddr.cpp`
- `domain-server/src/DomainServer.cpp`
- `libraries/networking/src/LimitedNodeList.cpp`

## UDT envelope

The UDP datagram starts with a 32-bit little-endian word. This is Overte’s own UDT packet envelope (a custom transport in the Overte networking library), not a claim that the standard UDT library or its stream mode is being used. The control bit is bit 31; reliable is bit 30; message-fragment is bit 29; obfuscation occupies bits 27–28; the low 27 bits are the sequence number. The ICE heartbeat/query path uses unfragmented, unreliable, unobfuscated data packets. The next two bytes are the network packet type and version.

Packet identifiers from the enum in the supplied source:

| Packet | Type | Version |
|---|---:|---:|
| ICEServerPeerInformation | 23 | 17 |
| ICEServerQuery | 24 | 17 |
| ICEServerHeartbeat | 39 | 18 |
| ICEServerHeartbeatDenied | 61 | 17 |
| ICEServerHeartbeatACK | 64 | 17 |

ICE packets are marked non-sourced and non-verified, so their NLPacket local header is just the one-byte type and one-byte version after the four-byte UDT header.

## Heartbeat payload

The Domain Server writes a Qt data stream containing:

1. Domain UUID
2. public SockAddr (QHostAddress + port)
3. local SockAddr (QHostAddress + port)
4. QByteArray signature

The signature covers the serialized bytes of items 1–3, before the QByteArray signature field. The source verifies RSA/SHA-256 using the public key fetched from the directory API. The source denies the first heartbeat when it has to fetch a missing key; a later heartbeat can be accepted after the key is cached.

## Query payload and peer information

Query payload: sender UUID, sender public SockAddr, sender local SockAddr, target UUID.

Peer information payload: peer UUID, public SockAddr, local SockAddr. The ICE server sends the target peer's information to the requester and the requester's information to the target peer's active observed address.

## Multi-directory routing

The existing heartbeat/query packet format does not carry a Directory Service identifier. Therefore the ICE service must first maintain a trusted registry mapping each Domain UUID to the Directory Service that owns it. The registration API in this milestone provides that mapping. The ICE service then fetches that UUID's public key from the owning Directory Service.

## Timing

The inspected source clears inactive peers every second and removes a peer after five seconds without a heartbeat.
