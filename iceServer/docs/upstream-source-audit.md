# Upstream Overte ICE source audit baseline

This audit is pinned to the Overte source tree at commit
[`f788e8faa27189c33c8a5da2d47f9f55915abcb7`](https://github.com/overte-org/overte/commit/f788e8faa27189c33c8a5da2d47f9f55915abcb7)
(`master` at the time of review). Re-run this comparison when updating the
supported Overte source baseline; do not treat a moving branch name as a
reproducible protocol reference.

## Source-to-implementation traceability

| Overte source | Contract established by source | MetaStar implementation / coverage |
|---|---|---|
| `ice-server/src/IceServer.cpp` | Heartbeat verification, query routing, ACK/denial behavior, peer-information delivery, five-second peer expiry | `internal/server/server.go`; server and peer-routing tests |
| `libraries/networking/src/NetworkPeer.cpp` | Peer-information payload order is UUID, public socket, local socket; observed heartbeat socket becomes active | `internal/protocol/ice.go`; peer-routing test |
| `libraries/networking/src/SockAddr.cpp` | ICE socket serialization excludes socket type and writes QHostAddress followed by port | `internal/qtstream/reader.go`; Qt stream fixtures |
| `libraries/networking/src/udt/PacketHeaders.cpp` | ICE packet IDs and packet versions | `internal/protocol/packet.go`; packet identifier/version tests |
| `libraries/networking/src/udt/Packet.cpp` | UDT data header flags and sequence-number bit layout | `internal/protocol/packet.go`; datagram framing tests |
| `libraries/networking/src/udt/Socket.cpp` | Unreliable sequence counter is per destination and shared across packet types | `internal/server/server.go`; sequence tests and peer-routing integration test |
| `libraries/networking/src/LimitedNodeList.cpp` | ICE query payload order and unreliable packet send path | `internal/protocol/ice.go`; query parsing and peer-routing tests |
| `domain-server/src/DomainServer.cpp` | Heartbeat contains UUID and both sockets, signed before appending the signature; sent unreliably once per second | `internal/protocol/ice.go`; signed-heartbeat tests |
| `tools/ice-client/src/ICEClientApp.cpp` | Client sends the same query structure and consumes peer-information packets | Query/peer-information source review; client live test remains outstanding |

## Wire-level assertions

The server integration tests assert the exact packet type, packet version,
sequence number and payload for the two-way peer-information exchange. They
also assert that an unregistered domain receives a correctly versioned
heartbeat-denial packet.

In particular, the current observed endpoint first receives a heartbeat ACK
(sequence 1), then receives peer information (sequence 2). This checks that
MetaStar shares its outgoing unreliable sequence counter across packet types
for the same destination, as Overte does. A different destination starts at
sequence 1.

## Scope and limits

This is a source-derived compatibility audit, not a packet capture and not a
live interoperability result. The Go server implements the unreliable,
unfragmented, unobfuscated data-frame subset used by the inspected ICE
application packet paths. It does not implement Overte's full reliable UDT
transport.

The source review does not validate:
- behavior of a compiled, unmodified Overte Domain Server or ICE client;
- real Internet NAT mapping and hole-punch behavior;
- platform/build variations outside the reviewed source baseline;
- future changes to Overte's packet definitions or ICE call paths.

Those remain explicit release-validation gates. Do not describe MetaStar as
end-to-end compatible until those tests have been run.
