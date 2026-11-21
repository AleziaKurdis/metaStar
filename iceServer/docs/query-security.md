# ICE query security and compatibility

## What the current protocol permits

The reviewed upstream Overte ICE implementation accepts an ICE query containing a sender UUID, public socket, local socket, and target UUID. The query does not carry a client credential or signature. The original ICE server looks up the requested active peer, returns that peer's information to the UDP source address, and forwards the query's claimed sender UUID and sockets to the target peer.

MetaStar cannot reliably authenticate that claimed client identity from this packet alone. Requiring a new token, signature, or registered-client identity would change the wire contract and would prevent unmodified Overte clients from using the service. PR #23 therefore does not claim to solve query identity spoofing.

## Compatibility-preserving mitigation

MetaStar limits query relay work using the source IP observed by the UDP socket:

- Refill rate: 10 query packets per second per source IP.
- Initial burst: 30 query packets.
- Source-state cap: 4,096 IP addresses.
- Idle source entries are reclaimed after two minutes when capacity is needed.
- Different UDP source ports behind the same public IP share one bucket.

The limit is applied only after a query has passed packet framing, version, and Qt payload parsing. It does not alter any packet, response, sequence number, or client behavior below the configured threshold.

The per-IP policy intentionally prevents trivial source-port rotation from bypassing the limit. It also means many clients behind one NAT share a bucket; the defaults should be reviewed against real deployment traffic before production use.

## Remaining limitations

This is an abuse-control measure, not authentication. It does not prevent:

- a distributed flood spread across many source IPs;
- spoofed-source traffic where the network permits source-IP spoofing;
- a client from claiming another UUID or arbitrary public/local sockets below the rate limit;
- an attacker from targeting a known active peer with allowed-rate queries.

A stronger identity guarantee requires a future protocol extension or a client-supported authentication mechanism. That work must be designed with the Overte client and Domain Server protocol owners and validated against unmodified-client compatibility; the ICE server cannot safely invent that contract unilaterally.

## Source reference

The behavior described above was checked against the pinned upstream source baseline in upstream-source-audit.md, specifically ice-server/src/IceServer.cpp at commit f788e8faa27189c33c8a5da2d47f9f55915abcb7.