# Heartbeat denial response budget

## Scope

Overte Domain Servers send signed ICE heartbeats periodically (the reviewed upstream behavior is approximately once per second). Heartbeats for registered domains must continue to receive the normal ACK behavior, including while a public key is being fetched or refreshed.

A heartbeat containing a syntactically valid but unregistered domain UUID is different: the UUID is not authenticated, and replying with a denial packet lets an unauthenticated sender cause outbound UDP traffic.

## Mitigation

MetaStar applies one process-wide token bucket only to denial responses for unknown domain UUIDs:

- Refill rate: 50 denial responses per second.
- Initial burst: 100 denial responses.
- Once depleted, additional unknown-domain heartbeats are silently ignored until tokens refill.
- The limiter is global, not per source IP, source port, or claimed domain UUID.

This bounds the ICE service's outbound denial traffic independently of attacker-controlled source identifiers. It avoids penalizing legitimate domains behind a shared NAT: registered-domain ACKs are not subject to this limiter.

The limiter is applied after packet framing and heartbeat parsing and after the registry lookup identifies an unknown UUID. It therefore does not eliminate the CPU cost of receiving, decoding, parsing, and looking up every incoming datagram. Network-layer filtering and host-level DDoS protection remain necessary for volumetric floods.

## Compatibility

No packet fields, packet identifiers, versions, sequence rules, heartbeat cadence, or registered-domain ACK behavior are changed. Only excess denial replies for unknown UUIDs are suppressed. This is intentionally a server-side abuse control compatible with unmodified clients and Domain Servers.

## Limits

The budget is per ICE process, not distributed across multiple ICE instances. It limits response amplification, not inbound bandwidth or all packet-processing work. A flood can still consume network and parsing resources before reaching the denial decision. Production deployments should use upstream network filtering and monitor real denial traffic before tuning the defaults.


## Public-key refresh amplification

A registered-domain heartbeat with an invalid signature can indicate that the Domain Server rotated its RSA keypair. MetaStar therefore retains the compatibility behavior of fetching a replacement public key from the Directory Service. However, a peer repeatedly sending invalid signatures for the same registered UUID could otherwise trigger a new outbound HTTPS lookup after every successful refresh.

After a successful refresh initiated by an invalid signature, MetaStar applies a 30-second cooldown for that domain and Directory Service owner. Repeated invalid signatures during that window are still handled with the normal heartbeat ACK behavior, but do not trigger another key fetch. Initial lookups for domains with no cached key are not delayed, and failed fetches continue to use the existing exponential retry backoff. A changed Directory Service owner clears the cooldown.

This is a per-domain refresh-work limit, not a heartbeat rate limit. It does not affect the normal one-second heartbeat cadence or penalize other domains sharing the same source IP. A legitimate subsequent key rotation inside the cooldown window may take up to 30 seconds to trigger another refresh.
