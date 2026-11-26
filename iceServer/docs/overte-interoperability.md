# Live Overte ICE interoperability capture procedure

This procedure prepares a reproducible comparison between the Go ICE service and unmodified Overte binaries. It does **not** claim that live interoperability has already been demonstrated. The repository currently has source-derived fixtures and localhost UDP tests only.

## Safety and test setup

- Use a dedicated test ICE instance and test Domain Server(s). Do not point production domains at an experimental ICE service.
- Keep the test ICE endpoint separate from the official Overte ICE service.
- Record the exact Overte client and Domain Server versions, operating system, ICE build commit, and network topology.
- Synchronize clocks on the capture hosts before testing.
- Do not publish raw captures. They can contain public IP addresses, domain UUIDs, socket information, and heartbeat signatures. Share them privately only when necessary and with the relevant operators' consent.

## Capture UDP 7337

Capture on the ICE host and, separately, on the Domain Server/client host. Capturing both sides helps distinguish a packet not sent by Overte from one sent but not received by ICE.

On each host:

```sh
sudo tcpdump -ni any -s 0 -w /tmp/metastar-ice.pcap 'udp port 7337'
```

Run the test, then stop tcpdump with Ctrl+C. This filter captures the UDP ICE protocol only; the HTTPS enrollment/control API uses TCP 7337.

## Extract and inspect UDP payloads

With Wireshark's command-line tool `tshark` installed:

```sh
tshark -r /tmp/metastar-ice.pcap \
  -Y 'udp.port == 7337 && data.data' \
  -T fields -e data.data > /tmp/metastar-ice.hex
```

From the repository's `iceServer/` directory, inspect the extracted datagrams:

```sh
go run ./cmd/ice-packet-inspect < /tmp/metastar-ice.hex
```

The command emits one JSON object per input datagram. It reports the UDT sequence number, ICE packet type, packet version, payload length, and whether the version matches the source-audited value for known ICE packet types. It rejects truncated frames and unsupported UDT control/reliable/fragment/obfuscation flags.

A non-zero exit status means at least one non-comment input line could not be decoded. The output is a framing aid, not a complete protocol verdict: it does not verify heartbeat RSA signatures, decode every Qt payload field, prove that a response reached its destination, or establish NAT traversal.

## Required live test matrix

Run each case with unmodified Overte binaries and preserve the client/server logs alongside the capture timestamps.

| Case | Action | Evidence to record |
|---|---|---|
| Domain heartbeat | Start a test Domain Server configured for the test ICE endpoint | Outbound heartbeat type/version, ICE-side receipt, ACK or denial, and Domain Server log |
| Key bootstrap | Start with an empty ICE public-key cache | First heartbeat is denied while the Directory Service key lookup runs; confirm the domain is **not** admitted yet; after the key is fetched, a later validly signed heartbeat is ACKed and the peer becomes queryable |
| Key rotation | Change the test Domain Server keypair while the ICE service has the previous public key cached | First heartbeat with the new signature is denied while the owning Directory Service key is refreshed; verify that the stale-key heartbeat does not create/update an active peer; a later heartbeat signed by the fetched key is ACKed and accepted |
| Client query | Connect an unmodified Overte client to a test domain | Query type/version, query target UUID, and both peer-information datagrams |
| Two-peer exchange | Connect two test peers/domains and request peer information | Each side receives the other's advertised public/local socket information |
| Endpoint rebinding | Change the target peer's observed UDP source endpoint, then query it again | Reverse peer-information response goes to the latest observed endpoint, not the superseded one |
| Internet NAT | Repeat with two genuinely separate NATs and ordinary Internet paths | Packet captures on both sides and successful application-level connectivity; localhost simulation is not sufficient |

**Important heartbeat behavior:** the upstream Overte ICE server denies a heartbeat while it fetches a missing or replacement public key. MetaStar now matches that behavior: it sends `ICEServerHeartbeatDenied` until a later heartbeat verifies against the fetched key. Only a verified heartbeat is ACKed and admitted to the peer registry. The live test should verify this sequence against an unmodified Domain Server. The upstream Domain Server regenerates its domain keypair after more than three heartbeat denials, so the test should also confirm that key publication and ICE retrieval complete before repeated denials cause an unintended rotation.

For each packet, compare the observed type and version with `iceServer/internal/protocol/packet.go` and `iceServer/docs/protocol-notes.md`. Compare payload field order and byte order with the corresponding Qt stream notes. Investigate every discrepancy before treating a case as passed.

## Reporting results

A useful private test report includes:

- metaStar commit SHA and Go version
- Overte client and Domain Server build identifiers
- ICE host OS, public network topology, and whether NAT is present
- the JSON Lines output from the inspector
- matching timestamps from Overte and ICE logs
- pass/fail/blocked status for each matrix row, with a short explanation

Do not commit unredacted packet captures, private keys, enrollment secrets, registration tokens, or production domain data. If a fixture is later committed, it must be deliberately minimized and reviewed for sensitive values; synthetic source-derived fixtures must remain clearly distinguished from captured traffic.
