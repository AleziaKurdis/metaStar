# metaStar ICE Server — Go 0.3.9-dev

Standalone Go ICE service for Ubuntu 24.04 x86_64. Designed for one ICE server to serve multiple independently operated Directory Services without manual per-directory configuration on the ICE host.

**Development build: not validated against a real Overte Domain Server or client.**

## Ports

- UDP 7337 — Overte ICE protocol
- TCP 7337 — HTTPS enrollment and directory synchronization

No Apache/Nginx is required. Firewall/router rules must cover both protocols. The installer accepts a public IPv4 or IPv6 address and selects the matching wildcard listener. For a manually edited configuration, `listen_address` and `advertise_ip` must use the same family (for example, `::` and a public IPv6 address). Each service instance binds one address family; IPv4 remains the default when an existing configuration is preserved. The Directory Service HTTPS control hostname may be a DNS name with a matching certificate.

## Protocol implementation status

The Go packet type identifiers now match the zero-based values in Overte's `PacketTypeEnum::Value`. Numeric golden tests protect these values.

The Go implementation handles the unreliable, unfragmented and unobfuscated Overte UDP data-frame subset used by ICE heartbeats, queries, acknowledgements, denials and peer-information responses. It reads complete UDP payloads before enforcing a 2,048-byte ICE datagram limit, so oversized packets cannot be silently truncated into valid-looking prefixes. It also refreshes a cached domain public key when heartbeat signature verification fails, matching the original ICE server's key-rotation behavior. Concurrent public-key retrieval is capped at 32 requests; when all slots are occupied, a domain can retry on its next heartbeat. It does not implement Overte's full reliable UDT transport. See `docs/protocol-notes.md` for the source audit and remaining validation work.

The server tests exercise the two-peer UDP information exchange locally, including a simulated change to the target peer's NAT-mapped source endpoint. This is still **not proof of end-to-end interoperability**. Real Domain Server and ICE client tests and real Internet NAT hole-punch tests are still required.

Unknown-domain heartbeat denial replies are bounded by a process-wide token bucket (50 responses/second, burst of 100); registered-domain heartbeat ACKs are unaffected. This limits outbound denial amplification, not inbound packet-processing cost. See docs/heartbeat-security.md.\n\nICE query packets do not authenticate the requesting client in the current Overte protocol. MetaStar applies a bounded per-source-IP token bucket (10 queries/second, burst of 30) to limit query-relay abuse without changing the wire format. This is an abuse-control measure, not client authentication; distributed or source-IP-spoofed traffic is not fully prevented. See docs/query-security.md.

The outgoing UDP sender follows Overte's unreliable UDT sequence rules: counters start at 1, are independent per destination, are shared across packet types for that destination and wrap at 27 bits. Sequence state is capped at 8,192 destinations and idle entries expire after two minutes. If the cap is full, stale entries are reclaimed; if all entries are active, packets to new destinations are dropped rather than evicting an active counter and risking a sequence reset. Regression tests protect these details and the decoder's rejection of unsupported UDT flags.

When a Directory Service synchronizes its complete domain list, peers whose UUID ownership changed are evicted immediately rather than remaining queryable until the normal five-second heartbeat expiry. In-flight public-key fetches are also discarded if ownership changes before they complete.

Registry changes roll back in-memory ownership data when the atomic registry-file save fails. First-time enrollment stores the Directory Service record and its credential hash in one file write, avoiding a partially enrolled entry.

## Preparing a real Overte capture

The packet inspection utility reads UDP payloads exported from Wireshark/tshark and reports the UDT sequence, ICE packet type/version, and payload length. It is a framing aid only; it does not verify signatures or prove that a peer exchange or NAT traversal succeeded.

From this directory:

```sh
tshark -r /path/to/capture.pcap -Y 'udp.port == 7337 && data.data' -T fields -e data.data > /tmp/ice-datagrams.hex
go run ./cmd/ice-packet-inspect < /tmp/ice-datagrams.hex
```

See [docs/overte-interoperability.md](docs/overte-interoperability.md) for the full capture procedure, safety notes, and required live test matrix. No live Overte capture has yet been validated or committed.

## Install

Extract the package and run `sudo ./scripts/install.sh` from the `iceServer/` directory. The script preserves an existing config and generates a random enrollment secret on first install. **Keep it private.** Use:

```sh
sudo systemctl status overte-ice
sudo journalctl -u overte-ice -f
```

The default installation generates a self-signed certificate for the configured `advertise_ip` (IPv4 or IPv6). For a CA-issued certificate on a DNS hostname, follow [TLS certificate setup](docs/tls-certificates.md).

## Registration

See `docs/enrollment.md`. New directories call `/v1/enroll` using the shared bootstrap secret, receive their own token, and then call `/v1/register` to update the domain list. No ICE restart is needed.

## Current limitations

- The PHP Directory Server includes `php bin/ice-sync.php enroll|sync` and a queued scheduler worker (`php bin/scheduler.php`). Enrollment is a deliberate one-time CLI operation. After enrollment, domain creation/deletion and periodic domain heartbeats queue reconciliation locally; a cron/scheduler invocation is required to execute the worker. HTTP requests never call the ICE control API directly.
- The bootstrap secret is an administrative enrollment capability; it must not be publicly shared.
- The default installer certificate is self-signed and requires explicit trust. CA-issued certificates are supported when the configured certificate and key match the HTTPS hostname used by the Directory Server.
- Go ICE interoperability has not been tested live against unmodified Overte binaries.
- Domain key cache invalidation and service restart behavior need production-style testing.
- Upgrading an already-installed 0.2.0-dev instance requires a configuration migration; the installer preserves existing configuration. Do not install over 0.2.0-dev without reviewing `/etc/overte-ice/config.json`.

Developer checks:

```sh
go test -race ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/overte-ice-server ./cmd/overte-ice
```
