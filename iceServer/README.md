# metaStar ICE Server — Go 0.3.1-dev

Standalone Go ICE service for Ubuntu 24.04 x86_64. Designed for one ICE server to serve multiple independently operated Directory Services without manual per-directory configuration on the ICE host.

**Development build: not validated against a real Overte Domain Server or client.**

## Ports

- UDP 7337 — Overte ICE protocol
- TCP 7337 — HTTPS enrollment and directory synchronization

No Apache/Nginx is required. Router forwarding must cover both protocols. The installer currently asks for the public IPv4 address used in the IP-address TLS certificate; it does not ask for a Directory Service ID.

## Protocol implementation status

The Go packet type identifiers now match the zero-based values in Overte's `PacketTypeEnum::Value`. Numeric golden tests protect these values.

The Go implementation handles the unreliable, unfragmented and unobfuscated Overte UDP data-frame subset used by ICE heartbeats, queries, acknowledgements, denials and peer-information responses. It also refreshes a cached domain public key when heartbeat signature verification fails, matching the original ICE server's key-rotation behavior. It does not implement Overte's full reliable UDT transport. See `docs/protocol-notes.md` for the source audit and remaining validation work.

This is **not yet proof of end-to-end interoperability**. Real Domain Server and ICE client tests are still required.

## Install on VIRZ (after test review)

Extract the package and run `sudo ./scripts/install.sh` from the `iceServer/` directory. The script preserves an existing config and generates a random enrollment secret on first install. **Keep it private.** Use:

```bash
sudo systemctl status overte-ice
sudo journalctl -u overte-ice -f
```

## Registration

See `docs/enrollment.md`. New directories call `/v1/enroll` using the shared bootstrap secret, receive their own token, and then call `/v1/register` to update the domain list. No ICE restart is needed.

## Current limitations

- The PHP Directory Server does not yet automatically call enrollment/sync; examples are supplied for integration.
- The bootstrap secret is an administrative enrollment capability; it must not be publicly shared.
- TLS currently uses a self-signed IP-address certificate requiring explicit trust. The final certificate/trust model remains to be improved before public service.
- Go ICE interoperability has not been tested live against unmodified Overte binaries.
- Domain key cache invalidation and service restart behavior need production-style testing.
- Upgrading an already-installed 0.2.0-dev instance requires a configuration migration; the installer preserves existing configuration. Do not install over 0.2.0-dev without reviewing `/etc/overte-ice/config.json`.

Developer checks:

```bash
go test -race ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/overte-ice-server ./cmd/overte-ice
```
