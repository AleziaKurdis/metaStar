# metaStar ICE Server — Go 0.3.0-dev

Standalone Go ICE service for Ubuntu 24.04 x86_64. Designed to support multiple independently operated Directory Services with no manual per-directory configuration on the ICE host.

**Development build: not validated against a real Overte Domain Server or client.**

## Ports

- UDP 7337 — Overte ICE protocol
- TCP 7337 — HTTPS enrollment and directory sync

No Apache/Nginx required. Router forwarding must cover both protocols. The installer asks for the public IPv4 to generate the IP-address TLS certificate; it **does not** ask for a Directory Service ID.

## Install on VIRZ (after test review)

Extract the package and run `sudo ./scripts/install.sh` from the `iceServer/` directory. The script preserves an existing config and generates a random enrollment secret on first install. **Keep it private.** Use `sudo systemctl status overte-ice` and `sudo journalctl -u overte-ice -f` to inspect the service.

## Registration

See `docs/enrollment.md`. New directories call `/v1/enroll` using the shared bootstrap secret, receive their own token, and then call `/v1/register` to update the domain list. No ICE restart needed.

## Current limitations

- Upgrading an already-installed 0.2.0-dev instance requires a configuration migration; the installer deliberately preserves existing configuration. Do not install this over 0.2.0-dev without reviewing `/etc/overte-ice/config.json`.

- The PHP Directory Server does not yet automatically call enrollment/sync; examples are supplied for integration.
- The bootstrap secret is an administrative enrollment capability; it must not be publicly shared.
- TLS uses a self-signed IP-address certificate requiring explicit trust.
- Overte packet interoperability remains to be verified in live tests.
- Domain key cache is invalidated on successful registration; no production soak testing yet.

Build for developers only: `go test ./...` and `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/overte-ice-server ./cmd/overte-ice`.
