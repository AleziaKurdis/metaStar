<!--
Copyright Alezia Kurdis, 2026.
SPDX-License-Identifier: Apache-2.0
-->
<p align="center">
<picture><source srcset="docs/images/logo-metaStar-black.svg" alt="metaStar" width="300" media="(prefers-color-scheme: dark)">
<img src="docs/images/logo-metaStar-white.svg" alt="metaStar" width="300">
</picture>
</p>

# metaStar

Independent infrastructure for the Overte metaverse.

metaStar is organized as a monorepo with two independently deployable services:

- **`directoryServer/`** — PHP 8.2+ Directory Service intended for conventional PHP hosting.
- **`iceServer/`** — standalone Go ICE service intended for a Linux host with public UDP reachability.

The services are developed together but do not need to run on the same machine. One ICE service is intended to support multiple independent Directory Services.

## Project status

**Development only. Not production-ready.** The current Go ICE implementation is an early prototype. Compatibility with unmodified Overte Domain Servers and clients must be demonstrated using real protocol interoperability tests before it can replace the official ICE service. Do not expose an unreviewed development service as a production endpoint.

## Repository layout

```text
metaStar/
├── directoryServer/   # PHP Directory Service
├── iceServer/         # Go ICE service
├── docs/              # Cross-component architecture and operations
└── .github/workflows/ # Automated checks
```

## Development requirements

### Directory Server

- PHP 8.2 or newer
- Required PHP extensions documented in `directoryServer/README.md`
- No Node.js, Composer, npm, Vue, or frontend build step is required by this project

### ICE Server

- Go toolchain for development and tests
- Linux x86_64 host for deployment and runtime testing
- Runtime installation should not require Go or a compiler

See `iceServer/README.md` for the current prototype's actual capabilities and limitations.

## Security and deployment

- Never commit live credentials, enrollment secrets, registration tokens, TLS private keys, private domain data, or production databases.
- Keep the ICE control API authenticated and protect its transport with correctly validated TLS before exposing it publicly.
- Do not disable TLS certificate verification to work around a certificate problem.
- Router forwarding and host firewall rules must be documented and tested separately from application-level tests.

## Versioning

The Directory Server and ICE Server can evolve independently. A metaStar release should identify the exact component versions it contains. Cross-component API changes must be documented in `docs/`.

## License

See `LICENSE` and the component-specific notices. The ICE component retains its upstream attribution and license notices.
