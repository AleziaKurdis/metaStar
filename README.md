# metaStar

Independent infrastructure for the Overte metaverse.

- `directoryServer/`: PHP 8.2+ Directory Server (based on the previously developed milestone 24.4).
- `iceServer/`: standalone Go ICE Server, sharing **UDP 7337** (Overte ICE) and **TCP 7337** (HTTPS registration).

Each service deploys independently; a single ICE Server may serve many independent Directory Services. There is no requirement for a domain name for the ICE endpoint: a public IPv4 address works.

**Status: development / NOT production-ready.** Go ICE packet interoperability with unmodified Overte Domain Servers and clients has not been proven in live testing. Do not replace a working ICE service yet.

## Directory enrollment model

1. Install the ICE service once on Ubuntu. The installer asks **only** for the public IPv4 address and generates a server-wide **enrollment secret**.
2. Give that secret securely to each authorized Directory Service administrator (not through a public repository).
3. The Directory Service calls `POST https://ICE_IP:7337/v1/enroll` with its chosen identifier, HTTPS base URL and current domain UUID list. The ICE service returns a **unique per-directory registration token**.
4. The Directory Service stores its token privately and calls `POST /v1/register` when its domain list changes and periodically to resynchronize.
5. New Directory Services do not require editing ICE configuration or restarting ICE.

**Security limitation:** the enrollment secret authorizes onboarding; anyone possessing it could enroll a new directory and claim unregistered UUIDs. Share it only with trusted operators. This is **not open anonymous self-registration**. A future enrollment-approval/challenge protocol is desirable. The HTTPS service currently uses a self-signed IP certificate; Directory Services must explicitly trust it. Never disable certificate verification.

## Source provenance

`directoryServer/` is copied from the latest available PHP milestone 24.4 package. Its project-root `.htaccess` and `public/.htaccess` are both preserved. The ICE code is derived from the previous 0.2.0-dev Go prototype. No production data or live credentials are included.

## GitHub

Create a repository called `metaStar`, then copy this directory tree into it. Do not commit private tokens, local configuration, certificates, user databases or production state.

## Deployment

Read `iceServer/README.md` and `iceServer/docs/enrollment.md`. No Go compiler is needed on VIRZ if using the included release binary.
