# Directory enrollment (v0.3 development protocol)

## First-time enrollment

POST `https://PUBLIC_IP:7337/v1/enroll` with a trusted IP-address TLS certificate.

Headers: `Authorization: Bearer <ICE_ENROLLMENT_SECRET>`, `Content-Type: application/json`.

```json
{"directory_id":"my-directory","base_url":"https://directory.example.org","domains":[]}
```

The response contains `registration_token` (64 hexadecimal characters). The PHP Directory Server's `php bin/ice-sync.php enroll` command stores it in the private storage directory as `data/ice-registration.json`, with restrictive file permissions. Do not copy it into public configuration, publish it in GitHub, or share it.

## Sync

POST `https://PUBLIC_IP:7337/v1/register` with `Authorization: Bearer <REGISTRATION_TOKEN>` and the same JSON fields, including the **complete current** list of domain UUIDs. An empty list removes previous domain ownership entries while retaining the directory registration.

A second enrollment attempt with the same directory ID is rejected. Register calls cannot claim a UUID owned by another directory. Enrollment and sync are authenticated; this is not anonymous registration.

Each successful enrollment or synchronization compares the previous and new UUID ownership mappings. Active peer records are immediately removed for UUIDs whose owner changed, including UUIDs removed from a Directory Service's complete list or assigned to a first-time owner. Heartbeat acceptance and query handling are synchronized with these changes, and an in-flight public-key response is discarded if its Directory Service owner or base URL is no longer current.

Registry persistence is atomic from the service's point of view: a failed file save restores the previous in-memory directory and ownership state. First-time enrollment writes the directory record and its credential hash together, so a failed write cannot leave an enrolled directory without a usable registration token.

## TLS trust

The ICE service generates a self-signed certificate for its public IPv4 address. The Directory Service must securely obtain the ICE certificate and configure its HTTP client to trust it. Changing public IP regenerates the certificate and requires redistributing trust. A CA-issued certificate or a stronger enrollment trust design may replace this before production.

## PHP Directory Server integration

The PHP Directory Server now includes the production-path integration code in `directoryServer/app/IceRegistrationService.php` and the CLI entry point `directoryServer/bin/ice-sync.php`.

1. Configure `ice_control_url`, `ice_control_ca_file`, and a stable `ice_directory_id` in `directoryServer/config/local.php`.
2. Run `php bin/ice-sync.php enroll` once with `OVERTE_ICE_ENROLLMENT_SECRET` set in the CLI environment.
3. Configure `php bin/scheduler.php` to run from cron (normally every minute).
4. Domain creation and deletion queue immediate reconciliation. Domain heartbeats queue periodic reconciliation according to `ice_sync_interval_seconds` (default 300 seconds).

The HTTP heartbeat and domain lifecycle requests only update the local task queue. The CLI worker performs outbound HTTPS requests and retains failed work for retry. See [the Directory Server registration guide](../../docs/ice-registration.md) for the complete operator procedure.
