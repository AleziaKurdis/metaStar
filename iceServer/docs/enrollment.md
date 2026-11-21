# Directory enrollment (v0.3 development protocol)

## First-time enrollment

POST `https://PUBLIC_IP:7337/v1/enroll` with a trusted IP-address TLS certificate.

Headers: `Authorization: Bearer <ICE_ENROLLMENT_SECRET>`, `Content-Type: application/json`.

```json
{"directory_id":"my-directory","base_url":"https://directory.example.org","domains":[]}
```

The response contains `registration_token` (64 hexadecimal characters). Store it securely in the Directory Server configuration. Never publish it in GitHub.

## Sync

POST `https://PUBLIC_IP:7337/v1/register` with `Authorization: Bearer <REGISTRATION_TOKEN>` and the same JSON fields, including the **complete current** list of domain UUIDs. An empty list removes previous domain ownership entries while retaining the directory registration.

A second enrollment attempt with the same directory ID is rejected. Register calls cannot claim a UUID owned by another directory. Enrollment and sync are authenticated; this is not anonymous registration.

Each successful enrollment or synchronization compares the previous and new UUID ownership mappings. Active peer records are immediately removed for UUIDs whose owner changed, including UUIDs removed from a Directory Service's complete list or assigned to a first-time owner. Heartbeat acceptance and query handling are synchronized with these changes, and an in-flight public-key response is discarded if its Directory Service owner or base URL is no longer current.

Registry persistence is atomic from the service's point of view: a failed file save restores the previous in-memory directory and ownership state. First-time enrollment writes the directory record and its credential hash together, so a failed write cannot leave an enrolled directory without a usable registration token.

## TLS trust

The ICE service generates a self-signed certificate for its public IPv4 address. The Directory Service must securely obtain the ICE certificate and configure its HTTP client to trust it. Changing public IP regenerates the certificate and requires redistributing trust. A CA-issued certificate or a stronger enrollment trust design may replace this before production.

## PHP

See `integration/php/overte_ice_enroll.php` and `overte_ice_register.php`. These are **integration examples**, not yet wired into the existing PHP Directory Server. A future milestone will add automatic domain-list synchronization to its lifecycle.
