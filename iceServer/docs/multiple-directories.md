# Adding multiple Directory Services

One ICE server can serve multiple independently operated Directory Services. Directory Services enroll themselves through the HTTPS control API; **you do not add per-directory tokens or domain UUIDs manually on the ICE host**.

## Enroll another Directory Service

For each Directory Service:

1. Give it a stable, unique `ice_directory_id` in its private `config/local.php`.
2. Configure `ice_control_url` with the ICE HTTPS endpoint and `ice_control_ca_file` with the CA/certificate bundle trusted by that host.
3. Set the ICE installation's bootstrap enrollment secret in the CLI environment and run `php bin/ice-sync.php enroll` once.
4. Keep the returned registration token in the Directory Server's private `data/ice-registration.json` file. The CLI integration writes this file with restrictive permissions.
5. Configure the Directory Server scheduler worker to run regularly so queued domain changes and periodic heartbeat reconciliation reach ICE.

The enrollment secret is a shared bootstrap capability used only for initial enrollment. Each successful enrollment issues an individual registration token for that Directory Service. Do not reuse registration tokens, publish either kind of secret, or put credentials in public configuration.

See the [Directory Server registration guide](../../docs/ice-registration.md) for the full CLI and scheduler procedure, and [TLS certificate setup](tls-certificates.md) for the HTTPS trust options.

## How ownership works

Each Directory Service sends its complete current domain UUID list during enrollment and subsequent synchronization. The ICE service maintains the UUID-to-Directory mapping and uses the owning Directory Service's public HTTPS base URL to retrieve a domain's public key when needed.

- A Directory Service cannot claim a UUID already owned by another Directory Service.
- A sync with an empty domain list removes that Directory Service's previous domain ownership entries while retaining its registration.
- When ownership changes or a UUID is removed, affected active peer records and cached keys are evicted.
- Domain creation and deletion queue immediate reconciliation in the PHP Directory Server. Domain heartbeats queue periodic reconciliation.
- The scheduler worker performs outbound HTTPS requests. Directory Server HTTP requests only update the local queue and do not synchronously call the ICE API.

The ICE host therefore needs no per-directory configuration changes or restart when another Directory Service enrolls. Keep the bootstrap secret secure because it can authorize new Directory Service registrations.
