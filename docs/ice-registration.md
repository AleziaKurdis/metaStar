# Directory Server ↔ metaStar ICE registration

The Directory Server synchronizes its complete domain UUID list with the Go ICE control API. Domain heartbeats enqueue synchronization when it is due; a separate CLI worker performs the network request. This keeps ICE calls out of the heartbeat response and allows temporary ICE outages to be retried without affecting Domain Server API requests.

## Configuration

Add these values to `config/local.php`:

```php
'metaverse_server_url' => 'https://directory.example.org',
'ice_control_url' => 'https://203.0.113.10:7337',
'ice_control_ca_file' => '/secure/path/ice-server-ca.crt',
'ice_directory_id' => 'my-overte-directory',
```

- `metaverse_server_url` is the public HTTPS base URL of this Directory Server. The ICE service uses it to fetch domain public keys.
- `ice_control_url` is the ICE HTTPS control API origin. It is **not** the same as `default_ice_server_url`, which is the address advertised to Overte clients and Domain Servers.
- `ice_control_ca_file` must be a readable PEM CA/certificate file that trusts the ICE HTTPS certificate. TLS peer and hostname verification remain enabled. Never work around trust errors by disabling verification.
- `ice_directory_id` is a stable unique identifier. Do not change it after enrollment.
- Keep `config/local.php`, the certificate file, and the `data/ice-registration.json` token file private. The token file is created with mode 0600.

## First-time enrollment

Copy the ICE server certificate securely to the Directory Server host. Then set the bootstrap secret only in the shell environment and enroll once:

```sh
export OVERTE_ICE_ENROLLMENT_SECRET='THE_SECRET_PRINTED_DURING_ICE_INSTALL'
php bin/ice-sync.php enroll
unset OVERTE_ICE_ENROLLMENT_SECRET
```

The command sends the complete current domain list to `POST /v1/enroll`, then saves the returned per-directory registration token in `data/ice-registration.json`. It refuses to enroll again when that file already exists. Do not put the bootstrap secret in a command-line argument, source file, or Git commit.

An empty domain list is valid during initial enrollment. A later sync publishes the full list.

## Synchronization

Run:

```sh
php bin/ice-sync.php sync
```

The command sends the complete current domain UUID list to `POST /v1/register`. Removed domains are removed from this Directory Service's ICE ownership list; the ICE service evicts peers whose ownership changed.

For low-maintenance hosting, configure the scheduler worker to run every minute (adjust the PHP path and project path for the host):

```cron
* * * * * /usr/bin/php /path/to/directoryServer/bin/scheduler.php >> /path/to/private-logs/scheduler.log 2>&1
```

The worker processes pending tasks only. It is safe to invoke every minute; it exits quickly when no work is pending. Failed ICE requests remain pending with a retry delay and are reported in the worker output. The heartbeat only writes a local queue record; it never makes an outbound request or waits for ICE. The manual `php bin/ice-sync.php sync` command remains available for an immediate synchronization.

## Operational boundaries

- Enrollment remains a deliberate one-time CLI operation; it never runs automatically during web requests.
- After enrollment, Domain Server heartbeats enqueue due ICE sync work. A cron invocation of `bin/scheduler.php` is required to execute it; without a worker, queued syncs remain pending.
- It does not change the ICE address advertised to Overte; configure `default_ice_server_url` separately to the correct public ICE address.
- The ICE service's current self-signed IP certificate requires explicit secure distribution and trust configuration.
- If the ICE endpoint or certificate changes, update `ice_control_url` and `ice_control_ca_file` before running sync.
- Never delete `data/ice-registration.json` casually. Re-enrollment with the same directory ID is intentionally rejected by the ICE service; token recovery/rotation is a separate administrative operation.
