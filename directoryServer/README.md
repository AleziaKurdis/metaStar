# MetaStar Directory Server — PHP implementation (Milestone 25 public ICE discovery)

**Milestone 25: Public ICE server discovery.** Adds the unauthenticated `GET /api/v1/ice-server` endpoint so an Overte Domain Server can discover the public ICE address from its configured Directory Server. The endpoint reuses `default_ice_server_url` and the existing metaverse-info fallback; it does not expose the separate ICE control URL or enrollment credentials.


**Milestone 24.4: Public-key conversion fix.** Overte uploads its RSA public key as PKCS#1 DER. The server now wraps that DER in the ASN.1 SubjectPublicKeyInfo structure and passes it to OpenSSL using the standard `PUBLIC KEY` PEM format. SPKI DER uploads remain supported as a fallback. Failed or missing public-key uploads now return HTTP 400 instead of HTTP 200 with a failure body, so the Domain Server cannot mistake an application-level rejection for a successful upload. The safe Milestone 24.3 diagnostics remain available.

**Milestone 24.2: ICE URL diagnostics.** The debug log now records the effective `ice_server_url` returned by both metaverse-info endpoints, including whether it came from `default_ice_server_url` or the metaverse URL fallback. It also records the effective per-domain `ice_server_address` returned by `GET /api/v1/domains/{domainId}`, including whether the value came from the stored domain record or the configured default. These events require `debug.enabled` in `config/local.php`.

**Milestone 24.1: Temporary domain request/response payload diagnostics.** This diagnostic build extends Milestone 24 logging for `/api/v1/domains` requests. It records the parsed incoming JSON/form payload and the JSON response payload with the HTTP status. The public-key multipart endpoint records field names, body size, and upload metadata rather than dumping binary file contents. Sensitive values such as bearer tokens, API keys, passwords, and private keys are redacted. Remove or disable this diagnostic logging after the Domain Server issue is resolved.

**Milestone 24: Application-owned debug and authentication logging.** The application now has a reusable JSON-lines debug logger that writes to its own log file, independently of the hosting provider's PHP error log. Authentication checks record whether a request authenticated and safe metadata about Authorization-header detection and token/account lookup. Credential values are never written. Logging is controlled through the `debug` configuration block and is disabled by default in the base configuration.

Milestone 23's Authorization-header compatibility remains in place: Bearer-token detection checks the common Apache and LiteSpeed/FastCGI server variables (`HTTP_AUTHORIZATION`, `REDIRECT_HTTP_AUTHORIZATION`, and `AUTHORIZATION`) and falls back to case-insensitive request-header inspection when available. Existing query-string and legacy raw-token handling are retained.

Milestone 22's account-scoped **Choose from my domains** behavior, `/server` URL-prefix compatibility, and all previous project functionality remain included.

Milestone 17.1 added the account dashboard, authentication navigation, and clean public URL normalization. This milestone completes the public account flow: registration returns visitors to sign-in, successful sign-in routes administrators to the administration dashboard and regular users to their personal account dashboard, and both dashboards clear the shared browser sign-in state on sign-out. It also restores the project-root `.htaccess` file.

## Domain Server: Choose from my domains

The Overte Domain Server requests `GET /api/domains` from its own web interface. The Domain Server forwards this to the Directory Service as `GET /api/v1/domains` with the configured bearer access token. The response must contain `data.domains`; each entry must expose `domainId` and `name` for the selection dialog. This endpoint is account-scoped: it returns only domains whose `sponsorAccountId` matches the authenticated account, matching Iamus `AccountScopeFilter` behavior. It does not create a domain or adopt an arbitrary ID.

## Overte `/server` URL prefix

The Overte Domain Server calls Directory Service endpoints beneath `/server` (for example, `/server/api/v1/domains/{domainId}/public_key` and `/server/api/v1/domains/{domainId}/ice_server_address`). The front controller now strips that leading `/server` segment before route matching. Existing root-level routes such as `/api/v1/...` continue to work unchanged, so both URL forms are supported.


## Technology

- PHP 8.2+
- JSON files for persistence
- Native PHP, HTML, CSS and vanilla JavaScript for the administration dashboard and public account pages
- No database server, Node.js, npm, Composer, Vue, or build step

## Included

Milestone 18 added:

- Public registration page at `/register/` using the existing account-creation API
- Public sign-in and sign-out page at `/login/` using the OAuth password grant
- Role-aware post-login routing: administrators open `/dashboard/`; regular users open `/account/`
- Personal account dashboard at `/account/` showing the signed-in account, sponsored domains and places, and generating/revoking domain-scope access tokens
- Email verification confirmation page at `/verify-email/`
- Default email-verification links now redirect to the confirmation page; configured success/failure redirects remain supported

Milestone 15 added:

- Administrator dashboard actions to create domains and additional places
- Domain creation automatically creates the initial Place, matching the original Overte API
- Domain and Place creation credentials displayed after successful creation, with copy controls
- Duplicate domain-name protection and network-port validation


Milestone 20 adds:

- `GET /api/v1/domains/{domainId}/public_key`, returning the domain public key as a single-line PEM body without the BEGIN/END markers
- `PUT /api/v1/domains/{domainId}/public_key`, accepting the Iamus multipart fields `api_key` and binary `public_key` (PKCS#1 DER), converting the key to SPKI PEM, and storing it on the domain
- `PUT /api/v1/domains/{domainId}/ice_server_address`, accepting the Iamus JSON body `domain.api_key` and `domain.ice_server_address`
- Domain write authorization matching Iamus: API-key authentication when no bearer token is supplied, or a valid domain-scope bearer token belonging to the domain sponsor

All previous milestone functionality remains included, including:

- `POST /api/v1/domains/temporary` with configurable enable/disable switch
- Random color-animal domain names, with collision checking
- Automatic linked place creation for temporary domains
- Optional account association when the request carries a valid account token
- Domain API key returned as `data.domain.api_key`
- Place current-activity token returned when a logged-in account creates the temporary domain
- Domain inactivity detection and attendance reset
- Place activity reconciliation with domain attendance when place-current data is stale
- Throttled request-driven maintenance, so ordinary PHP hosting does not need a resident daemon
- Optional CLI maintenance entry point for cron: `php bin/maintenance.php`
- `PUT /api/v1/user/location` for authenticated account location updates
- `PUT /api/v1/user/heartbeat` for location + heartbeat updates
- `GET /api/v1/users/{accountId}/location` for authorized location lookup
- Heartbeat-based `location.online` in account and user responses
- `status=online` filtering for account/user listings
- Public profile listing and profile visibility checks
- Friend and connection list endpoints, with symmetric relationship cleanup
- Connection detail listings with image and location summaries
- Legacy location fields: `connected`, `path`, `place_id`, `domain_id`, `network_address`, `network_port`, `node_id`, and `availability`
- Persistent, expiring avatar connection handshakes
- Account locker read/write endpoints
- PKCS#1 DER public-key upload converted to SPKI PEM, plus public-key lookup
- One-time first-administrator setup page at `/setup/`, protected by a server-side setup key
- Administrator-only dashboard at `/dashboard/`
- Password login through the existing OAuth password grant; the dashboard does not store the password
- Overview counters for accounts, online accounts, domains, active domains, places, reported users, tokens, and pending requests
- Account, domain, and place listing views with client-side search
- Administrator controls to edit account email addresses, reset account passwords, manage administrator roles, and delete accounts, domains, and places
- Account token inspection and revocation
- Last-administrator and self-account protection for administrator role/deletion actions
- Administrator-only API endpoints for dashboard statistics and complete place listings
- Responsive layout; no frontend framework, build step, or additional runtime
- Persistent connection, friend, and follow requests with accept/reject/cancel lifecycle
- Email verification and password recovery using native PHP `mail()`; actual delivery testing is intentionally deferred until dashboard work is complete

## Application debug logging (Milestone 24)

For testing, add or merge this block into `config/local.php`:

```php
'debug' => [
    'enabled' => true,
    'auth_logging' => true,
    'log_file' => ''
],
```

With an empty `log_file`, the application writes to `storage_path/logs/overte-debug.log` (by default, `data/logs/overte-debug.log`). The directory is created automatically when possible, and the file is written with restrictive permissions. Set `log_file` to an absolute path if you want a different location. Keep the storage directory outside the public web directory and ensure PHP can write to it.

- `enabled` controls general application debug logging.
- `auth_logging` controls authentication diagnostics and requires `enabled` to also be true.
- Both are `false` in `config/local.php.example`. Enable them temporarily in your actual `config/local.php` only when collecting diagnostics.
- Before production, set both values to `false`. No code changes are needed.

Log entries contain timestamps, event names, HTTP method/path, and safe diagnostic metadata. Query strings are deliberately omitted from the recorded path. Access tokens, refresh tokens, passwords, Authorization values, API keys, and private keys are redacted defensively. In this temporary diagnostic build, requests under `/api/v1/domains` also produce `http.request_payload` and `http.response_payload` events. Milestone 24.2 adds `metaverse_info.ice_server_url` and `domain.ice_server_address` events so the advertised ICE URL and per-domain ICE address can be distinguished, including the source of each value. Milestone 24.3 adds `domain.public_key_upload` and `account.public_key_upload` events with safe binary extraction and OpenSSL conversion diagnostics. Milestone 24.4 converts Overte PKCS#1 DER into standard SPKI DER before OpenSSL parsing and returns HTTP 400 when public-key extraction or conversion fails. JSON request/response structures are recorded with sensitive fields redacted. The public-key multipart upload records field names, body size, and available upload metadata; it does not dump the binary key contents. After collecting the diagnostic log, disable `debug.enabled` (and `auth_logging`) in `config/local.php`, or remove this diagnostic build once the issue is resolved.

## ICE Server administration

The administrator dashboard includes an **ICE Server** section for checking the configured control endpoint, performing initial enrollment, recovering a lost registration token, and manually synchronizing the complete domain UUID list. The enrollment secret is entered by an administrator and sent to the ICE control API over HTTPS; it is not stored in browser storage or persisted by the Directory Server, and the dashboard clears the password field after each attempt. The issued registration token is stored in the private JSON storage directory with restrictive file permissions. The registration record also remembers the ICE control URL used when it was issued, so the dashboard can detect when `ice_control_url` has changed in `config/local.php`.

The dashboard also provides a **Disconnect from ICE Server** action. Disconnect while the original `ice_control_url` is still configured; the Directory Server uses its saved directory-specific token to ask the old ICE server to revoke the token and release its domain UUIDs. Only after the disconnect succeeds should `ice_control_url` and `ice_control_ca_file` be changed in `config/local.php`, followed by enrollment with the new ICE server's bootstrap secret. The dashboard blocks disconnect and synchronization if the configured endpoint differs from the saved registration endpoint. Do not delete the local registration file manually to switch servers.

## ICE certificate file

The example configuration expects the ICE server's **public TLS certificate** at `directoryServer/certificates/ice-server.crt`. The `certificates/` directory is included in the project and is outside the web-accessible `public/` directory. If deploying by FTP, upload the certificate into this folder and keep the configured `ice_control_ca_file` path. Only the public certificate belongs here; never copy the ICE server's private key to the Directory Server.

## Deployment notes

This release includes both the project-root `.htaccess` and `public/.htaccess`. The root file forwards requests into `public/` when the project root is the web document root, normalizes requests such as `/login` to `/login/` without exposing `/public/`, and blocks direct access to private application folders. If your hosting account has additional PHP-handler directives (for example, a cPanel PHP version handler) in its existing root `.htaccess`, preserve those hosting-specific directives when deploying this file. Also preserve `config/local.php` and the entire `data/` directory.

## Temporary domains

Temporary-domain creation is disabled by default, matching the original Iamus configuration. To enable it, add this to `config/local.php`:

```php
'allow_temp_domain_creation' => true,
```

A temporary domain may be created anonymously. If a valid account token is supplied, the account becomes its sponsor and a place-scoped activity token is created for the linked place.

## Activity maintenance

The original Iamus server used recurring background timers. This PHP implementation has no permanently running process, so it runs a throttled maintenance pass during incoming requests. For low-traffic installations, configure a cron job to run:

```sh
php /path/to/overte-php/bin/maintenance.php
```

Suggested initial cadence: every 2–3 minutes. The script is safe to run repeatedly. Maintenance settings can be overridden in `config/local.php`:

- `domain_seconds_until_offline` (default `600`)
- `domain_seconds_check_if_online` (default `120`)
- `place_current_timeout_minutes` (default `5`)
- `place_check_last_activity_seconds` (default `175`)


## Account activity and location

The original Iamus defaults to considering an account offline after 300 seconds without a heartbeat. The PHP rewrite uses the same default, configurable with:

```php
'heartbeat_seconds_until_offline' => 300,
```

Authenticated clients can send location information using the legacy request shape:

```json
{
    "location": {
        "connected": true,
        "path": "/10,20,30/0,0,0,1",
        "place_id": "place-id",
        "domain_id": "domain-id",
        "network_address": "domain.example.org",
        "network_port": 40102,
        "node_id": "client-node-id",
        "availability": ["all"]
    }
}
```

Use `PUT /api/v1/user/location` to update location without refreshing the heartbeat. Use `PUT /api/v1/user/heartbeat` to update the supplied location fields and set `timeOfLastHeartbeat`; when a node ID is present, the response includes `data.session_id`. As in the original Iamus implementation, a heartbeat request only refreshes the timestamp when it contains a `location` object with at least one accepted field.

Online status is computed from the heartbeat timestamp and timeout; it is not stored as a separate flag. Account and user location data includes `online`, `node_id`, and, when available, the domain root and avatar path. `GET /api/v1/users/{accountId}/location` accepts either the account ID or username and is available to the account owner, an administrator, or a listed friend/connection.

Iamus's internal `Sessions` map tracks the lifetime of an individual TCP connection and is not the user's logged-in session. PHP-FPM generally handles requests independently, so reproducing that in-memory connection map would not provide equivalent client-visible behavior. The PHP version therefore implements the meaningful presence timeout through account heartbeats; the existing `session_timeout_minutes` setting remains for compatibility but does not create a persistent PHP session layer.


## Public account pages

- `/register/` — create a normal user account using the public registration API.
- `/login/` — sign in with a username or email address and sign out of the browser session.
- `/verify-email/` — display the result after opening an email verification link.

The public account pages use native HTML, CSS, and vanilla JavaScript. OAuth access tokens are held in browser `sessionStorage`; signing out clears the browser copy but does not revoke the server-side token. Use HTTPS.

## Administration dashboard

Open `/dashboard/` on the metaverse server and sign in with an account that has the `admin` role. Milestone 14 adds administrator management controls to the dashboard. Administrators can edit account email addresses and administrator roles, delete accounts, inspect and revoke account tokens, edit domain settings, delete domains, edit place details, and delete places. The dashboard uses the existing account, domain, place, and token APIs; management permissions are enforced by the API. The last administrator cannot be deleted or demoted, and the currently signed-in administrator cannot delete or demote their own account.

The dashboard obtains an OAuth owner token using the existing `/oauth/token` password grant. The access token is held in browser `sessionStorage`, not in a cookie or server-side PHP session, and is cleared when the user signs out or closes the tab. Use HTTPS for the server and protect administrator credentials accordingly. Signing out clears the browser copy; it does not revoke the token server-side, so the token remains valid until its configured expiration unless separately revoked.

The dashboard uses these administrator-only endpoints:

- `GET /api/v1/admin/dashboard` — server counters and runtime information
- `GET /api/v1/admin/places?page=1&per_page=50` — all places, including non-public places
- `GET /api/v1/accounts?asAdmin=true` — administrator account listing; `GET /api/v1/domains` — domains sponsored by the authenticated account (used by Domain Server **Choose from my domains**); `GET /api/v1/user/domains` — the same account-scoped domain list
- Existing account field, account deletion, domain field/deletion, place field/deletion, and account-token routes — management actions

Deleting an account also removes its access tokens, sponsored domains and their places, owned places, pending requests, and references in other accounts' relationship lists. Deleting a domain through the domain API leaves its places in the directory without an associated domain. Deleting a place also removes its place access token. Review the confirmation message before using any delete action.

## Milestone 14: dashboard management tools

The administration dashboard now supports editing account email addresses, resetting account passwords, managing administrator roles, and deleting accounts, domains, and places, as well as viewing and revoking account access tokens. The dashboard is still a browser interface over the existing JSON API; it does not introduce a JavaScript framework, build process, or additional runtime dependency.

Account role safeguards prevent deleting the currently signed-in administrator, removing administrator privileges from that account, or deleting/demoting the last administrator. Domain deletion deliberately follows the existing API behavior and leaves its places in the directory; the dashboard warns about this before deletion.

## Installation

1. Upload this directory to a PHP 8.2+ hosting account.
2. Prefer setting the web document root to this project's `public/` directory.
3. Copy `config/local.php.example` to `config/local.php` and edit it. Set `base_admin_account` to the administrator username you want (for example, `admin`). Set `initial_admin_setup_key` to a private random secret of at least 32 characters; generate one with `php -r "echo bin2hex(random_bytes(32)), PHP_EOL;"`. Do not publish or share this key.
4. Ensure PHP can write to `data/` (normally directory permission `750` or `770`, depending on the hosting account).
5. Open `/setup/`, enter the configured setup key, your email address, and a password of at least 12 characters. The page creates the first administrator account.
6. Sign in at `/dashboard/`. After the first account is created, `/setup/` is permanently disabled.
7. Visitors can create normal accounts at `/register/` and sign in at `/login/`. After registration, they are sent to sign in. After successful sign-in, regular users are sent to `/account/` and administrators to `/dashboard/`. The account dashboard lists sponsored domains and places, supports domain registration, and lets users generate or revoke domain-scope access tokens. If email verification is enabled, the verification link opens a confirmation page at `/verify-email/`.

The registration page uses the existing public `POST /api/v1/users` endpoint. Registration is refused while the account store is empty and a `base_admin_account` is configured, preventing an unauthenticated visitor from claiming the configured administrator username before first-run setup.

If the host requires the project root as document root, the included root `.htaccess` forwards requests into `public/` and blocks direct access to private folders. Apache rewrite support is required for that arrangement. If you set the document root directly to `public/`, the root `.htaccess` is not used; `public/.htaccess` still provides the public-directory rewrite and protection rules.

## Storage

Collections are JSON arrays stored in `data/`: `accounts.json`, `domains.json`, `places.json`, `tokens.json`, `requests.json`, `sessions.json`, `maintenance.json`, and `scheduled_tasks.json`. Files are created on first write. Back up the complete `data/` directory.

## Tests

Run:

```sh
php tests/smoke.php
php tests/auth-header.php
php tests/debug-logging.php
php tests/domains.php
php tests/places.php
php tests/maintenance.php
php tests/maintenance-scheduler.php
php tests/account-activity.php
php tests/profiles.php
php tests/social.php
php tests/admin-dashboard.php
php tests/initial-admin-setup.php
php tests/email-account.php
php tests/relationship-requests.php
php -d zend.assertions=1 -d assert.exception=1 tests/account-management.php
```

## Compatibility notes and remaining work

This is an incremental replacement, not yet a complete Iamus implementation. The domain and place APIs are practical compatibility subsets. Some edge-case visibility filtering, actual email delivery on the target host, complete monitoring/administration coverage, and broader live-client compatibility still need validation.

Other work remaining includes broader live-client compatibility validation, expanded monitoring, and dashboard management tools. The maintenance process is deliberately compatible with ordinary PHP request hosting and can also be run by cron; it is not a long-running PHP daemon. Domain heartbeats can enqueue due cross-service tasks, while a separate CLI worker performs network operations outside the heartbeat response.

Iamus wraps ordinary API responses as `{"status":"success","data":{}}`; the OAuth endpoint returns its OAuth body directly. This distinction is retained.

## Profiles, friends and connections

Milestone 07 adds the profile and relationship endpoints found in the original Iamus API:

- `GET /api/v1/profiles` lists public profiles (`availability` contains `all`, or is not set), with `page` and `per_page` pagination.
- `GET /api/v1/profile/{accountId}` retrieves a profile by account ID or username. Profiles marked `none`, `friends`, or `connections` are not exposed by the public profile endpoint; the account owner and administrators can still retrieve them. This matches the original `/profile/:accountId` permission check (PUBLIC, OWNER, ADMIN).
- `GET /api/v1/user/profile` retains the legacy signed-in user profile response.
- `GET /api/v1/user/friends` lists the signed-in account's friends.
- `POST /api/v1/user/friends` upgrades an existing connection to a friend; the request body is `{"username":"OtherUser"}`.
- `DELETE /api/v1/user/friends/{username}` removes the friendship from both accounts.
- `GET /api/v1/user/connections` and `GET /api/v1/users/connections` return connection details, including friend/connection status, images, and location.
- `DELETE /api/v1/user/connections/{username}` removes the connection and friendship from both accounts.
- `POST /api/v1/user/connections` deliberately retains Iamus behavior and fails with `cannot add connections this way`; connection establishment belongs to the connection-request workflow, not this endpoint.

The existing `GET /api/v1/users` endpoint now supports `filter=friends`, `filter=connections`, `filter=all`, `status=online`, domain-ID status filters, `search`, and pagination, while preserving account-scope restrictions. Profile visibility is controlled by the account's `availability` values: `none`, `friends`, `connections`, and `all`.

Relationship names are compared case-insensitively. Removing a connection also removes any friendship on both sides, matching the original Iamus relationship cleanup behavior. The PHP implementation does not yet add the separate connection-request workflow; that remains a later compatibility item.


## Connection requests and user utilities

Milestone 08 implements the original Iamus avatar connection handshake and several signed-in user utilities:

- `POST /api/v1/user/connection_request` accepts the legacy `user_connection_request` object containing `node_id` and `proposed_node_id`. The first avatar receives `connection: pending`; the second avatar accepts by initiating the same handshake in reverse; both accounts then receive each other in their `connections` arrays. The initiating avatar can poll again to receive the `new_connection` response.
- `DELETE /api/v1/user/connection_request` cancels outstanding handshake requests associated with the signed-in account or its current node.
- Handshake requests expire after `handshake_request_expiration_minutes` (default: 1 minute) and expired requests are cleaned during normal maintenance and before handshake processing.
- `GET /api/v1/user/locker` and `POST /api/v1/user/locker` read and replace the signed-in account's JSON locker data. An empty locker is returned as an empty JSON object for legacy compatibility.
- `PUT /api/v1/user/public_key` accepts a multipart upload named `public_key` containing a DER-encoded PKCS#1 RSA public key, converts it to SPKI PEM, and stores it on the account.
- `GET /api/v1/users/{accountId}/public_key` returns the stripped PEM public key, username, and account ID. The account identifier may be an account ID or username.

Connection requests are persisted in the `requests` JSON collection. The handshake remains a short-lived node-to-node rendezvous, not a long-lived invitation system. Long-lived connection/friend/follow requests are separate request types in Iamus and are not included in this milestone.

## Account management and tokens

Milestone 09 expands the account and token APIs using the original Iamus account-field permission table and token routes:

- `POST /api/v1/users` creates an account and returns `accountAwaitingVerification` alongside the account ID, username, and active state.
- `GET`, `POST`, and `DELETE /api/v1/account/{accountId}` support lookup by account ID or URL-encoded username, owner/admin updates, and administrator-only deletion.
- `GET` and `POST /api/v1/account/{accountId}/field/{fieldname}` implement per-field access and validation for account settings, images, location, availability, relationships, locker, profile details, password, public key, legacy account credentials, roles, and account timestamps.
- Array fields support the Iamus `set`, `add`, and `remove` manipulator format. Availability values are limited to `none`, `friends`, `connections`, and `all`; roles are limited to `user` and `admin`.
- Username changes update the username references in other accounts' friend and connection lists.
- Password changes use Iamus's HMAC-SHA512 password format with a fresh random salt.
- Administrator account deletion removes tokens, sponsored domains and related places, owned places, pending requests, and references in other accounts' relationship lists.
- `POST /api/v1/token/new?scope=owner|domain|place` creates scoped tokens. The account dashboard uses `scope=domain` for domain-server access; domain-scope tokens can manage domains sponsored by the token owner's account and expire according to `domain_token_expire_hours` (default: one year).
- `GET /api/v1/account/{accountId}/tokens`, `DELETE /api/v1/account/{accountId}/tokens/{tokenId}`, `DELETE /api/v1/account/{accountId}/tokens`, and `GET /api/v1/tokens` list and revoke tokens with owner/admin checks and pagination.
- Expired access tokens are removed during the throttled maintenance pass.

The OAuth password grant remains unchanged. The refresh-token grant now verifies that the refresh token is unexpired and belongs to the account authenticated by the current bearer token, matching the original Iamus ownership check. As in Iamus, refreshing creates a new token without immediately revoking the previous token.

The account field endpoint follows the documented per-field permissions: public fields can be read by any authenticated user; friend/connection lists require the corresponding relationship; locker and private legacy credentials remain owner/admin or owner-only as documented; password hashes are never readable; and roles are writable only by administrators.

Run the new account-management suite with:

```sh
php -d zend.assertions=1 -d assert.exception=1 tests/account-management.php
```

The complete test list now includes `tests/account-management.php` and `tests/debug-logging.php`.

## Milestone 10: persistent relationship requests

The original Iamus source declares `connection`, `friend`, and `follow` request types, but does not expose public routes that implement those workflows. This PHP rewrite provides a documented native API while leaving the existing Iamus-compatible avatar `handshake` endpoint unchanged.

All routes below require an authenticated account:

- `GET /api/v1/user/relationship-requests` — list pending relationship requests involving the current account.
- `POST /api/v1/user/relationship-requests` — create a request. JSON body: `{"type":"connection|friend|follow","target":"username-or-account-id"}`.
- `POST /api/v1/user/relationship-requests/{requestId}/accept` — accept a request addressed to the current account.
- `POST /api/v1/user/relationship-requests/{requestId}/reject` — reject a request addressed to the current account.
- `DELETE /api/v1/user/relationship-requests/{requestId}` — cancel a request created by the current account.

Acceptance semantics:

- `connection`: adds each account to the other's `connections` list.
- `friend`: adds each account to the other's `friends` and `connections` lists.
- `follow`: adds the requester to the target's `followers` list and the target to the requester's `following` list. This is directional.

Requests expire after 14 days by default. Configure `relationship_request_expiration_days` in `config/local.php` to change this (1–90 days). Expired requests are removed by the existing throttled maintenance process and before request listing. Opposite pending requests of the same type are resolved by accepting the existing request, avoiding duplicate pair records. Existing `handshake` and `verifyEmail` request records are not exposed through this new endpoint.

Run the test scripts with PHP assertions enabled, for example (including the authentication-header coverage):

```sh
for test in tests/*.php; do php -d zend.assertions=1 -d assert.exception=1 "$test" || exit 1; done
```


## Milestone 11: email verification and account recovery

Email delivery uses PHP's built-in `mail()` function. PHP hands messages to the server's configured mail transport; the host must have a working MTA/sendmail-compatible transport (for example, Postfix on Ubuntu). This project does not install or configure that system service.

Configure these values in `config/local.php`:

```php
'email_enabled' => true,
'email_from' => 'noreply@example.com',
'email_from_name' => 'My Overte Metaverse',
'email_verification_enabled' => false,
'email_verification_timeout_minutes' => 1440,
'email_verification_success_redirect' => '',
'email_verification_failure_redirect' => '',
'password_reset_timeout_minutes' => 60,
'email_resend_cooldown_seconds' => 60,
'password_reset_url' => 'https://www.example.com/password-reset',
```

`email_enabled` and a valid `email_from` address are required for delivery. Email verification is disabled by default, matching the original Iamus default. If enabled, new accounts remain disabled until verified; registration reports `accountAwaitingVerification: true` and `verificationEmailSent` indicates whether PHP's `mail()` accepted the message. If the handoff fails, the account is still created but remains pending, and the registration page directs the visitor to request another verification email or contact the administrator. Failed email handoffs do not leave a new verification/reset request behind or trigger the resend cooldown. A successful `mail()` result confirms handoff to the host mail transport, not final delivery to the recipient.

Password recovery endpoints:

- `POST /api/v1/account/password/reset/request` with `{ "email": "person@example.com" }`. The response is deliberately generic to avoid revealing whether an email belongs to an account.
- `POST /api/v1/account/password/reset` with `{ "token": "...", "password": "new password" }`. Tokens expire, are stored as SHA-256 hashes, and can be used only once. A successful reset revokes all existing account access tokens.

The reset email points to `password_reset_url` with the token in its query string. This is the URL of the metaverse website's reset form; the PHP API does not provide a user-facing HTML form. The form should submit the token and new password to the reset endpoint.

Additional endpoints:

- `POST /api/v1/account/verify/email/resend` with `{ "email": "person@example.com" }`; the response is generic whether or not an account needs verification, to avoid revealing which email addresses have accounts. Sending failures are recorded in the PHP error log by the email service.
- `GET /api/v1/account/verify/email?a=ACCOUNT_ID&v=CODE` consumes a valid verification link and activates the account.

Email account tests: `php tests/email-account.php`.

## Milestone 13.1 maintenance update

- The initial setup page now reports empty and non-JSON API responses with useful HTTP/rewrite diagnostics instead of exposing a raw JSON parsing exception.
- Unhandled PHP exceptions and fatal errors from the API front controller are logged server-side and returned as a generic JSON HTTP 500 response.
- The setup page and administration dashboard UI label now reads **OVERTE DIRECTORY SERVER**. Internal configuration keys and API names are unchanged.

## Milestone 14.1 addition

- Administrators can revoke all access tokens for an account from the Access tokens dialog. Revoking the signed-in administrator account also signs out the current dashboard session.
- `DELETE /api/v1/account/{accountId}/tokens` revokes all tokens for the target account.

## Milestone 17.2.1 browser-side login fix

- The login page script now checks that page-specific elements exist before registering event handlers. In particular, the login page does not contain the `sign-out-button` used on authenticated pages; its absence must not abort the script.
- The resend-verification handler is registered only when its form, message area, button, and email input are all present. The request remains a JSON `POST` to `/api/v1/account/verify/email/resend`.
- The login form and sign-out handlers are likewise guarded, allowing the script to be reused without a missing element stopping the remaining initialization.
- `showMessage()` now safely handles pages without the login message element.


## Domain registration workflow

Domain entries are not created from the account dashboard. A signed-in account generates a `domain`-scope token and supplies it to the Overte Domain Server setup wizard. When the user activates the domain from Domain Server settings (the “Create new domain ID” action), the Domain Server calls `POST /api/v1/domains` with its domain label and optional network details. Following the original Iamus protocol, the directory service creates the domain record and assigns its permanent UUID, associates it with the account represented by the token, creates the initial place entry, and returns the domain and place information. The Domain Server then sends `PUT /api/v1/domains/{domainId}` heartbeats using that domain token. The account dashboard lists only domains sponsored by the signed-in account and refreshes automatically while open.

The dashboard is intentionally not a domain-registration client: it only generates/revokes tokens and displays domains registered by their Domain Servers.


## metaStar ICE registration and synchronization

The PHP Directory Server includes an optional CLI integration for one-time enrollment with the metaStar Go ICE service and recurring synchronization of the complete domain UUID list. It does not make outbound ICE requests during ordinary web traffic.

See [docs/ice-registration.md](../docs/ice-registration.md) for configuration, first-time enrollment, certificate trust, and cron setup.

- Configure `ice_control_url`, `ice_control_ca_file`, and a stable `ice_directory_id` in `config/local.php`.
- Run `OVERTE_ICE_ENROLLMENT_SECRET=... php bin/ice-sync.php enroll` once; the issued per-directory token is saved in the private storage directory.
- Domain creation and deletion enqueue an immediate ICE registry reconciliation; domain heartbeats also enqueue periodic synchronization when `ice_sync_interval_seconds` has elapsed (default: 300 seconds). These HTTP requests do not contact ICE or wait for network operations.
- Run `php bin/scheduler.php` from cron (for example, every minute) to process queued tasks and retry temporary failures. The existing `php bin/ice-sync.php sync` command remains available for manual synchronization.
- TLS verification is mandatory. The ICE certificate must be explicitly trusted; the integration never disables certificate checks.
- `default_ice_server_url` remains the separate client-advertised ICE address.
- `GET /api/v1/ice-server` publicly returns the effective client-advertised ICE URL for Domain Server discovery; it does not expose the separate `ice_control_url` or any enrollment credentials.

Run the ICE integration tests with assertions enabled:

```sh
php -d zend.assertions=1 -d assert.exception=1 tests/ice-registration.php
php -d zend.assertions=1 -d assert.exception=1 tests/ice-server-discovery.php
```


## Customizing the Directory Server logo

Replace `directoryServer/logo.svg` with your own SVG logo. The application serves this file through `public/logo.php`, so the same customization works whether the project root or the `public/` folder is configured as the web document root. The displayed logo area uses a 2:1 aspect ratio; the subtitle below it is shared across the login, registration, account, setup, and administration pages.

## Browser-based ICE discovery checks

After signing in to the administration dashboard, use **Run ICE discovery tests** in the sidebar. The test runner reuses the same checks as `tests/ice-server-discovery.php` and requires a valid administrator bearer token. It does not contact the ICE server or change stored data. The runner is a temporary diagnostic convenience and can be removed after the discovery endpoint has been verified.
