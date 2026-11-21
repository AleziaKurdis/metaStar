# Directory Server / ICE registration contract

This document defines the HTTPS control-plane contract shared by the PHP
Directory Server and the Go ICE Server. It covers enrollment and ownership
synchronization only; it does not describe the separate UDP peer-discovery
protocol.

## Endpoints

Both endpoints are served by the ICE Server over HTTPS on its configured
control port (7337 by default).

### One-time enrollment

`POST /v1/enroll`

The Directory Server sends its configured enrollment secret:

```http
Authorization: Bearer <ICE enrollment secret>
Content-Type: application/json
```

Request JSON:

```json
{
  "directory_id": "directory-one",
  "base_url": "https://directory.example",
  "domains": [
    "4784f9dc-388c-47c3-8855-373d22f31ff4"
  ]
}
```

A successful request returns HTTP 200:

```json
{
  "status": "success",
  "registration_token": "<64 hexadecimal characters>"
}
```

The registration token is a one-time credential issuance result. The ICE
Server stores only its SHA-256 hash. The Directory Server must save the
returned token in private storage with restrictive file permissions and must
not log or display it. Repeating enrollment for the same directory is rejected;
use the registration endpoint after the first successful enrollment.

### Lost-token recovery

`POST /v1/recover`

If the ICE Server completed enrollment but the Directory Server lost the
response or could not persist the issued token, the operator can rotate the
credential for that already-enrolled directory. This endpoint requires the
same out-of-band enrollment secret:

```http
Authorization: Bearer <ICE enrollment secret>
Content-Type: application/json
```

Request JSON contains only the stable directory identifier:

```json
{
  "directory_id": "directory-one"
}
```

A successful response has the same token shape as enrollment. The ICE Server
replaces the old credential hash atomically; the old registration token stops
working. Recovery does not create a directory or change its domain ownership.
Unknown directory IDs are rejected. If the Directory Server still cannot save
the returned token, fix its private storage permissions and run recovery
again; each successful recovery issues a new token.

The Directory Server exposes this through:

```sh
OVERTE_ICE_ENROLLMENT_SECRET='...' php bin/ice-sync.php recover
```

The secret is read from the process environment and is not accepted as a
command-line argument. Recovery may replace an existing local token file
atomically, so it also repairs a lost or corrupted local credential.

### Subsequent synchronization

`POST /v1/register` (also accepts `PUT /v1/register`)

The Directory Server sends the saved registration token:

```http
Authorization: Bearer <registration token>
Content-Type: application/json
```

The JSON request has the same three fields as enrollment. `domains` is the
complete current domain UUID list, not a delta. An empty array means that the
Directory Server currently owns no domains. The ICE Server replaces the
directory's previous list with the supplied list and releases ownership of
domains omitted from it.

A successful request returns HTTP 200 with:

```json
{
  "status": "success",
  "message": "registered 1 domains"
}
```

## Field and validation rules

- `directory_id` is a stable identifier of 1–128 ASCII letters, digits,
  dots, underscores, or hyphens. It must remain unchanged after enrollment.
- `base_url` is the public HTTPS base URL of the Directory Server. It must
  not contain URL credentials, a query, or a fragment.
- `domains` is an array of at most 10,000 unique UUID strings. UUIDs are
  normalized to lowercase and must use a supported UUID version (1–8) and
  the RFC variant (8, 9, a, or b).
- A domain UUID can be owned by only one registered Directory Server at a
  time. Attempting to claim another directory's domain is rejected; ownership
  is never silently transferred.
- The request body is limited to 1 MiB.
- The Directory Server validates its own complete domain list before sending
  it. If any stored domain record has an invalid UUID, synchronization fails
  rather than sending a partial list.

## HTTP status behavior

| Status | Meaning |
| --- | --- |
| 200 | Enrollment or synchronization succeeded |
| 400 | Request body is not valid JSON or exceeds the body limit |
| 401 | Enrollment/recovery secret or registration credential is missing or invalid |
| 409 | Directory/domain validation failed, duplicate enrollment, unknown recovery directory, or a domain ownership conflict |

Error responses use JSON with `status: "error"` and a human-readable
`message`. Clients should treat non-200 responses as failed operations and
retain their current registration token.

## Persistence and recovery properties

- Enrollment stores directory ownership and the registration-token hash in
  one registry-file commit. A failed disk write must not leave an in-memory
  owner or credential behind.
- Synchronization preserves the previous in-memory directory, ownership, and
  credential state if the registry-file commit fails.
- The token hash and ownership data survive ICE Server restart. A restart
  does not require re-enrollment.
- The Directory Server token file is private application data, not a public
  web asset. If enrollment succeeds remotely but the token cannot be persisted,
  the operator can use the enrollment secret with the recovery endpoint to
  rotate and retrieve a fresh token after fixing local storage.

## Security requirements

- The Directory Server must validate the ICE Server TLS certificate and
  hostname using its configured CA trust file. Redirects are not followed.
- The enrollment secret is used only for initial enrollment and explicit
  credential recovery. Routine synchronization uses the per-directory
  registration token.
- Neither credential belongs in command-line arguments, source control,
  public configuration files, or logs. The enrollment CLI reads the initial
  secret from its environment.
- The ICE Server compares bearer credentials in constant time and stores
  only a hash of each registration token.

## Test coverage and interoperability boundary

The Go tests exercise the HTTP handler contract, enrollment and recovery credential lifecycle,
complete-list replacement, invalid UUIDs, cross-directory ownership conflicts,
persistence across restart, and failure responses. PHP tests exercise the
Directory Server's UUID validation, complete sorted unique list construction,
and private token-file permissions. Both implementations enforce the same
UUID version and variant rules.

These automated tests do not establish compatibility with an unmodified
Overte Domain Server or real-world NAT traversal. Those require separate
capture-based and live-network validation described in
[Overte interoperability](overte-interoperability.md).
