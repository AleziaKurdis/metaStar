# PHP Directory Service registration example

These dependency-free examples target PHP 8.2+ and require the cURL extension. They are integration examples; the main MetaStar Directory Server uses its own `IceRegistrationService` and `bin/ice-sync.php` command.

- `overte_ice_enroll.php`: perform first-time enrollment and receive the initial registration token.
- `overte_ice_recover.php`: recover a lost token for a directory that is already enrolled.
- `overte_ice_register.php`: synchronize the complete current domain UUID list using the registration token.

The Directory Server must supply its current domain UUID list and call `overteIceRegisterDirectory()` after domain registration/removal and periodically. It must trust the ICE Server's certificate by supplying its securely copied PEM file as the CA certificate path. TLS verification is deliberately enabled; do not disable peer or hostname verification.

The registration token must be stored in a private server-side configuration location and must never be sent to browsers. The enrollment secret must also remain private and should only be used for initial enrollment or explicit recovery.

## Recovering a lost token

If the ICE Server completed enrollment but the Directory Server did not retain the returned token, first fix the local storage problem, then call `metaStarIceRecover()` with the same out-of-band enrollment secret configured on the ICE Server:

```php
require_once __DIR__ . '/overte_ice_recover.php';

$result = metaStarIceRecover(
    '203.0.113.10',
    7337,
    'directory-one',
    $enrollmentSecret,
    '/etc/overte-ice/ice-ca.pem'
);

if (!$result['success']) {
    throw new RuntimeException($result['error']);
}

// Persist this token in private server-side storage before continuing.
$registrationToken = $result['registration_token'];
```

Recovery rotates the ICE Server's credential immediately, so the previous token becomes invalid. Save the returned token securely before attempting routine synchronization. If saving fails again, fix storage and perform recovery again; each successful recovery issues another fresh token.

For the main MetaStar Directory Server, use its built-in command instead:

```sh
OVERTE_ICE_ENROLLMENT_SECRET='...' php bin/ice-sync.php recover
```
