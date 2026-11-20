# PHP Directory Service registration example

`overte_ice_register.php` is a small, dependency-free example for PHP 8.2+ using the cURL extension. It is not wired into the Directory Server automatically.

The Directory Server must supply its current domain UUID list and call `overteIceRegisterDirectory()` after domain registration/removal and periodically. It must also trust the ICE Server's self-signed certificate by supplying its securely copied PEM file as `$iceCaCertificateFile`. TLS verification is deliberately enabled; do not change it to `false`.

The ICE registration token must be stored in a private server-side configuration location and must never be sent to browsers.
