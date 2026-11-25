# TLS certificates for the ICE control API

The ICE server exposes its enrollment and synchronization API over HTTPS on TCP port 443. TLS is separate from the Overte ICE protocol on UDP port 7337. The Go service listens directly on TCP 443; no reverse proxy is required.

## Option A: installer-generated self-signed certificate

The installer accepts a public IPv4 or IPv6 address and selects the matching wildcard listener. On first startup, the service creates a self-signed certificate with the configured `advertise_ip` as its subject alternative name (SAN). Each service instance listens on one address family at a time. If changing an existing installation from IPv4 to IPv6, update both `listen_address` and `advertise_ip` and replace the old self-signed certificate/key pair.

For this option:

- Set the Directory Server's `ice_control_url` to `https://PUBLIC_IP` for IPv4, or `https://[PUBLIC_IPV6]` for IPv6 (HTTPS defaults to TCP 443).
- Securely copy the generated certificate to the Directory Server host.
- Set `ice_control_ca_file` to that certificate file.
- Keep PHP cURL peer and hostname verification enabled.

This is suitable for controlled testing, but distributing and rotating a self-signed trust anchor manually is operationally cumbersome.

## Option B: CA-issued certificate for a DNS hostname

A publicly trusted certificate can be used without changing the IP address advertised to Overte. The ICE service's `advertise_ip` remains the public IP address used for its self-signed certificate; the Directory Server connects to the HTTPS control API using a DNS hostname.

1. Create a DNS A record for IPv4 or an AAAA record for IPv6 (for example, `ice.example.org`) pointing to the ICE server's public address.
2. Obtain a certificate whose SAN includes that exact hostname, using your preferred ACME client or certificate authority.
3. Install the certificate chain and private key at paths readable by the `overte-ice` service account. For example, copy them into `/etc/overte-ice/`, keeping the private key restricted to the service group.
4. Set `tls_cert_file` and `tls_key_file` in `/etc/overte-ice/config.json` to those files. Keep `advertise_ip` set to the public IPv4 or IPv6 address configured for the service.
5. Restart the service and verify that the HTTPS certificate presented on TCP 443 is valid for the hostname.
6. In the PHP Directory Server's `config/local.php`, set:

```php
'ice_control_url' => 'https://ice.example.org',
'ice_control_ca_file' => '/etc/ssl/certs/ca-certificates.crt',
```

On Ubuntu, `/etc/ssl/certs/ca-certificates.crt` is the system CA bundle. Use the appropriate CA bundle path for the Directory Server host. If the certificate is issued by a private CA, point `ice_control_ca_file` to a PEM bundle containing that CA instead.

The ICE server loads the configured certificate/key pair at process startup. After certificate renewal, install the renewed pair at the configured paths and restart `overte-ice`. Configure your ACME client’s renewal deploy hook to perform both operations. Do not expose the private key to the web server or place it in a public directory.

## Important

- Do not disable TLS peer verification or hostname verification in PHP.
- Do not use a certificate for a hostname different from the hostname in `ice_control_url`.
- TCP 443 must reach the ICE service directly for this setup; a reverse proxy is not required.
- Certificate renewal and trust distribution must be tested before production use.
