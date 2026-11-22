# ICE server certificates

This directory is the intended location for the ICE server's **public TLS certificate** used by the PHP Directory Server to verify the HTTPS control connection.

- Upload the public certificate as `ice-server.crt`.
- The example setting in `config/local.php.example` already points here.
- This directory is outside `public/` and must remain non-public.
- Never put the ICE server's private key in this directory or copy it from the ICE host.
- Certificate files are ignored by Git; keep deployment-specific certificates out of commits.

If the certificate has a different filename, update `ice_control_ca_file` in `config/local.php` accordingly.
