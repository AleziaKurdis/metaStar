# Adding multiple Directory Services

The ICE Server keeps one registration credential per Directory Service. The initial installer creates one entry. To authorize another independent Directory Service:

1. Generate a new secret on VIRZ:

   ```bash
   openssl rand -hex 32
   ```

2. Edit `/etc/overte-ice/config.json` and add another entry to `registration_tokens`, using a unique Directory Service ID:

   ```json
   "registration_tokens": {
     "ak-galaxy": "FIRST_LONG_SECRET_HERE",
     "another-directory": "SECOND_LONG_SECRET_HERE"
   }
   ```

3. Restart the service:

   ```bash
   sudo systemctl restart overte-ice
   ```

4. Configure that Directory Service to call `POST https://PUBLIC_IP:7337/v1/register` with its own ID and secret, its public HTTPS base URL, and its current domain UUID list.

The Directory Service does not need to send public keys. The ICE Server fetches each domain's key from the correct Directory Service when that domain first sends a heartbeat. The UUID-to-Directory mapping is learned from registration; individual domains are not manually configured on VIRZ.

A token should be unique per Directory Service. Never reuse the same token for several directories.
