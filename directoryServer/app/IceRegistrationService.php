<?php
declare(strict_types=1);

namespace OvertePHP;

use RuntimeException;

/**
 * Synchronizes this Directory Server's complete domain UUID list with metaStar ICE.
 *
 * The issued registration token is stored in the private JSON storage directory,
 * not in source control or the public web root.
 */
final class IceRegistrationService
{
    private string $controlUrl;
    private string $caFile;
    private string $directoryId;
    private string $directoryBaseUrl;
    private string $tokenFile;

    public function __construct(private JsonStore $store, array $config)
    {
        $this->controlUrl = rtrim(trim((string)($config['ice_control_url'] ?? '')), '/');
        $this->caFile = trim((string)($config['ice_control_ca_file'] ?? ''));
        $this->directoryId = trim((string)($config['ice_directory_id'] ?? ''));
        $this->directoryBaseUrl = rtrim(trim((string)($config['metaverse_server_url'] ?? '')), '/');
        $storagePath = rtrim((string)($config['storage_path'] ?? ''), DIRECTORY_SEPARATOR);
        if ($storagePath === '') {
            throw new RuntimeException('Directory storage_path is not configured.');
        }
        $this->tokenFile = $storagePath . DIRECTORY_SEPARATOR . 'ice-registration.json';
        $this->validateConfiguration();
    }

    /** @return string[] Complete, unique, sorted domain UUID list. */
    public function domainIds(): array
    {
        $ids = [];
        foreach ($this->store->all('domains') as $domain) {
            $id = strtolower(trim((string)($domain['id'] ?? '')));
            if (!self::isUuid($id)) {
                throw new RuntimeException('A domain record has a missing or invalid UUID; refusing to send an incomplete ownership list.');
            }
            $ids[$id] = true;
        }
        $result = array_keys($ids);
        sort($result, SORT_STRING);
        return $result;
    }

    public static function isUuid(string $value): bool
    {
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $value) === 1;
    }

    /** Perform one-time enrollment and securely persist the returned registration token. */
    public function enroll(string $enrollmentSecret): array
    {
        if (is_file($this->tokenFile)) {
            throw new RuntimeException('This Directory Server already has an ICE registration token. Use the sync command instead of enrolling again.');
        }
        $secret = trim($enrollmentSecret);
        if ($secret === '') {
            throw new RuntimeException('The ICE enrollment secret is empty.');
        }

        $response = $this->request('/v1/enroll', $secret);
        $token = (string)($response['registration_token'] ?? '');
        if (preg_match('/^[a-f0-9]{64}$/i', $token) !== 1) {
            throw new RuntimeException('ICE enrollment response did not contain a valid registration token.');
        }
        $this->saveToken($token);
        return ['success' => true, 'domain_count' => count($this->domainIds())];
    }

    /** Synchronize the full current domain list using the previously issued token. */
    public function sync(): array
    {
        $token = $this->loadToken();
        $response = $this->request('/v1/register', $token);
        return [
            'success' => true,
            'domain_count' => count($this->domainIds()),
            'message' => (string)($response['message'] ?? 'Registered.')
        ];
    }

    private function validateConfiguration(): void
    {
        $url = parse_url($this->controlUrl);
        if (!is_array($url) || strtolower((string)($url['scheme'] ?? '')) !== 'https' ||
            empty($url['host']) || isset($url['user']) || isset($url['pass']) ||
            isset($url['query']) || isset($url['fragment'])) {
            throw new RuntimeException('ice_control_url must be an HTTPS origin, for example https://203.0.113.10:7337.');
        }
        if (isset($url['path']) && $url['path'] !== '' && $url['path'] !== '/') {
            throw new RuntimeException('ice_control_url must not include an API path.');
        }
        if (preg_match('/^[a-zA-Z0-9._-]{1,128}$/', $this->directoryId) !== 1) {
            throw new RuntimeException('ice_directory_id must be a stable identifier containing only letters, numbers, dots, underscores or hyphens.');
        }
        $base = parse_url($this->directoryBaseUrl);
        if (!is_array($base) || strtolower((string)($base['scheme'] ?? '')) !== 'https' || empty($base['host'])) {
            throw new RuntimeException('metaverse_server_url must be configured as the public HTTPS Directory Server URL.');
        }
        if ($this->caFile === '' || !is_file($this->caFile) || !is_readable($this->caFile)) {
            throw new RuntimeException('ice_control_ca_file must point to a readable CA/certificate file that trusts the ICE HTTPS certificate.');
        }
        if (!function_exists('curl_init')) {
            throw new RuntimeException('The PHP cURL extension is required for ICE registration.');
        }
    }

    private function request(string $path, string $bearerToken): array
    {
        $payload = json_encode([
            'directory_id' => $this->directoryId,
            'base_url' => $this->directoryBaseUrl,
            'domains' => $this->domainIds()
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        $curl = curl_init($this->controlUrl . $path);
        if ($curl === false) {
            throw new RuntimeException('Could not initialize the ICE HTTPS request.');
        }
        curl_setopt_array($curl, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $bearerToken
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CAINFO => $this->caFile
        ]);
        $body = curl_exec($curl);
        $error = curl_error($curl);
        $status = (int)curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);

        if ($body === false) {
            throw new RuntimeException('ICE HTTPS request failed: ' . $error);
        }
        try {
            $decoded = json_decode((string)$body, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('ICE returned invalid JSON (HTTP ' . $status . ').', 0, $exception);
        }
        if ($status !== 200 || !is_array($decoded) || ($decoded['status'] ?? '') !== 'success') {
            $message = is_array($decoded) ? (string)($decoded['message'] ?? 'Request rejected.') : 'Request rejected.';
            throw new RuntimeException('ICE rejected the registration request (HTTP ' . $status . '): ' . $message);
        }
        return $decoded;
    }

    private function saveToken(string $token): void
    {
        $json = json_encode([
            'directory_id' => $this->directoryId,
            'registration_token' => $token
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL;
        $temporary = $this->tokenFile . '.' . bin2hex(random_bytes(6)) . '.tmp';

        // Create the temporary file under a restrictive umask, then verify the
        // requested mode before writing any credential material.
        $previousUmask = umask(0077);
        $handle = @fopen($temporary, 'x');
        if ($handle === false) {
            umask($previousUmask);
            throw new RuntimeException('Could not create the temporary ICE registration token file.');
        }

        try {
            if (!chmod($temporary, 0600)) {
                throw new RuntimeException('Could not restrict permissions on the ICE registration token file.');
            }
            $written = fwrite($handle, $json);
            if ($written !== strlen($json) || !fflush($handle)) {
                throw new RuntimeException('Could not completely write the ICE registration token file.');
            }
        } catch (\\Throwable $error) {
            fclose($handle);
            @unlink($temporary);
            umask($previousUmask);
            throw $error;
        }

        fclose($handle);
        umask($previousUmask);

        // Rename is atomic on the same filesystem and preserves the verified
        // 0600 mode. Never report success if the secure file cannot be committed.
        if (!rename($temporary, $this->tokenFile)) {
            @unlink($temporary);
            throw new RuntimeException('Could not commit the ICE registration token file.');
        }
    }

    private function loadToken(): string
    {
        if (!is_file($this->tokenFile) || !is_readable($this->tokenFile)) {
            throw new RuntimeException('No ICE registration token found. Run the enroll command once first.');
        }
        try {
            $record = json_decode((string)file_get_contents($this->tokenFile), true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('The ICE registration token file is invalid.', 0, $exception);
        }
        if (!is_array($record) || ($record['directory_id'] ?? '') !== $this->directoryId) {
            throw new RuntimeException('The saved ICE registration token belongs to a different Directory Server ID.');
        }
        $token = (string)($record['registration_token'] ?? '');
        if (preg_match('/^[a-f0-9]{64}$/i', $token) !== 1) {
            throw new RuntimeException('The saved ICE registration token is malformed.');
        }
        return $token;
    }
}
