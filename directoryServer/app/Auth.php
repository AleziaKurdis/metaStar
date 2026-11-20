<?php
declare(strict_types=1);

namespace OvertePHP;

final class Auth
{
    public function __construct(private JsonStore $store, private array $config) {}

    public function accountForBearer(?string $token): ?array
    {
        if (!$token) {
            return null;
        }
        $authToken = $this->store->first('tokens', static fn(array $t): bool =>
            hash_equals((string)($t['token'] ?? ''), $token) &&
            (strtotime((string)($t['expirationTime'] ?? '1970-01-01')) ?: 0) > time()
        );
        if (!$authToken) {
            return null;
        }
        return $this->store->first('accounts', static fn(array $a): bool => ($a['id'] ?? null) === ($authToken['accountId'] ?? null));
    }

    /**
     * Read Authorization consistently across Apache, CGI/FastCGI and LiteSpeed.
     * Returns the value and the server variable/header source without logging it.
     */
    private function authorizationHeader(): array
    {
        foreach (['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION', 'AUTHORIZATION'] as $key) {
            $value = trim((string)($_SERVER[$key] ?? ''));
            if ($value !== '') {
                return ['value' => $value, 'source' => $key];
            }
        }

        foreach (['getallheaders', 'apache_request_headers'] as $function) {
            if (!function_exists($function)) {
                continue;
            }
            $headers = $function();
            if (!is_array($headers)) {
                continue;
            }
            foreach ($headers as $name => $value) {
                if (strcasecmp((string)$name, 'Authorization') === 0 && trim((string)$value) !== '') {
                    return ['value' => trim((string)$value), 'source' => $function . ':Authorization'];
                }
            }
        }

        return ['value' => '', 'source' => 'none'];
    }

    /** Extract the credential using the legacy raw-token fallback as well. */
    private function requestToken(array $header): array
    {
        $value = (string)$header['value'];
        if ($value !== '') {
            if (preg_match('/^Bearer\s+(.+)$/i', $value, $matches)) {
                return ['token' => trim($matches[1]), 'source' => $header['source'], 'scheme' => 'Bearer'];
            }
            return ['token' => $value, 'source' => $header['source'], 'scheme' => 'non-Bearer'];
        }

        $queryToken = trim((string)($_GET['access_token'] ?? ''));
        if ($queryToken !== '') {
            return ['token' => $queryToken, 'source' => 'query:access_token', 'scheme' => 'query'];
        }
        return ['token' => '', 'source' => 'none', 'scheme' => 'none'];
    }

    public function currentAccount(): ?array
    {
        $header = $this->authorizationHeader();
        $credential = $this->requestToken($header);
        $account = $this->accountForBearer($credential['token'] !== '' ? $credential['token'] : null);

        // This records the result and safe metadata only; no credential value is retained.
        Logger::auth($this->config, 'authentication_check', [
            'authenticated' => $account !== null,
            'diagnostics' => $this->authenticationDiagnostics(),
        ]);
        return $account;
    }

    /** Safe diagnostics for authentication failures. Never returns the token itself. */
    public function authenticationDiagnostics(): array
    {
        $header = $this->authorizationHeader();
        $credential = $this->requestToken($header);
        $token = $credential['token'];
        $record = null;
        if ($token !== '') {
            $record = $this->store->first('tokens', static fn(array $t): bool =>
                hash_equals((string)($t['token'] ?? ''), $token)
            );
        }
        $expiration = $record ? (strtotime((string)($record['expirationTime'] ?? '1970-01-01')) ?: 0) : 0;
        $account = ($record && $expiration > time())
            ? $this->store->first('accounts', static fn(array $a): bool => ($a['id'] ?? null) === ($record['accountId'] ?? null))
            : null;

        return [
            'authorization_header_present' => $header['value'] !== '',
            'authorization_source' => $header['source'],
            'credential_source' => $credential['source'],
            'credential_scheme' => $credential['scheme'],
            'credential_present' => $token !== '',
            'credential_length' => strlen($token),
            'matching_token_record' => $record !== null,
            'token_expired' => $record !== null && $expiration <= time(),
            'account_record_found' => $account !== null,
        ];
    }

    public function createToken(array $account, array $scopes, int $expireHours = 0): array
    {
        $allowed = ['owner', 'domain', 'place'];
        $scopes = array_values(array_intersect($scopes, $allowed));
        $now = time();
        $domain = in_array('domain', $scopes, true);
        $hours = $expireHours === 0
            ? (int)($domain ? $this->config['domain_token_expire_hours'] : $this->config['owner_token_expire_hours'])
            : max(1, min(1000000, $expireHours));
        $expiration = $expireHours === -1 ? gmmktime(0, 0, 0, 1, 1, 2400) : $now + $hours * 3600;
        $token = [
            'id' => JsonStore::uuid(),
            'token' => JsonStore::uuid(),
            'refreshToken' => JsonStore::uuid(),
            'scope' => $scopes,
            'accountId' => $account['id'],
            'whenCreated' => gmdate('c', $now),
            'expirationTime' => gmdate('c', $expiration)
        ];
        return $this->store->insert('tokens', $token);
    }

    public function tokenForRefresh(string $refreshToken): ?array
    {
        return $this->store->first('tokens', static fn(array $t): bool =>
            hash_equals((string)($t['refreshToken'] ?? ''), $refreshToken)
        );
    }

    public function revokeToken(array $token): bool
    {
        return $this->store->delete('tokens', (string)$token['id']);
    }

    public static function passwordMatches(array $account, string $password): bool
    {
        $salt = (string)($account['passwordSalt'] ?? '');
        $expected = (string)($account['passwordHash'] ?? '');
        if ($salt === '' || $expected === '') {
            return false;
        }
        // Exact Iamus format: HMAC-SHA512(password, salt), hexadecimal digest.
        return hash_equals($expected, hash_hmac('sha512', $password, $salt));
    }

    public static function oauthBody(array $account, array $token): array
    {
        $created = strtotime((string)$token['whenCreated']);
        $expires = strtotime((string)$token['expirationTime']);
        return [
            'access_token' => $token['token'],
            'token_type' => 'Bearer',
            'expires_in' => max(0, $expires - $created),
            'refresh_token' => $token['refreshToken'],
            'scope' => $token['scope'][0] ?? 'owner',
            'created_at' => $created,
            'account_id' => $account['id'],
            'account_name' => $account['username'],
            'account_roles' => $account['roles'] ?? ['user']
        ];
    }
}
