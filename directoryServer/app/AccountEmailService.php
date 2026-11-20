<?php
declare(strict_types=1);

namespace OvertePHP;

final class AccountEmailService
{
    public static function issueVerification(JsonStore $store, array $account, array $config): bool
    {
        $existing = $store->first('requests', static fn(array $r): bool =>
            ($r['requestType'] ?? '') === 'verifyEmail' && ($r['requestingAccountId'] ?? '') === (string)$account['id']
        );
        $cooldown = max(0, (int)($config['email_resend_cooldown_seconds'] ?? 60));
        $lastSent = $existing ? strtotime((string)($existing['whenCreated'] ?? '')) : false;
        if ($lastSent && $lastSent > time() - $cooldown) return false;
        $code = bin2hex(random_bytes(24));
        $minutes = max(5, (int)($config['email_verification_timeout_minutes'] ?? 1440));
        $request = $store->insert('requests', [
            'id' => JsonStore::uuid(), 'requestType' => 'verifyEmail',
            'requestingAccountId' => $account['id'], 'verificationCode' => $code,
            'whenCreated' => gmdate('c'), 'expirationTime' => gmdate('c', time() + $minutes * 60)
        ]);
        $url = EmailService::baseUrl($config) . '/api/v1/account/verify/email?a=' . rawurlencode((string)$account['id']) . '&v=' . rawurlencode($code);
        $body = "Hello " . ($account['username'] ?? 'there') . ",\n\n" .
            "Please verify your email address for " . ($config['metaverse_name'] ?? 'your Overte metaverse') . ":\n\n" .
            $url . "\n\nThis link expires in " . $minutes . " minutes.\n\n" .
            "If you did not create this account, you can ignore this message.\n";
        $sent = EmailService::send($config, (string)$account['email'], 'Verify your email address', $body);
        if (!$sent) {
            $store->delete('requests', (string)$request['id']);
            return false;
        }
        self::deleteRequestsExcept($store, (string)$account['id'], 'verifyEmail', (string)$request['id']);
        return true;
    }

    public static function verify(JsonStore $store, string $accountId, string $code): bool
    {
        $request = $store->first('requests', static fn(array $r): bool =>
            ($r['requestType'] ?? '') === 'verifyEmail' &&
            ($r['requestingAccountId'] ?? '') === $accountId
        );
        if (!$request || !hash_equals((string)($request['verificationCode'] ?? ''), $code)) return false;
        $expires = strtotime((string)($request['expirationTime'] ?? ''));
        if (!$expires || $expires <= time()) {
            $store->delete('requests', (string)$request['id']);
            return false;
        }
        $account = $store->first('accounts', static fn(array $a): bool => ($a['id'] ?? '') === $accountId);
        if (!$account) {
            $store->delete('requests', (string)$request['id']);
            return false;
        }
        $store->update('accounts', $accountId, ['accountEmailVerified' => true]);
        $store->delete('requests', (string)$request['id']);
        return true;
    }

    public static function requestPasswordReset(JsonStore $store, array $config, string $email): bool
    {
        $email = strtolower(trim($email));
        $account = $store->first('accounts', static fn(array $a): bool => strcasecmp((string)($a['email'] ?? ''), $email) === 0);
        if (!$account || !filter_var($email, FILTER_VALIDATE_EMAIL)) return false;
        $existing = $store->first('requests', static fn(array $r): bool =>
            ($r['requestType'] ?? '') === 'passwordReset' && ($r['requestingAccountId'] ?? '') === (string)$account['id']
        );
        $cooldown = max(0, (int)($config['email_resend_cooldown_seconds'] ?? 60));
        $lastSent = $existing ? strtotime((string)($existing['whenCreated'] ?? '')) : false;
        if ($lastSent && $lastSent > time() - $cooldown) return false;
        $token = bin2hex(random_bytes(32));
        $minutes = max(5, (int)($config['password_reset_timeout_minutes'] ?? 60));
        $request = $store->insert('requests', [
            'id' => JsonStore::uuid(), 'requestType' => 'passwordReset',
            'requestingAccountId' => $account['id'], 'tokenHash' => hash('sha256', $token),
            'whenCreated' => gmdate('c'), 'expirationTime' => gmdate('c', time() + $minutes * 60)
        ]);
        $resetBase = trim((string)($config['password_reset_url'] ?? ''));
        if ($resetBase === '') $resetBase = EmailService::baseUrl($config) . '/password-reset';
        $url = $resetBase . (str_contains($resetBase, '?') ? '&' : '?') . 'token=' . rawurlencode($token);
        $body = "Hello " . ($account['username'] ?? 'there') . ",\n\n" .
            "A password reset was requested for your " . ($config['metaverse_name'] ?? 'Overte metaverse') . " account.\n\n" .
            "Use this one-time token in the password reset form:\n" . $token . "\n\n" .
            "You can also open this link if your website provides a password reset page:\n" . $url . "\n\n" .
            "This token expires in " . $minutes . " minutes. If you did not request this, ignore this message.\n";
        $sent = EmailService::send($config, (string)$account['email'], 'Password reset request', $body);
        if (!$sent) {
            $store->delete('requests', (string)$request['id']);
            return false;
        }
        self::deleteRequestsExcept($store, (string)$account['id'], 'passwordReset', (string)$request['id']);
        return true;
    }

    public static function resetPassword(JsonStore $store, array $config, string $token, string $password): bool
    {
        if ($token === '' || strlen($password) < (int)($config['minimum_password_length'] ?? 1)) return false;
        $hash = hash('sha256', $token);
        $request = $store->first('requests', static fn(array $r): bool =>
            ($r['requestType'] ?? '') === 'passwordReset' &&
            hash_equals((string)($r['tokenHash'] ?? ''), $hash)
        );
        if (!$request) return false;
        $expires = strtotime((string)($request['expirationTime'] ?? ''));
        if (!$expires || $expires <= time()) {
            $store->delete('requests', (string)$request['id']);
            return false;
        }
        $accountId = (string)($request['requestingAccountId'] ?? '');
        $account = $store->first('accounts', static fn(array $a): bool => ($a['id'] ?? '') === $accountId);
        if (!$account) {
            $store->delete('requests', (string)$request['id']);
            return false;
        }
        $salt = bin2hex(random_bytes(8));
        $store->update('accounts', $accountId, [
            'passwordSalt' => $salt, 'passwordHash' => hash_hmac('sha512', $password, $salt)
        ]);
        $store->delete('requests', (string)$request['id']);
        foreach ($store->all('tokens') as $authToken) {
            if (($authToken['accountId'] ?? '') === $accountId) $store->delete('tokens', (string)$authToken['id']);
        }
        return true;
    }

    private static function deleteRequestsExcept(JsonStore $store, string $accountId, string $type, string $keepId): void
    {
        foreach ($store->find('requests', static fn(array $r): bool =>
            ($r['requestType'] ?? '') === $type &&
            ($r['requestingAccountId'] ?? '') === $accountId &&
            ($r['id'] ?? '') !== $keepId
        ) as $request) {
            $store->delete('requests', (string)$request['id']);
        }
    }
}
