<?php
declare(strict_types=1);

namespace OvertePHP;

use RuntimeException;

final class InitialAdminSetup
{
    public static function isAvailable(JsonStore $store, array $config): bool
    {
        return self::configured($config) && count($store->all('accounts')) === 0;
    }

    public static function create(JsonStore $store, array $config, string $setupKey, string $email, string $password): array
    {
        $expectedKey = (string)($config['initial_admin_setup_key'] ?? '');
        $username = trim((string)($config['base_admin_account'] ?? ''));
        if ($expectedKey === '' || strlen($expectedKey) < 32 || $username === '') {
            throw new RuntimeException('Initial administrator setup is not configured.');
        }
        if (!hash_equals($expectedKey, $setupKey)) {
            throw new RuntimeException('Invalid setup key.');
        }
        if (!preg_match('/^[A-Za-z][A-Za-z0-9+_.-]{0,31}$/', $username)) {
            throw new RuntimeException('The configured base_admin_account username is invalid.');
        }
        $email = strtolower(trim($email));
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new RuntimeException('Enter a valid email address.');
        }
        $minimumLength = max(12, (int)($config['minimum_password_length'] ?? 1));
        if (strlen($password) < $minimumLength) {
            throw new RuntimeException('The administrator password must contain at least ' . $minimumLength . ' characters.');
        }

        $lockPath = rtrim((string)$config['storage_path'], DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '.initial-admin-setup.lock';
        $lock = fopen($lockPath, 'c');
        if (!$lock) {
            throw new RuntimeException('Unable to lock initial administrator setup.');
        }
        try {
            if (!flock($lock, LOCK_EX)) {
                throw new RuntimeException('Unable to lock initial administrator setup.');
            }
            if (count($store->all('accounts')) !== 0) {
                throw new RuntimeException('Initial setup has already been completed.');
            }
            $salt = bin2hex(random_bytes(16));
            return $store->insert('accounts', [
                'id' => JsonStore::uuid(),
                'username' => $username,
                'email' => $email,
                'passwordSalt' => $salt,
                'passwordHash' => hash_hmac('sha512', $password, $salt),
                'roles' => ['user', 'admin'],
                'friends' => [],
                'connections' => [],
                'availability' => ['all'],
                'accountEmailVerified' => null,
                'whenCreated' => gmdate('c')
            ]);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private static function configured(array $config): bool
    {
        return trim((string)($config['base_admin_account'] ?? '')) !== '' &&
            strlen((string)($config['initial_admin_setup_key'] ?? '')) >= 32;
    }
}
