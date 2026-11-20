<?php
declare(strict_types=1);

namespace OvertePHP;

final class ProfileService
{
    public static function hasName(array $names, string $username): bool
    {
        foreach ($names as $name) {
            if (is_string($name) && strcasecmp($name, $username) === 0) {
                return true;
            }
        }
        return false;
    }

    public static function addName(array $names, string $username): array
    {
        if (!self::hasName($names, $username)) {
            $names[] = $username;
        }
        return array_values($names);
    }

    public static function removeName(array $names, string $username): array
    {
        return array_values(array_filter($names, static fn($name): bool =>
            !is_string($name) || strcasecmp($name, $username) !== 0
        ));
    }

    public static function addFriend(JsonStore $store, array $account, string $username): void
    {
        $username = trim($username);
        if ($username === '' || strcasecmp($username, (string)($account['username'] ?? '')) === 0) {
            Http::failure('badly formed request');
        }
        $connections = is_array($account['connections'] ?? null) ? $account['connections'] : [];
        if (!self::hasName($connections, $username)) {
            Http::failure('cannot add friend who is not a connection');
        }
        $friends = is_array($account['friends'] ?? null) ? $account['friends'] : [];
        $store->update('accounts', (string)$account['id'], ['friends' => self::addName($friends, $username)]);
    }

    public static function removeFriend(JsonStore $store, array $account, string $username): void
    {
        $store->update('accounts', (string)$account['id'], [
            'friends' => self::removeName(is_array($account['friends'] ?? null) ? $account['friends'] : [], $username)
        ]);
        $other = $store->first('accounts', static fn(array $a): bool => strcasecmp((string)($a['username'] ?? ''), $username) === 0);
        if ($other) {
            $store->update('accounts', (string)$other['id'], [
                'friends' => self::removeName(is_array($other['friends'] ?? null) ? $other['friends'] : [], (string)$account['username'])
            ]);
        }
    }

    public static function removeConnection(JsonStore $store, array $account, string $username): void
    {
        $store->update('accounts', (string)$account['id'], [
            'connections' => self::removeName(is_array($account['connections'] ?? null) ? $account['connections'] : [], $username),
            'friends' => self::removeName(is_array($account['friends'] ?? null) ? $account['friends'] : [], $username)
        ]);
        $other = $store->first('accounts', static fn(array $a): bool => strcasecmp((string)($a['username'] ?? ''), $username) === 0);
        if ($other) {
            $store->update('accounts', (string)$other['id'], [
                'connections' => self::removeName(is_array($other['connections'] ?? null) ? $other['connections'] : [], (string)$account['username']),
                'friends' => self::removeName(is_array($other['friends'] ?? null) ? $other['friends'] : [], (string)$account['username'])
            ]);
        }
    }

    public static function imageInfo(array $account): array
    {
        return array_filter([
            'tiny' => $account['imagesTiny'] ?? null,
            'hero' => $account['imagesHero'] ?? null,
            'thumbnail' => $account['imagesThumbnail'] ?? null
        ], static fn($value): bool => is_string($value) && $value !== '');
    }

    public static function userInfo(JsonStore $store, array $account, array $config): array
    {
        return [
            'accountId' => $account['id'],
            'id' => $account['id'],
            'username' => $account['username'] ?? '',
            'images' => self::imageInfo($account),
            'location' => AccountActivity::locationInfo($store, $account, $config)
        ];
    }

    public static function profileInfo(JsonStore $store, array $account, array $config): array
    {
        $created = isset($account['whenCreated']) ? strtotime((string)$account['whenCreated']) : false;
        $heartbeat = isset($account['timeOfLastHeartbeat']) ? strtotime((string)$account['timeOfLastHeartbeat']) : false;
        return [
            'accountId' => $account['id'],
            'id' => $account['id'],
            'username' => $account['username'] ?? '',
            'images' => [
                'hero' => $account['imagesHero'] ?? null,
                'tiny' => $account['imagesTiny'] ?? null,
                'thumbnail' => $account['imagesThumbnail'] ?? null
            ],
            'profile_detail' => $account['profileDetail'] ?? null,
            'location' => AccountActivity::locationInfo($store, $account, $config),
            'when_account_created' => $created ? gmdate('Y-m-d\\TH:i:s.000\\Z', $created) : null,
            'when_account_created_s' => $created ? (string)($created * 1000) : null,
            'time_of_last_heartbeat' => $heartbeat ? gmdate('Y-m-d\\TH:i:s.000\\Z', $heartbeat) : null,
            'time_of_last_heartbeat_s' => $heartbeat ? (string)($heartbeat * 1000) : null
        ];
    }

    public static function canViewProfile(array $viewer, array $target): bool
    {
        if (($viewer['id'] ?? '') === ($target['id'] ?? '') || in_array('admin', $viewer['roles'] ?? [], true)) {
            return true;
        }
        // The original /profile/:accountId route grants PUBLIC, OWNER, or ADMIN
        // access. Friend/connection field permissions are handled by field APIs,
        // not by this complete public-profile response.
        $availability = is_array($target['availability'] ?? null) ? $target['availability'] : ['all'];
        return in_array('all', $availability, true);
    }

    public static function page(array $items): array
    {
        $perPage = max(1, min(1000, (int)($_GET['per_page'] ?? 20)));
        $page = max(1, min(1000, (int)($_GET['page'] ?? 1)));
        $total = count($items);
        return [
            'items' => array_slice($items, ($page - 1) * $perPage, $perPage),
            'current_page' => $page,
            'per_page' => $perPage,
            'total_pages' => max(1, (int)ceil($total / $perPage)),
            'total_entries' => $total
        ];
    }
}
