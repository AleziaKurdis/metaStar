<?php
declare(strict_types=1);

namespace OvertePHP;

final class AccountManagement
{
    private const FIELD_MAP = [
        'id' => 'id',
        'accountId' => 'id',
        'username' => 'username',
        'email' => 'email',
        'account_settings' => 'accountSettings',
        'images_hero' => 'imagesHero',
        'images_tiny' => 'imagesTiny',
        'images_thumbnail' => 'imagesThumbnail',
        'connected' => 'locationConnected',
        'path' => 'locationPath',
        'place_id' => 'locationPlaceId',
        'domain_id' => 'locationDomainId',
        'network_address' => 'locationNetworkAddress',
        'network_port' => 'locationNetworkPort',
        'node_id' => 'locationNodeId',
        'availability' => 'availability',
        'connections' => 'connections',
        'friends' => 'friends',
        'locker' => 'locker',
        'profile_detail' => 'profileDetail',
        'public_key' => 'sessionPublicKey',
        'password' => 'password',
        'xmpp_password' => 'xmppPassword',
        'discourse_api_key' => 'discourseApiKey',
        'wallet_id' => 'walletId',
        'roles' => 'roles',
        'ip_addr_of_creator' => 'IPAddrOfCreator',
        'when_account_created' => 'whenCreated',
        'when_account_created_s' => 'whenCreated',
        'time_of_last_heartbeat' => 'timeOfLastHeartbeat',
        'time_of_last_heartbeat_s' => 'timeOfLastHeartbeat'
    ];

    private const AVAILABILITY = ['none', 'friends', 'connections', 'all'];
    private const ROLES = ['user', 'admin'];

    public static function findAccount(JsonStore $store, string $identifier): ?array
    {
        $identifier = rawurldecode($identifier);
        return $store->first('accounts', static fn(array $account): bool =>
            (string)($account['id'] ?? '') === $identifier ||
            strcasecmp((string)($account['username'] ?? ''), $identifier) === 0
        );
    }

    public static function isAdmin(array $account): bool
    {
        return in_array('admin', $account['roles'] ?? [], true);
    }

    public static function canReadField(array $viewer, array $target, string $field): bool
    {
        if (!isset(self::FIELD_MAP[$field]) || $field === 'password') return false;
        $isOwner = ($viewer['id'] ?? '') === ($target['id'] ?? '');
        if (in_array($field, ['xmpp_password', 'discourse_api_key', 'wallet_id'], true)) return $isOwner;
        if ($isOwner || self::isAdmin($viewer)) return true;

        if (in_array($field, [
            'id', 'username', 'email', 'account_settings', 'images_hero', 'images_tiny', 'images_thumbnail',
            'connected', 'path', 'place_id', 'domain_id', 'network_address', 'network_port', 'node_id',
            'availability', 'public_key', 'roles', 'ip_addr_of_creator', 'when_account_created',
            'when_account_created_s', 'time_of_last_heartbeat', 'time_of_last_heartbeat_s'
        ], true)) return true;

        $viewerName = (string)($viewer['username'] ?? '');
        $targetName = (string)($target['username'] ?? '');
        $isConnection = ProfileService::hasName(is_array($viewer['connections'] ?? null) ? $viewer['connections'] : [], $targetName);
        $isFriend = ProfileService::hasName(is_array($viewer['friends'] ?? null) ? $viewer['friends'] : [], $targetName);
        if ($field === 'connections') return $isConnection || $isFriend;
        if ($field === 'friends') return $isFriend;
        return false;
    }

    public static function getField(array $viewer, array $target, string $field): mixed
    {
        if (!self::canReadField($viewer, $target, $field)) {
            Http::failure('Unauthorized');
        }
        if ($field === 'password') Http::failure('Unknown field name');
        $key = self::FIELD_MAP[$field];
        $value = $target[$key] ?? null;
        if (in_array($field, ['when_account_created', 'time_of_last_heartbeat'], true)) {
            $timestamp = $value !== null ? strtotime((string)$value) : false;
            return $timestamp ? gmdate('Y-m-d\\TH:i:s.000\\Z', $timestamp) : null;
        }
        if (in_array($field, ['when_account_created_s', 'time_of_last_heartbeat_s'], true)) {
            $timestamp = $value !== null ? strtotime((string)$value) : false;
            return $timestamp ? (string)($timestamp * 1000) : null;
        }
        if ($field === 'public_key' && is_string($value)) {
            return preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\\s+/', '', $value);
        }
        return $value;
    }

    public static function setField(JsonStore $store, array $viewer, array $target, string $field, mixed $value, array $config): void
    {
        if (!isset(self::FIELD_MAP[$field])) Http::failure('Unknown field name');
        $isOwner = ($viewer['id'] ?? '') === ($target['id'] ?? '');
        $isAdmin = self::isAdmin($viewer);
        if (!$isOwner && !$isAdmin) Http::failure('Unauthorized');

        $changes = [];
        $key = self::FIELD_MAP[$field];
        $arrayFields = ['availability', 'connections', 'friends', 'roles'];
        $stringFields = [
            'username', 'email', 'account_settings', 'images_hero', 'images_tiny', 'images_thumbnail',
            'place_id', 'domain_id', 'network_address', 'node_id', 'public_key', 'xmpp_password',
            'discourse_api_key', 'wallet_id'
        ];

        if (in_array($field, ['id', 'ip_addr_of_creator', 'when_account_created', 'when_account_created_s'], true)) {
            Http::failure('Field cannot be changed');
        }
        if ($field === 'roles' && !$isAdmin) Http::failure('Unauthorized');
        if ($field === 'time_of_last_heartbeat' || $field === 'time_of_last_heartbeat_s') Http::failure('Field cannot be changed');
        if ($field === 'password') {
            if (!is_string($value) || strlen($value) < (int)($config['minimum_password_length'] ?? 1)) {
                Http::failure('password is too short or invalid');
            }
            $salt = bin2hex(random_bytes(8));
            $changes['passwordSalt'] = $salt;
            $changes['passwordHash'] = hash_hmac('sha512', $value, $salt);
        } elseif (in_array($field, $arrayFields, true)) {
            if (!is_array($value)) Http::failure('field value must be an array or array manipulator');
            $allowed = $field === 'availability' ? self::AVAILABILITY : ($field === 'roles' ? self::ROLES : null);
            $current = is_array($target[$key] ?? null) ? $target[$key] : [];
            if (array_is_list($value)) {
                $next = $value;
            } else {
                $next = $current;
                if (isset($value['set'])) {
                    if (!is_array($value['set'])) Http::failure('set value must be an array');
                    $next = $value['set'];
                }
                foreach (['add', 'remove'] as $operation) {
                    if (!array_key_exists($operation, $value)) continue;
                    $values = is_array($value[$operation]) ? $value[$operation] : [$value[$operation]];
                    foreach ($values as $entry) {
                        if (!is_string($entry)) Http::failure('array values must be strings');
                        if ($operation === 'add') {
                            if (!ProfileService::hasName($next, $entry)) $next[] = $entry;
                        } else {
                            $next = ProfileService::removeName($next, $entry);
                        }
                    }
                }
            }
            foreach ($next as $entry) {
                if (!is_string($entry)) Http::failure('array values must be strings');
                if ($allowed !== null && !in_array($entry, $allowed, true)) Http::failure('not legal ' . $field . ' value');
            }
            $changes[$key] = array_values(array_unique($next));
        } elseif (in_array($field, $stringFields, true)) {
            if (!is_string($value)) Http::failure('field value must be a string');
            if ($field === 'username') {
                $username = trim($value);
                $maxName = (int)($config['max_name_length'] ?? 32);
                if ($username === '' || strlen($username) > $maxName || !preg_match('/^[A-Za-z][A-Za-z0-9+_.-]*$/', $username)) {
                    Http::failure('username can contain only A-Za-z0-9+-_. and must start with a letter');
                }
                $duplicate = $store->first('accounts', static fn(array $a): bool =>
                    ($a['id'] ?? '') !== ($target['id'] ?? '') && strcasecmp((string)($a['username'] ?? ''), $username) === 0
                );
                if ($duplicate) Http::failure('username already exists');
                self::replaceUsernameReferences($store, (string)$target['username'], $username);
                $value = $username;
            }
            if ($field === 'email') {
                $email = strtolower(trim($value));
                if ($email === '' || substr_count($email, '@') !== 1) Http::failure('email address needs one AT sign');
                $duplicate = $store->first('accounts', static fn(array $a): bool =>
                    ($a['id'] ?? '') !== ($target['id'] ?? '') && strcasecmp((string)($a['email'] ?? ''), $email) === 0
                );
                if ($duplicate) Http::failure('email already exists for another account');
                $value = $email;
            }
            $changes[$key] = $value;
        } elseif ($field === 'profile_detail' || $field === 'locker') {
            if (!is_array($value)) Http::failure('field value must be an object');
            $changes[$key] = $value;
        } elseif ($field === 'connected') {
            if (!is_bool($value)) Http::failure('field value must be a boolean');
            $changes[$key] = $value;
        } elseif ($field === 'path') {
            if (!is_string($value) || !preg_match('/^\\/-?\\d+(\\.\\d*)?,-?\\d+(\\.\\d*)?,-?\\d+(\\.\\d*)?\\/-?\\d+(\\.\\d*)?,-?\\d+(\\.\\d*)?,-?\\d+(\\.\\d*)?,-?\\d+(\\.\\d*)?$/', $value)) {
                Http::failure('Invalid path');
            }
            $changes[$key] = $value;
        } elseif ($field === 'network_port') {
            if (!is_int($value) && !is_float($value)) Http::failure('field value must be a number');
            $changes[$key] = $value;
        } else {
            Http::failure('Unknown or non-editable field');
        }
        if ($changes) $store->update('accounts', (string)$target['id'], $changes);
    }

    private static function replaceUsernameReferences(JsonStore $store, string $oldName, string $newName): void
    {
        foreach ($store->all('accounts') as $account) {
            $changes = [];
            foreach (['friends', 'connections'] as $field) {
                if (!is_array($account[$field] ?? null)) continue;
                $list = [];
                foreach ($account[$field] as $name) {
                    $list[] = is_string($name) && strcasecmp($name, $oldName) === 0 ? $newName : $name;
                }
                if ($list !== $account[$field]) $changes[$field] = $list;
            }
            if ($changes) $store->update('accounts', (string)$account['id'], $changes);
        }
    }

    public static function removeAccountContext(JsonStore $store, array $account): void
    {
        $username = (string)($account['username'] ?? '');
        foreach ($store->all('accounts') as $other) {
            if (($other['id'] ?? '') === ($account['id'] ?? '')) continue;
            $changes = [];
            foreach (['friends', 'connections'] as $field) {
                $list = is_array($other[$field] ?? null) ? $other[$field] : [];
                $filtered = ProfileService::removeName($list, $username);
                if ($filtered !== $list) $changes[$field] = $filtered;
            }
            if ($changes) $store->update('accounts', (string)$other['id'], $changes);
        }
        foreach ($store->all('tokens') as $token) {
            if (($token['accountId'] ?? '') === ($account['id'] ?? '')) $store->delete('tokens', (string)$token['id']);
        }
        foreach ($store->all('domains') as $domain) {
            if (($domain['sponsorAccountId'] ?? '') === ($account['id'] ?? '')) {
                $store->delete('domains', (string)$domain['id']);
                foreach ($store->all('places') as $place) {
                    if (($place['domainId'] ?? '') === ($domain['id'] ?? '')) $store->delete('places', (string)$place['id']);
                }
            }
        }
        foreach ($store->all('places') as $place) {
            if (($place['accountId'] ?? '') === ($account['id'] ?? '')) $store->delete('places', (string)$place['id']);
        }
        foreach ($store->all('requests') as $request) {
            if (($request['requesterAccountId'] ?? '') === ($account['id'] ?? '') ||
                ($request['targetAccountId'] ?? '') === ($account['id'] ?? '')) {
                $store->delete('requests', (string)$request['id']);
            }
        }
        $store->delete('accounts', (string)$account['id']);
    }
}
