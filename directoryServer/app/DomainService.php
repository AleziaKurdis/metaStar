<?php
declare(strict_types=1);

namespace OvertePHP;

final class DomainService
{
    public const FIELD_MAP = [
        'domainId' => 'id', 'id' => 'id', 'name' => 'name', 'visibility' => 'visibility',
        'visiblity' => 'visibility', 'world_name' => 'name', 'label' => 'name',
        'public_key' => 'publicKey', 'sponsor_account_id' => 'sponsorAccountId',
        'version' => 'version', 'protocol' => 'protocol', 'network_address' => 'networkAddr',
        'network_port' => 'networkPort', 'automatic_networking' => 'networkingMode',
        'num_users' => 'numUsers', 'num_anon_users' => 'anonUsers', 'restricted' => 'restricted',
        'capacity' => 'capacity', 'description' => 'description', 'contact_info' => 'contactInfo',
        'maturity' => 'maturity', 'restriction' => 'restriction', 'managers' => 'managers',
        'tags' => 'tags', 'thumbnail' => 'thumbnail', 'images' => 'images',
        'addr_of_first_contact' => 'iPAddrOfFirstContact', 'active' => 'active',
        'when_domain_entry_created' => 'whenCreated',
        'time_of_last_heartbeat' => 'timeOfLastHeartbeat',
        'last_sender_key' => 'lastSenderKey'
    ];

    public static function isAdmin(array $account): bool
    {
        return in_array('admin', $account['roles'] ?? [], true);
    }

    public static function canSponsor(array $account, array $domain): bool
    {
        return (string)($account['id'] ?? '') !== '' &&
            (string)($account['id'] ?? '') === (string)($domain['sponsorAccountId'] ?? '');
    }

    public static function canDomain(array $account, ?array $token, array $domain): bool
    {
        return $token !== null && in_array('domain', $token['scope'] ?? [], true) &&
            self::canSponsor($account, $domain);
    }

    public static function fieldValue(array $domain, string $field): mixed
    {
        if (in_array($field, ['when_domain_entry_created_s', 'time_of_last_heartbeat_s'], true)) {
            $source = $field === 'when_domain_entry_created_s' ? 'whenCreated' : 'timeOfLastHeartbeat';
            $timestamp = isset($domain[$source]) ? strtotime((string)$domain[$source]) : false;
            return $timestamp ? (string)($timestamp * 1000) : null;
        }
        if (in_array($field, ['when_domain_entry_created', 'time_of_last_heartbeat'], true)) {
            $source = $field === 'when_domain_entry_created' ? 'whenCreated' : 'timeOfLastHeartbeat';
            $timestamp = isset($domain[$source]) ? strtotime((string)$domain[$source]) : false;
            return $timestamp ? gmdate('Y-m-d\TH:i:s.000\Z', $timestamp) : null;
        }
        if (!isset(self::FIELD_MAP[$field])) {
            return null;
        }
        $value = $domain[self::FIELD_MAP[$field]] ?? null;
        if ($field === 'public_key' && is_string($value)) {
            return preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\\s+/', '', $value);
        }
        return $value;
    }

    /** Return false for wildcard addresses that cannot be used by remote clients. */
    public static function isUsableIceServerAddress(string $address): bool
    {
        $address = trim($address);
        if ($address === '' || $address === '*') {
            return false;
        }
        return preg_match('/^(?:0\\.0\\.0\\.0|::)(?::[0-9]{1,5})?$/i', $address) !== 1;
    }

    /** Return the public Directory Server base URL, preserving the legacy request-host fallback. */
    public static function metaverseBaseUrl(array $config): string
    {
        $baseUrl = trim((string)($config['metaverse_server_url'] ?? ''));
        if ($baseUrl === '') {
            $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
            $baseUrl = $scheme . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost');
        }
        return $baseUrl;
    }

    /** Return the same effective public ICE URL used by the metaverse-info response. */
    public static function effectiveIceServerUrl(array $config): string
    {
        $configured = trim((string)($config['default_ice_server_url'] ?? ''));
        return $configured !== '' ? $configured : self::metaverseBaseUrl($config);
    }

    public static function isValidHttpUrl(string $url): bool
    {
        $url = trim($url);
        $parts = parse_url($url);
        return is_array($parts)
            && in_array(strtolower((string)($parts['scheme'] ?? '')), ['http', 'https'], true)
            && !empty($parts['host'])
            && !isset($parts['user'])
            && !isset($parts['pass'])
            && filter_var($url, FILTER_VALIDATE_URL) !== false;
    }

    public static function info(array $domain, JsonStore $store, array $config, bool $v1 = true): array
    {
        $created = isset($domain['whenCreated']) ? strtotime((string)$domain['whenCreated']) : false;
        $heartbeat = isset($domain['timeOfLastHeartbeat']) ? strtotime((string)$domain['timeOfLastHeartbeat']) : false;
        $ice = trim((string)($config['default_ice_server_url'] ?? ''));
        $storedIce = trim((string)($domain['iceServerAddr'] ?? ''));
        if (!self::isUsableIceServerAddress($storedIce)) {
            $storedIce = $ice;
        }
        $places = array_values(array_filter($store->all('places'), static fn(array $p): bool => ($p['domainId'] ?? '') === ($domain['id'] ?? '')));
        $placeInfo = array_map(static fn(array $place): array => self::placeInfo($place, $domain), $places);

        $data = [
            'domainId' => $domain['id'], 'id' => $domain['id'], 'name' => $domain['name'] ?? '',
            'visibility' => $domain['visibility'] ?? 'open', 'world_name' => $domain['name'] ?? '',
            'label' => $domain['name'] ?? '', 'public_key' => self::fieldValue($domain, 'public_key'),
            'owner_places' => $placeInfo, 'sponsor_account_id' => $domain['sponsorAccountId'] ?? null,
            'ice_server_address' => $storedIce,
            'version' => $domain['version'] ?? '', 'protocol_version' => $domain['protocol'] ?? '',
            'network_address' => $domain['networkAddr'] ?? '', 'network_port' => $domain['networkPort'] ?? null,
            'automatic_networking' => $domain['networkingMode'] ?? 'full',
            'active' => (bool)($domain['active'] ?? false),
            'restricted' => (bool)($domain['restricted'] ?? false), 'num_users' => (int)($domain['numUsers'] ?? 0),
            'anon_users' => (int)($domain['anonUsers'] ?? 0), 'total_users' => (int)($domain['numUsers'] ?? 0),
            'capacity' => (int)($domain['capacity'] ?? 0), 'description' => $domain['description'] ?? '',
            'maturity' => $domain['maturity'] ?? 'unrated', 'restriction' => $domain['restriction'] ?? 'open',
            'managers' => $domain['managers'] ?? [], 'tags' => $domain['tags'] ?? [],
            'meta' => [
                'capacity' => (int)($domain['capacity'] ?? 0), 'contact_info' => $domain['contactInfo'] ?? '',
                'description' => $domain['description'] ?? '', 'images' => $domain['images'] ?? [],
                'managers' => $domain['managers'] ?? [], 'restriction' => $domain['restriction'] ?? 'open',
                'tags' => $domain['tags'] ?? [], 'thumbnail' => $domain['thumbnail'] ?? null,
                'world_name' => $domain['name'] ?? ''
            ],
            'users' => ['num_anon_users' => (int)($domain['anonUsers'] ?? 0), 'num_users' => (int)($domain['numUsers'] ?? 0), 'user_hostnames' => $domain['hostnames'] ?? []],
            'time_of_last_heartbeat' => $heartbeat ? gmdate('Y-m-d\\TH:i:s.000\\Z', $heartbeat) : null,
            'time_of_last_heartbeat_s' => $heartbeat ? (string)($heartbeat * 1000) : null,
            'last_sender_key' => $domain['lastSenderKey'] ?? null,
            'addr_of_first_contact' => $domain['iPAddrOfFirstContact'] ?? null,
            'when_domain_entry_created' => $created ? gmdate('Y-m-d\\TH:i:s.000\\Z', $created) : null,
            'when_domain_entry_created_s' => $created ? (string)($created * 1000) : null
        ];
        if (!$v1) {
            return [
                'id' => $data['id'], 'domainId' => $data['domainId'], 'name' => $data['name'],
                'visibility' => $data['visibility'], 'capacity' => $data['capacity'],
                'sponsorAccountId' => $data['sponsor_account_id'], 'label' => $data['label'],
                'network_address' => $data['network_address'], 'network_port' => $data['network_port'],
                'ice_server_address' => $data['ice_server_address'], 'version' => $data['version'],
                'protocol_version' => $data['protocol_version'], 'active' => (bool)($domain['active'] ?? false),
                'time_of_last_heartbeat' => $data['time_of_last_heartbeat'],
                'time_of_last_heartbeat_s' => $data['time_of_last_heartbeat_s'], 'num_users' => $data['num_users']
            ];
        }
        return $data;
    }

    public static function placeInfo(array $place, ?array $domain = null): array
    {
        $path = (string)($place['path'] ?? '/0,0,0/0,0,0,1');
        $address = $path;
        if (str_starts_with($path, '/') && $domain && !empty($domain['networkAddr'])) {
            $address = (string)$domain['networkAddr'];
            if (!empty($domain['networkPort'])) {
                $address .= ':' . $domain['networkPort'];
            }
            $address .= $path;
        }
        $currentUpdate = isset($place['currentLastUpdateTime']) ? strtotime((string)$place['currentLastUpdateTime']) : false;
        $lastActivity = isset($place['lastActivity']) ? strtotime((string)$place['lastActivity']) : false;
        return [
            'placeId' => $place['id'], 'id' => $place['id'], 'name' => $place['name'] ?? '',
            'displayName' => $place['displayName'] ?? ($place['name'] ?? ''),
            'visibility' => $place['visibility'] ?? 'open', 'address' => $address,
            'path' => $path, 'description' => $place['description'] ?? '',
            'maturity' => $place['maturity'] ?? 'unrated', 'tags' => $place['tags'] ?? [],
            'managers' => $place['managers'] ?? [], 'thumbnail' => $place['thumbnail'] ?? null,
            'images' => $place['images'] ?? [], 'current_attendance' => (int)($place['currentAttendance'] ?? 0),
            'current_images' => $place['currentImages'] ?? [], 'current_info' => $place['currentInfo'] ?? '',
            'current_last_update_time' => $currentUpdate ? gmdate('Y-m-d\\TH:i:s.000\\Z', $currentUpdate) : null,
            'current_last_update_time_s' => $currentUpdate ? (string)($currentUpdate * 1000) : null,
            'last_activity_update' => $lastActivity ? gmdate('Y-m-d\\TH:i:s.000\\Z', $lastActivity) : null,
            'last_activity_update_s' => $lastActivity ? (string)($lastActivity * 1000) : null
        ];
    }

    public static function create(array $account, array $input, ?string $senderKey = null): array
    {
        $now = gmdate('c');
        $id = JsonStore::uuid();
        return [
            'id' => $id, 'name' => trim((string)$input['label']), 'visibility' => 'open',
            'apiKey' => JsonStore::uuid(), 'publicKey' => '', 'sponsorAccountId' => $account['id'],
            'version' => '', 'protocol' => '', 'networkAddr' => (string)($input['network_address'] ?? ''),
            'networkPort' => isset($input['network_port']) ? (int)$input['network_port'] : null,
            'networkingMode' => 'full', 'restricted' => false, 'numUsers' => 0, 'anonUsers' => 0,
            'hostnames' => [], 'capacity' => 0, 'description' => '', 'contactInfo' => '',
            'thumbnail' => null, 'images' => [], 'maturity' => 'unrated', 'restriction' => 'open',
            'managers' => [], 'tags' => [], 'iPAddrOfFirstContact' => $senderKey,
            'whenCreated' => $now, 'active' => false, 'timeOfLastHeartbeat' => null, 'lastSenderKey' => null
        ];
    }
}
