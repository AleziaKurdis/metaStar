<?php
declare(strict_types=1);

namespace OvertePHP;

final class AccountActivity
{
    public static function isOnline(array $account, array $config, ?int $now = null): bool
    {
        $now ??= time();
        $heartbeat = isset($account['timeOfLastHeartbeat'])
            ? strtotime((string)$account['timeOfLastHeartbeat'])
            : false;
        $timeout = max(1, (int)($config['heartbeat_seconds_until_offline'] ?? 300));
        return $heartbeat !== false && $heartbeat > ($now - $timeout);
    }

    public static function locationInfo(JsonStore $store, array $account, array $config): array
    {
        $location = [
            'node_id' => $account['locationNodeId'] ?? null,
            'online' => self::isOnline($account, $config)
        ];

        $domainId = (string)($account['locationDomainId'] ?? '');
        if ($domainId !== '') {
            $domain = $store->first('domains', static fn(array $d): bool => ($d['id'] ?? '') === $domainId);
            if ($domain) {
                $location['root'] = [
                    'domain' => DomainService::info($domain, $store, $config, false)
                ];
                $location['path'] = $account['locationPath'] ?? null;
            } else {
                $location['root'] = ['domain' => [
                    'network_address' => $account['locationNetworkAddress'] ?? null,
                    'network_port' => $account['locationNetworkPort'] ?? null
                ]];
            }
        }

        return $location;
    }

    /** Validate and translate the legacy Iamus location object to account fields. */
    public static function locationChanges(array $location): array
    {
        $map = [
            'connected' => 'locationConnected',
            'path' => 'locationPath',
            'place_id' => 'locationPlaceId',
            'domain_id' => 'locationDomainId',
            'network_address' => 'locationNetworkAddress',
            'network_port' => 'locationNetworkPort',
            'node_id' => 'locationNodeId',
            'availability' => 'availability'
        ];
        $changes = [];
        foreach ($map as $input => $field) {
            if (!array_key_exists($input, $location)) {
                continue;
            }
            $value = $location[$input];
            if ($input === 'connected') {
                if (!is_bool($value)) {
                    Http::failure('connected must be a boolean');
                }
            } elseif ($input === 'path') {
                if (!is_string($value) || !preg_match('~^/[^\s]*$~', $value)) {
                    Http::failure('Invalid location path');
                }
            } elseif ($input === 'network_port') {
                if (!is_int($value) && !is_float($value)) {
                    Http::failure('network_port must be a number');
                }
                $value = (int)$value;
            } elseif ($input === 'availability') {
                $allowed = ['none', 'friends', 'connections', 'all'];
                if (!is_array($value) || array_diff($value, $allowed)) {
                    Http::failure('not legal availability value');
                }
                $value = array_values(array_unique($value));
            } elseif (!is_string($value)) {
                Http::failure($input . ' must be a string');
            }
            $changes[$field] = $value;
        }
        return $changes;
    }
}
