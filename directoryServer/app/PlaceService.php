<?php
declare(strict_types=1);

namespace OvertePHP;

final class PlaceService
{
    public const FIELD_MAP = [
        'placeId' => 'id', 'id' => 'id', 'name' => 'name', 'displayName' => 'displayName',
        'description' => 'description', 'visibility' => 'visibility', 'domainId' => 'domainId',
        'maturity' => 'maturity', 'tags' => 'tags', 'managers' => 'managers',
        'address' => 'path', 'path' => 'path', 'thumbnail' => 'thumbnail', 'images' => 'images',
        'current_attendance' => 'currentAttendance', 'current_images' => 'currentImages',
        'current_info' => 'currentInfo', 'current_last_update_time' => 'currentLastUpdateTime',
        'current_api_key' => 'currentAPIKeyTokenId', 'addr_of_first_contact' => 'iPAddrOfFirstContact',
        'when_place_entry_created' => 'whenCreated'
    ];

    public static function domainFor(JsonStore $store, array $place): ?array
    {
        $id = (string)($place['domainId'] ?? '');
        return $id === '' ? null : $store->first('domains', static fn(array $d): bool => ($d['id'] ?? '') === $id);
    }

    public static function isManager(array $account, array $place, ?array $domain): bool
    {
        $username = strtolower((string)($account['username'] ?? ''));
        if ($username === '') return false;
        $managers = array_map('strtolower', $domain['managers'] ?? []);
        $placeManagers = array_map('strtolower', $place['managers'] ?? []);
        return in_array($username, $managers, true) || in_array($username, $placeManagers, true);
    }

    public static function canManage(array $account, array $place, ?array $domain): bool
    {
        return DomainService::isAdmin($account) ||
            ($domain !== null && DomainService::canSponsor($account, $domain)) ||
            self::isManager($account, $place, $domain);
    }

    public static function currentApiKey(JsonStore $store, array $place): ?string
    {
        $id = (string)($place['currentAPIKeyTokenId'] ?? '');
        if ($id === '') return null;
        $token = $store->first('tokens', static fn(array $t): bool => ($t['id'] ?? '') === $id);
        return $token['token'] ?? null;
    }

    public static function info(JsonStore $store, array $place, bool $includeDomain = true): array
    {
        $domain = self::domainFor($store, $place);
        $info = DomainService::placeInfo($place, $domain);
        if ($includeDomain && $domain) {
            $config = $GLOBALS['overte_php_config'] ?? [];
            $info['domain'] = DomainService::info($domain, $store, $config, false);
        }
        $last = isset($place['currentLastUpdateTime']) ? strtotime((string)$place['currentLastUpdateTime']) : false;
        $config = $GLOBALS['overte_php_config'] ?? [];
        $timeout = max(1, (int)($config['place_current_timeout_minutes'] ?? 5)) * 60;
        $fresh = $last && $last > time() - $timeout;
        if (!$fresh) {
            $info['current_attendance'] = (int)($domain['numUsers'] ?? 0);
            $info['current_images'] = [];
            $info['current_info'] = '';
        }
        return $info;
    }

    public static function fieldValue(JsonStore $store, array $place, string $field): mixed
    {
        $domain = self::domainFor($store, $place);
        if ($field === 'address') {
            return DomainService::placeInfo($place, $domain)['address'];
        }
        if ($field === 'current_api_key') {
            return self::currentApiKey($store, $place);
        }
        if ($field === 'current_last_update_time_s' || $field === 'when_place_entry_created_s') {
            $key = $field === 'current_last_update_time_s' ? 'currentLastUpdateTime' : 'whenCreated';
            $timestamp = isset($place[$key]) ? strtotime((string)$place[$key]) : false;
            return $timestamp ? (string)($timestamp * 1000) : null;
        }
        if ($field === 'current_last_update_time' || $field === 'when_place_entry_created') {
            $key = $field === 'current_last_update_time' ? 'currentLastUpdateTime' : 'whenCreated';
            $timestamp = isset($place[$key]) ? strtotime((string)$place[$key]) : false;
            return $timestamp ? gmdate('Y-m-d\TH:i:s.000\Z', $timestamp) : null;
        }
        $key = self::FIELD_MAP[$field] ?? null;
        if ($key === null) return null;
        if ($field === 'current_attendance') {
            $last = isset($place['currentLastUpdateTime']) ? strtotime((string)$place['currentLastUpdateTime']) : false;
            $config = $GLOBALS['overte_php_config'] ?? [];
            $timeout = max(1, (int)($config['place_current_timeout_minutes'] ?? 5)) * 60;
            if (!$last || $last <= time() - $timeout) return (int)($domain['numUsers'] ?? 0);
        }
        return $place[$key] ?? null;
    }

    public static function validateName(string $name, int $maxLength): bool
    {
        return $name !== '' && strlen($name) <= $maxLength &&
            (bool)preg_match('/^[A-Za-z0-9][A-Za-z0-9.-]*$/', $name);
    }
}
