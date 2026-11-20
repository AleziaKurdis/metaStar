<?php
declare(strict_types=1);

namespace OvertePHP;

/**
 * Lightweight activity maintenance for PHP's request/response execution model.
 * A throttled pass runs on incoming requests rather than requiring a Node-style
 * always-on process. A cron job can call run() as well.
 */
final class Maintenance
{
    public static function run(JsonStore $store, array $config, ?int $now = null, bool $force = false): array
    {
        $now ??= time();
        $domainInterval = max(15, (int)($config['domain_seconds_check_if_online'] ?? 120));
        $placeInterval = max(15, (int)($config['place_check_last_activity_seconds'] ?? 175));
        $state = $store->first('maintenance', static fn(array $r): bool => ($r['id'] ?? '') === 'activity');
        $lastRun = (int)($state['lastRun'] ?? 0);
        $interval = min($domainInterval, $placeInterval);
        if (!$force && $lastRun > 0 && ($now - $lastRun) < $interval) {
            return ['skipped' => true, 'domains_offline' => 0, 'places_updated' => 0, 'expired_requests' => 0, 'expired_tokens' => 0];
        }

        $domainOfflineAfter = max(60, (int)($config['domain_seconds_until_offline'] ?? 600));
        $placeCurrentTimeout = max(1, (int)($config['place_current_timeout_minutes'] ?? 5)) * 60;
        $offlineBefore = $now - $domainOfflineAfter;
        $domainsOffline = 0;
        $expiredRequests = SocialService::cleanupExpired($store, $now);
        $expiredTokens = 0;
        foreach ($store->all('tokens') as $token) {
            $expires = isset($token['expirationTime']) ? strtotime((string)$token['expirationTime']) : false;
            if ($expires && $expires <= $now) {
                if ($store->delete('tokens', (string)($token['id'] ?? ''))) $expiredTokens++;
            }
        }

        foreach ($store->all('domains') as $domain) {
            $heartbeat = isset($domain['timeOfLastHeartbeat']) ? strtotime((string)$domain['timeOfLastHeartbeat']) : false;
            $isStale = !$heartbeat || $heartbeat < $offlineBefore;
            if ($isStale && ((int)($domain['numUsers'] ?? 0) !== 0 || (int)($domain['anonUsers'] ?? 0) !== 0 || !empty($domain['active']))) {
                $store->update('domains', (string)$domain['id'], ['numUsers' => 0, 'anonUsers' => 0, 'active' => false]);
                $domainsOffline++;
            }
        }

        $placesUpdated = 0;
        foreach ($store->all('places') as $place) {
            $currentUpdate = isset($place['currentLastUpdateTime']) ? strtotime((string)$place['currentLastUpdateTime']) : false;
            $changes = [];
            if (!$currentUpdate || $currentUpdate < ($now - $placeCurrentTimeout)) {
                $domainId = (string)($place['domainId'] ?? '');
                $domain = $domainId !== '' ? $store->first('domains', static fn(array $d): bool => ($d['id'] ?? '') === $domainId) : null;
                $attendance = (int)($domain['numUsers'] ?? 0);
                if ((int)($place['currentAttendance'] ?? 0) !== $attendance) {
                    $changes['currentAttendance'] = $attendance;
                }
                $lastActivity = $domain['timeOfLastHeartbeat'] ?? gmdate('c', $offlineBefore);
                if (($place['lastActivity'] ?? null) !== $lastActivity) {
                    $changes['lastActivity'] = $lastActivity;
                }
            } elseif (($place['lastActivity'] ?? null) !== ($place['currentLastUpdateTime'] ?? null)) {
                $changes['lastActivity'] = $place['currentLastUpdateTime'];
            }
            if ($changes) {
                $store->update('places', (string)$place['id'], $changes);
                $placesUpdated++;
            }
        }

        $record = ['id' => 'activity', 'lastRun' => $now, 'domainsOffline' => $domainsOffline, 'placesUpdated' => $placesUpdated];
        if ($state) {
            $store->update('maintenance', 'activity', $record);
        } else {
            $store->insert('maintenance', $record);
        }
        return ['skipped' => false, 'domains_offline' => $domainsOffline, 'places_updated' => $placesUpdated, 'expired_requests' => $expiredRequests, 'expired_tokens' => $expiredTokens];
    }
}
