<?php
declare(strict_types=1);
require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\DomainService;
use OvertePHP\JsonStore;
use OvertePHP\Maintenance;

$dir = sys_get_temp_dir() . '/overte-maintenance-test-' . bin2hex(random_bytes(4));
$store = new JsonStore($dir);
$account = ['id' => JsonStore::uuid(), 'username' => 'maintenance-owner', 'roles' => ['user']];
$domain = DomainService::create($account, ['label' => 'MaintenanceTest'], '127.0.0.1');
$domain['numUsers'] = 8;
$domain['anonUsers'] = 2;
$domain['active'] = true;
$domain['timeOfLastHeartbeat'] = gmdate('c', time() - 1200);
$store->insert('domains', $domain);
$place = [
    'id' => JsonStore::uuid(), 'name' => 'MaintenancePlace', 'domainId' => $domain['id'],
    'currentAttendance' => 8, 'currentLastUpdateTime' => gmdate('c', time() - 900),
    'lastActivity' => gmdate('c', time() - 900)
];
$store->insert('places', $place);
$expiredRequest = $store->insert('requests', [
    'requestType' => 'handshake', 'requesterNodeId' => 'old-node-a', 'targetNodeId' => 'old-node-b',
    'expirationTime' => gmdate('c', time() - 120)
]);
$expiredToken = $store->insert('tokens', [
    'token' => 'expired-token', 'refreshToken' => 'expired-refresh', 'accountId' => $account['id'],
    'scope' => ['owner'], 'whenCreated' => gmdate('c', time() - 7200),
    'expirationTime' => gmdate('c', time() - 3600)
]);

$result = Maintenance::run($store, ['domain_seconds_until_offline' => 600, 'place_current_timeout_minutes' => 5], time(), true);
assert($result['domains_offline'] === 1);
assert($result['places_updated'] === 1);
assert($result['expired_requests'] === 1);
assert($result['expired_tokens'] === 1);
$updatedDomain = $store->first('domains', static fn(array $d): bool => $d['id'] === $domain['id']);
$updatedPlace = $store->first('places', static fn(array $p): bool => $p['id'] === $place['id']);
assert($updatedDomain['numUsers'] === 0 && $updatedDomain['anonUsers'] === 0 && $updatedDomain['active'] === false);
assert($updatedPlace['currentAttendance'] === 0);
assert($store->first('requests', static fn(array $r): bool => $r['id'] === $expiredRequest['id']) === null);
assert($store->first('tokens', static fn(array $t): bool => $t['id'] === $expiredToken['id']) === null);

$recentDomain = $store->update('domains', $domain['id'], ['numUsers' => 4, 'timeOfLastHeartbeat' => gmdate('c')]);
$store->update('places', $place['id'], ['currentLastUpdateTime' => null]);
Maintenance::run($store, ['domain_seconds_until_offline' => 600, 'place_current_timeout_minutes' => 5], time() + 500, true);
$recentPlace = $store->first('places', static fn(array $p): bool => $p['id'] === $place['id']);
assert($recentPlace['currentAttendance'] === 4);

foreach (glob($dir . '/*') ?: [] as $path) @unlink($path);
@rmdir($dir);
echo "Maintenance tests passed.\n";
