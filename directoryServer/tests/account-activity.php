<?php
declare(strict_types=1);
require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\AccountActivity;
use OvertePHP\DomainService;
use OvertePHP\JsonStore;

$dir = sys_get_temp_dir() . '/overte-account-activity-test-' . bin2hex(random_bytes(4));
$store = new JsonStore($dir);
$config = ['heartbeat_seconds_until_offline' => 300];

$account = [
    'id' => JsonStore::uuid(), 'username' => 'activity-user',
    'timeOfLastHeartbeat' => gmdate('c', time() - 30),
    'locationNodeId' => 'node-123', 'locationPath' => '/1,2,3/0,0,0,1',
    'locationDomainId' => '', 'availability' => ['all']
];
$store->insert('accounts', $account);
assert(AccountActivity::isOnline($account, $config));
$oldAccount = $account;
$oldAccount['timeOfLastHeartbeat'] = gmdate('c', time() - 600);
assert(!AccountActivity::isOnline($oldAccount, $config));

$changes = AccountActivity::locationChanges([
    'connected' => true,
    'path' => '/10,20,30/0,0.1,0,0.99',
    'domain_id' => 'domain-abc',
    'place_id' => 'place-abc',
    'network_address' => 'example.org',
    'network_port' => 40102,
    'node_id' => 'node-456',
    'availability' => ['friends', 'all']
]);
assert($changes['locationConnected'] === true);
assert($changes['locationPath'] === '/10,20,30/0,0.1,0,0.99');
assert($changes['locationNetworkPort'] === 40102);
assert($changes['availability'] === ['friends', 'all']);

$domainAccount = ['id' => JsonStore::uuid(), 'username' => 'domain-owner', 'roles' => ['user']];
$domain = DomainService::create($domainAccount, ['label' => 'ActivityDomain'], '127.0.0.1');
$store->insert('domains', $domain);
$account['locationDomainId'] = $domain['id'];
$location = AccountActivity::locationInfo($store, $account, $config);
assert(($location['node_id'] ?? '') === 'node-123');
assert(($location['online'] ?? false) === true);
assert(($location['root']['domain']['id'] ?? '') === $domain['id']);
assert(($location['path'] ?? '') === '/1,2,3/0,0,0,1');

foreach (glob($dir . '/*') ?: [] as $path) @unlink($path);
@rmdir($dir);
echo "Account activity tests passed.\n";
