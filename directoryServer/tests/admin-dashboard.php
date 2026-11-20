<?php
declare(strict_types=1);

require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\AccountActivity;
use OvertePHP\DomainService;
use OvertePHP\JsonStore;

$dir = sys_get_temp_dir() . '/overte-admin-dashboard-test-' . bin2hex(random_bytes(4));
$store = new JsonStore($dir);
$admin = ['id' => JsonStore::uuid(), 'username' => 'dashboard-admin', 'roles' => ['user', 'admin']];
$user = ['id' => JsonStore::uuid(), 'username' => 'dashboard-user', 'roles' => ['user'], 'accountEmailVerified' => false];
$store->insert('accounts', $admin + ['accountEmailVerified' => true]);
$store->insert('accounts', $user);
$store->insert('domains', ['id' => JsonStore::uuid(), 'name' => 'DashboardDomain', 'active' => true, 'numUsers' => 3]);
$store->insert('places', ['id' => JsonStore::uuid(), 'name' => 'DashboardPlace', 'domainId' => $store->all('domains')[0]['id']]);
$store->insert('tokens', ['id' => JsonStore::uuid(), 'accountId' => $admin['id']]);
$store->insert('requests', ['id' => JsonStore::uuid(), 'status' => 'pending']);

$accounts = $store->all('accounts');
$domains = $store->all('domains');
$places = $store->all('places');
$tokens = $store->all('tokens');
$requests = $store->all('requests');

assert(count($accounts) === 2);
assert(count($domains) === 1);
assert(count($places) === 1);
assert(count($tokens) === 1);
assert(count(array_filter($requests, static fn(array $r): bool => ($r['status'] ?? 'pending') === 'pending')) === 1);
assert(DomainService::isAdmin($admin));
assert(!DomainService::isAdmin($user));
assert(!AccountActivity::isOnline($user, ['heartbeat_seconds_until_offline' => 300]));

foreach (glob($dir . '/*') ?: [] as $path) @unlink($path);
@rmdir($dir);
echo "Admin dashboard tests passed.\n";
