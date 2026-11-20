<?php
declare(strict_types=1);
require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\AccountManagement;
use OvertePHP\Auth;
use OvertePHP\JsonStore;

$dir = sys_get_temp_dir() . '/overte-account-management-' . bin2hex(random_bytes(4));
$store = new JsonStore($dir);
$config = ['minimum_password_length' => 8, 'max_name_length' => 32, 'owner_token_expire_hours' => 168, 'domain_token_expire_hours' => 8760];
$alice = $store->insert('accounts', [
    'username' => 'Alice', 'email' => 'alice@example.test', 'roles' => ['user'],
    'passwordSalt' => 'old-salt', 'passwordHash' => hash_hmac('sha512', 'old-password', 'old-salt'),
    'friends' => ['Bob'], 'connections' => ['Bob'], 'availability' => ['all'],
    'whenCreated' => gmdate('c')
]);
$bob = $store->insert('accounts', [
    'username' => 'Bob', 'email' => 'bob@example.test', 'roles' => ['user'],
    'friends' => ['Alice'], 'connections' => ['Alice'], 'availability' => ['all']
]);
$charlie = $store->insert('accounts', [
    'username' => 'Charlie', 'email' => 'charlie@example.test', 'roles' => ['user'],
    'friends' => [], 'connections' => [], 'availability' => ['all']
]);

assert(AccountManagement::findAccount($store, 'Alice')['id'] === $alice['id']);
assert(AccountManagement::findAccount($store, rawurlencode('Alice'))['id'] === $alice['id']);
assert(AccountManagement::canReadField($bob, $alice, 'friends'));
assert(AccountManagement::canReadField($bob, $alice, 'connections'));
assert(!AccountManagement::canReadField($charlie, $alice, 'friends'));
assert(!AccountManagement::canReadField($charlie, $alice, 'locker'));
assert(!AccountManagement::canReadField($charlie, $alice, 'password'));
assert(!AccountManagement::canReadField(['id' => 'admin', 'roles' => ['admin']], $alice, 'wallet_id'));

AccountManagement::setField($store, $alice, $alice, 'friends', ['add' => 'Charlie'], $config);
$aliceNow = AccountManagement::findAccount($store, $alice['id']);
assert(AccountManagement::canReadField($charlie, $aliceNow, 'friends') === false);
assert(in_array('Charlie', $aliceNow['friends'], true));
AccountManagement::setField($store, $aliceNow, $aliceNow, 'availability', ['friends'], $config);
assert(AccountManagement::findAccount($store, $alice['id'])['availability'] === ['friends']);

AccountManagement::setField($store, $aliceNow, $aliceNow, 'email', 'ALICE2@example.test', $config);
assert(AccountManagement::findAccount($store, $alice['id'])['email'] === 'alice2@example.test');
AccountManagement::setField($store, $aliceNow, $aliceNow, 'username', 'Alicia', $config);
assert(AccountManagement::findAccount($store, $alice['id'])['username'] === 'Alicia');
$bobNow = AccountManagement::findAccount($store, $bob['id']);
assert($bobNow['friends'] === ['Alicia'] && $bobNow['connections'] === ['Alicia']);

AccountManagement::setField($store, $aliceNow, $aliceNow, 'password', 'new-password', $config);
$auth = new Auth($store, $config);
assert(Auth::passwordMatches(AccountManagement::findAccount($store, $alice['id']), 'new-password'));
assert(!Auth::passwordMatches(AccountManagement::findAccount($store, $alice['id']), 'old-password'));

$token = $auth->createToken($alice, ['owner']);
assert($token['scope'] === ['owner']);
assert(strtotime($token['expirationTime']) > strtotime($token['whenCreated']));
$domainToken = $auth->createToken($alice, ['domain']);
assert(strtotime($domainToken['expirationTime']) - strtotime($domainToken['whenCreated']) > 300 * 86400);

$store->insert('domains', ['id' => 'domain-owned', 'sponsorAccountId' => $alice['id']]);
$store->insert('places', ['id' => 'place-owned', 'accountId' => $alice['id'], 'domainId' => 'domain-owned']);
$store->insert('requests', ['id' => 'request-owned', 'requesterAccountId' => $alice['id']]);
AccountManagement::removeAccountContext($store, AccountManagement::findAccount($store, $alice['id']));
assert(AccountManagement::findAccount($store, $alice['id']) === null);
assert(AccountManagement::findAccount($store, $bob['id'])['friends'] === []);
assert(AccountManagement::findAccount($store, $bob['id'])['connections'] === []);
assert($store->first('tokens', static fn(array $t): bool => ($t['accountId'] ?? '') === $alice['id']) === null);
assert($store->first('domains', static fn(array $d): bool => ($d['id'] ?? '') === 'domain-owned') === null);
assert($store->first('places', static fn(array $p): bool => ($p['id'] ?? '') === 'place-owned') === null);
assert($store->first('requests', static fn(array $r): bool => ($r['id'] ?? '') === 'request-owned') === null);

foreach (glob($dir . '/*') ?: [] as $path) @unlink($path);
@rmdir($dir);
echo "Account management and token tests passed.\n";
