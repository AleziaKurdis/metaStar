<?php
declare(strict_types=1);
require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\JsonStore;
use OvertePHP\ProfileService;

$dir = sys_get_temp_dir() . '/overte-profiles-test-' . bin2hex(random_bytes(4));
$store = new JsonStore($dir);
$alice = $store->insert('accounts', [
    'username' => 'Alice', 'friends' => [], 'connections' => ['Bob'], 'availability' => ['all']
]);
$bob = $store->insert('accounts', [
    'username' => 'Bob', 'friends' => [], 'connections' => ['alice'], 'availability' => ['friends']
]);
$charlie = $store->insert('accounts', [
    'username' => 'Charlie', 'friends' => [], 'connections' => [], 'availability' => ['none']
]);

assert(ProfileService::hasName(['bOb'], 'BOB'));
assert(ProfileService::addName(['Bob'], 'BOB') === ['Bob']);
assert(ProfileService::removeName(['Bob', 'Charlie'], 'bob') === ['Charlie']);

ProfileService::addFriend($store, $alice, 'bOb');
$aliceNow = $store->first('accounts', static fn(array $a): bool => $a['id'] === $alice['id']);
assert($aliceNow['friends'] === ['bOb']);

ProfileService::removeFriend($store, $aliceNow, 'BOB');
$aliceNow = $store->first('accounts', static fn(array $a): bool => $a['id'] === $alice['id']);
$bobNow = $store->first('accounts', static fn(array $a): bool => $a['id'] === $bob['id']);
assert($aliceNow['friends'] === []);
assert($bobNow['friends'] === []);

ProfileService::addFriend($store, $alice, 'Bob');
$aliceNow = $store->first('accounts', static fn(array $a): bool => $a['id'] === $alice['id']);
ProfileService::removeConnection($store, $aliceNow, 'Bob');
$aliceNow = $store->first('accounts', static fn(array $a): bool => $a['id'] === $alice['id']);
$bobNow = $store->first('accounts', static fn(array $a): bool => $a['id'] === $bob['id']);
assert($aliceNow['connections'] === [] && $aliceNow['friends'] === []);
assert($bobNow['connections'] === [] && $bobNow['friends'] === []);

assert(ProfileService::canViewProfile($alice, ['id' => 'x', 'username' => 'Bob', 'availability' => ['all']]));
assert(!ProfileService::canViewProfile($alice, ['id' => 'x', 'username' => 'Bob', 'availability' => ['connections'], 'connections' => ['Alice']]));
assert(!ProfileService::canViewProfile($alice, ['id' => 'x', 'username' => 'Charlie', 'availability' => ['none']]));
assert(ProfileService::canViewProfile($alice, ['id' => $alice['id'], 'username' => 'Alice', 'availability' => ['none']]));

foreach (glob($dir . '/*') ?: [] as $path) @unlink($path);
@rmdir($dir);
echo "Profile and relationship tests passed.\n";
