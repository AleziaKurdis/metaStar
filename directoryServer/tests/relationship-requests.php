<?php
declare(strict_types=1);
require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\JsonStore;
use OvertePHP\RelationshipRequestService;

$dir = sys_get_temp_dir() . '/overte-relationship-test-' . bin2hex(random_bytes(4));
$store = new JsonStore($dir);
$alice = $store->insert('accounts', ['username' => 'Alice', 'connections' => [], 'friends' => [], 'following' => [], 'followers' => []]);
$bob = $store->insert('accounts', ['username' => 'Bob', 'connections' => [], 'friends' => [], 'following' => [], 'followers' => []]);
$carol = $store->insert('accounts', ['username' => 'Carol', 'connections' => [], 'friends' => [], 'following' => [], 'followers' => []]);
$now = time();
$config = ['relationship_request_expiration_days' => 14];

// Connection request is visible to both parties and creates mutual connections on acceptance.
$connection = RelationshipRequestService::create($store, $alice, 'Bob', 'connection', $now, $config);
assert($connection['requestType'] === 'connection');
assert(count(RelationshipRequestService::listFor($store, $bob['id'], $now)) === 1);
$result = RelationshipRequestService::accept($store, $connection, $bob['id'], $now);
assert($result['accepted'] === true);
$a = $store->first('accounts', static fn(array $r): bool => $r['id'] === $alice['id']);
$b = $store->first('accounts', static fn(array $r): bool => $r['id'] === $bob['id']);
assert($a['connections'] === ['Bob'] && $b['connections'] === ['Alice']);
assert(RelationshipRequestService::listFor($store, $bob['id'], $now) === []);

// Friendship acceptance also establishes a connection.
$friend = RelationshipRequestService::create($store, $alice, 'Carol', 'friend', $now, $config);
RelationshipRequestService::accept($store, $friend, $carol['id'], $now);
$a = $store->first('accounts', static fn(array $r): bool => $r['id'] === $alice['id']);
$c = $store->first('accounts', static fn(array $r): bool => $r['id'] === $carol['id']);
assert($a['friends'] === ['Carol'] && $c['friends'] === ['Alice']);
assert($a['connections'] === ['Bob', 'Carol'] && $c['connections'] === ['Alice']);

// Follow is directional and does not create a connection.
$follow = RelationshipRequestService::create($store, $bob, 'Carol', 'follow', $now, $config);
RelationshipRequestService::accept($store, $follow, $carol['id'], $now);
$b = $store->first('accounts', static fn(array $r): bool => $r['id'] === $bob['id']);
$c = $store->first('accounts', static fn(array $r): bool => $r['id'] === $carol['id']);
assert($b['following'] === ['Carol'] && $c['followers'] === ['Bob']);
assert($b['connections'] === ['Alice']);

// Opposite pending request auto-completes instead of creating a duplicate pair.
$pending = RelationshipRequestService::create($store, $alice, 'Bob', 'friend', $now, $config);
$reverse = RelationshipRequestService::create($store, $bob, 'Alice', 'friend', $now, $config);
assert(($reverse['accepted'] ?? false) === true);
assert($store->first('requests', static fn(array $r): bool => ($r['id'] ?? '') === ($pending['id'] ?? '')) === null);

// Expiration cleanup applies to long-lived relationship requests.
$expired = $store->insert('requests', [
    'requestType' => 'follow', 'requestingAccountId' => $alice['id'], 'targetAccountId' => $carol['id'],
    'whenCreated' => gmdate('c', $now - 86400), 'expirationTime' => gmdate('c', $now - 1)
]);
assert(RelationshipRequestService::cleanupExpired($store, $now) === 1);
assert($store->first('requests', static fn(array $r): bool => ($r['id'] ?? '') === $expired['id']) === null);

// Cancellation is limited to the requester; rejected requests do not alter relationships.
$cancel = RelationshipRequestService::create($store, $alice, 'Carol', 'follow', $now, $config);
assert(RelationshipRequestService::cancel($store, $cancel, $alice['id']) === true);
$reject = RelationshipRequestService::create($store, $alice, 'Carol', 'follow', $now, $config);
assert(RelationshipRequestService::reject($store, $reject, $carol['id']) === true);
$c = $store->first('accounts', static fn(array $r): bool => $r['id'] === $carol['id']);
assert($c['followers'] === ['Bob']);

foreach (glob($dir . '/*') ?: [] as $path) @unlink($path);
@rmdir($dir);
echo "Relationship request tests passed.\n";
