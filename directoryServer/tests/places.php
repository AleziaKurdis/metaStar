<?php
declare(strict_types=1);
require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\Auth;
use OvertePHP\DomainService;
use OvertePHP\JsonStore;
use OvertePHP\PlaceService;

$dir = sys_get_temp_dir() . '/overte-place-test-' . bin2hex(random_bytes(4));
$store = new JsonStore($dir);
$account = ['id' => JsonStore::uuid(), 'username' => 'place-owner', 'roles' => ['user']];
$domain = DomainService::create($account, ['label' => 'PlaceTest'], '127.0.0.1');
$domain['numUsers'] = 7;
$store->insert('domains', $domain);
$auth = new Auth($store, ['domain_token_expire_hours' => 8760, 'owner_token_expire_hours' => 168]);
$token = $auth->createToken($account, ['place'], -1);
$place = [
    'id' => JsonStore::uuid(), 'name' => 'TestPlace', 'displayName' => 'Test Place',
    'description' => 'A test place', 'visibility' => 'open', 'maturity' => 'unrated',
    'tags' => ['test'], 'domainId' => $domain['id'], 'managers' => ['place-owner'],
    'path' => '/1,2,3/0,0,0,1', 'thumbnail' => null, 'images' => [],
    'currentAttendance' => 0, 'currentImages' => [], 'currentInfo' => '',
    'currentLastUpdateTime' => null, 'currentAPIKeyTokenId' => $token['id'],
    'iPAddrOfFirstContact' => '127.0.0.1', 'whenCreated' => gmdate('c'), 'lastActivity' => null
];
$store->insert('places', $place);

assert(PlaceService::validateName('Place-01.test', 32));
assert(!PlaceService::validateName('bad name', 32));
assert(PlaceService::canManage($account, $place, $domain));
assert(PlaceService::currentApiKey($store, $place) === $token['token']);
assert(PlaceService::fieldValue($store, $place, 'address') === '/1,2,3/0,0,0,1');
assert(PlaceService::fieldValue($store, $place, 'current_attendance') === 7); // falls back to domain
$info = PlaceService::info($store, $place);
assert($info['placeId'] === $place['id']);
assert($info['current_attendance'] === 7);
assert($info['domain']['id'] === $domain['id']);

$store->update('places', $place['id'], ['currentAttendance' => 3, 'currentLastUpdateTime' => gmdate('c')]);
$fresh = $store->first('places', static fn(array $p): bool => $p['id'] === $place['id']);
assert(PlaceService::fieldValue($store, $fresh, 'current_attendance') === 3);

foreach (glob($dir . '/*') ?: [] as $path) @unlink($path);
@rmdir($dir);
echo "Place tests passed.\n";
