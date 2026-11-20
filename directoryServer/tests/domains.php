<?php
declare(strict_types=1);

require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\DomainService;
use OvertePHP\JsonStore;

$dir = sys_get_temp_dir() . '/overte-domain-test-' . bin2hex(random_bytes(4));
$store = new JsonStore($dir);
$account = ['id' => JsonStore::uuid(), 'username' => 'domain-owner', 'roles' => ['user']];
$domain = DomainService::create($account, ['label' => 'TestDomain'], '127.0.0.1');
$store->insert('domains', $domain);

assert($domain['id'] !== '');
assert($domain['apiKey'] !== '');
assert($domain['sponsorAccountId'] === $account['id']);
assert($domain['maturity'] === 'unrated');
assert(DomainService::canSponsor($account, $domain));
assert(!DomainService::isAdmin($account));
assert(DomainService::fieldValue($domain, 'name') === 'TestDomain');
assert(DomainService::fieldValue($domain, 'id') === $domain['id']);
assert(DomainService::fieldValue($domain, 'when_domain_entry_created') === gmdate('Y-m-d\\TH:i:s.000\\Z', strtotime($domain['whenCreated'])));

$domainToken = ['scope' => ['domain'], 'accountId' => $account['id']];
assert(DomainService::canDomain($account, $domainToken, $domain));
assert(!DomainService::canDomain($account, ['scope' => ['owner'], 'accountId' => $account['id']], $domain));

$info = DomainService::info($domain, $store, ['default_ice_server_url' => '']);
assert($info['domainId'] === $domain['id']);
assert($info['name'] === 'TestDomain');
assert($info['maturity'] === 'unrated');
assert($info['active'] === false);
assert($info['owner_places'] === []);

$activeDomain = $store->update('domains', $domain['id'], [
    'active' => true, 'timeOfLastHeartbeat' => gmdate('c'), 'networkAddr' => '127.0.0.1', 'networkPort' => 40102
]);
$activeInfo = DomainService::info($activeDomain, $store, ['default_ice_server_url' => '']);
assert($activeInfo['active'] === true);
assert($activeInfo['time_of_last_heartbeat'] !== null);
assert($activeInfo['network_address'] === '127.0.0.1');

foreach (glob($dir . '/*') ?: [] as $path) {
    @unlink($path);
}
@rmdir($dir);
echo "Domain tests passed.\n";
