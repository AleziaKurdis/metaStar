<?php
declare(strict_types=1);

require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\DomainService;
use OvertePHP\JsonStore;
use OvertePHP\MaintenanceScheduler;

$dir = sys_get_temp_dir() . '/overte-scheduler-test-' . bin2hex(random_bytes(4));
$store = new JsonStore($dir);
$account = ['id' => JsonStore::uuid(), 'username' => 'scheduler-owner', 'roles' => ['user']];
$domain = DomainService::create($account, ['label' => 'SchedulerTest'], '127.0.0.1');
$store->insert('domains', $domain);

$disabled = MaintenanceScheduler::onDomainHeartbeat($store, ['storage_path' => $dir], 1000);
assert($disabled['queued'] === false);
assert($store->first('scheduled_tasks', static fn(array $task): bool => ($task['id'] ?? '') === 'ice_sync') === null);

// A token file is enough to indicate that enrollment has completed. The test
// does not invoke the worker, so no external ICE endpoint is contacted.
file_put_contents($dir . '/ice-registration.json', '{"registration_token":"test"}');
$config = [
    'storage_path' => $dir,
    'ice_control_url' => 'https://ice.example.invalid:7337',
    'ice_sync_interval_seconds' => 300
];

$first = MaintenanceScheduler::onDomainHeartbeat($store, $config, 1000);
assert($first['queued'] === true);
assert($first['reason'] === 'scheduled');

$state = $store->first('scheduled_tasks', static fn(array $task): bool => ($task['id'] ?? '') === 'ice_sync');
assert($state !== null && $state['pending'] === true);
assert($state['requestedAt'] === 1000);

$again = MaintenanceScheduler::onDomainHeartbeat($store, $config, 1100);
assert($again['queued'] === true);
assert($again['reason'] === 'already_pending');
$state = $store->first('scheduled_tasks', static fn(array $task): bool => ($task['id'] ?? '') === 'ice_sync');
assert($state['requestedAt'] === 1000);

// A successful run suppresses further queueing until the configured interval.
$store->update('scheduled_tasks', 'ice_sync', [
    'pending' => false,
    'lastSuccess' => 1000
]);
$notDue = MaintenanceScheduler::onDomainHeartbeat($store, $config, 1200);
assert($notDue['queued'] === false);
assert($notDue['reason'] === 'not_due');

// A domain registry change bypasses the periodic interval and queues immediately.
$registryChange = MaintenanceScheduler::onDomainRegistryChanged($store, $config, 1200);
assert($registryChange['queued'] === true);
assert($registryChange['reason'] === 'scheduled');
$state = $store->first('scheduled_tasks', static fn(array $task): bool => ($task['id'] ?? '') === 'ice_sync');
assert($state['pending'] === true);

// Simulate a completed sync; a later heartbeat still respects the normal interval.
$store->update('scheduled_tasks', 'ice_sync', ['pending' => false, 'lastSuccess' => 1000]);

$due = MaintenanceScheduler::onDomainHeartbeat($store, $config, 1300);
assert($due['queued'] === true);
assert($due['reason'] === 'scheduled');

$noWork = MaintenanceScheduler::runPending($store, ['storage_path' => $dir], 1300);
assert($noWork['skipped'] === false);
assert($noWork['success'] === false);
assert($noWork['task'] === 'ice_sync');

// The deliberately incomplete ICE config makes the worker fail locally. The
// failure is retained for retry instead of escaping into an API heartbeat.
$state = $store->first('scheduled_tasks', static fn(array $task): bool => ($task['id'] ?? '') === 'ice_sync');
assert($state['pending'] === true);
assert($state['attempts'] === 1);
assert($state['nextAttemptAt'] > 1300);
assert(is_string($state['lastError']) && $state['lastError'] !== '');

foreach (glob($dir . '/*') ?: [] as $path) {
    if (is_file($path)) @unlink($path);
}
@rmdir($dir);
echo "Maintenance scheduler tests passed.\n";
