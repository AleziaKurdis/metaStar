<?php
declare(strict_types=1);

require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\IceRegistrationService;
use OvertePHP\JsonStore;

$dir = sys_get_temp_dir() . '/overte-ice-registration-test-' . bin2hex(random_bytes(4));
$store = new JsonStore($dir);

assert(IceRegistrationService::isUuid('4784f9dc-388c-47c3-8855-373d22f31ff4'));
assert(!IceRegistrationService::isUuid('not-a-domain-id'));
assert(!IceRegistrationService::isUuid('4784f9dc-388c-47c3-8855-373d22f31ff'));

$store->insert('domains', ['id' => '4784f9dc-388c-47c3-8855-373d22f31ff4', 'name' => 'One']);
$store->insert('domains', ['id' => '11111111-2222-4333-8444-555555555555', 'name' => 'Two']);
$service = new IceRegistrationService($store, [
    'storage_path' => $dir,
    'ice_control_url' => 'https://127.0.0.1:17337',
    'ice_control_ca_file' => __FILE__,
    'ice_directory_id' => 'test-directory',
    'metaverse_server_url' => 'https://directory.example.test'
]);
$ids = $service->domainIds();
assert(count($ids) === 2);
assert($ids === ['11111111-2222-4333-8444-555555555555', '4784f9dc-388c-47c3-8855-373d22f31ff4']);

$saveToken = new ReflectionMethod($service, 'saveToken');
$saveToken->invoke($service, str_repeat('a', 64));
$tokenPath = $dir . '/ice-registration.json';
assert(is_file($tokenPath), 'Enrollment token should be persisted.');
assert((fileperms($tokenPath) & 0777) === 0600, 'Enrollment token must be stored with mode 0600.');
$tokenRecord = json_decode((string)file_get_contents($tokenPath), true);
assert(($tokenRecord['registration_token'] ?? '') === str_repeat('a', 64));

$store->insert('domains', ['id' => 'invalid-domain-id', 'name' => 'Broken']);
$failed = false;
try {
    $service->domainIds();
} catch (RuntimeException) {
    $failed = true;
}
assert($failed, 'Invalid domain IDs must block synchronization rather than silently sending an incomplete list.');

foreach (glob($dir . '/*') ?: [] as $path) {
    @unlink($path);
}
@rmdir($dir);
echo "ICE registration tests passed.\n";
