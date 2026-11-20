<?php
declare(strict_types=1);

require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\Auth;
use OvertePHP\InitialAdminSetup;
use OvertePHP\JsonStore;

$dir = sys_get_temp_dir() . '/overte-initial-admin-test-' . bin2hex(random_bytes(4));
$config = [
    'storage_path' => $dir,
    'base_admin_account' => 'admin',
    'initial_admin_setup_key' => str_repeat('a7', 32),
    'minimum_password_length' => 1
];
$store = new JsonStore($dir);

assert(InitialAdminSetup::isAvailable($store, $config));
$failed = false;
try {
    InitialAdminSetup::create($store, $config, 'wrong-key', 'admin@example.test', 'a-long-enough-password');
} catch (RuntimeException) {
    $failed = true;
}
assert($failed);
assert(count($store->all('accounts')) === 0);

$account = InitialAdminSetup::create($store, $config, $config['initial_admin_setup_key'], 'ADMIN@example.test', 'a-long-enough-password');
assert($account['username'] === 'admin');
assert($account['email'] === 'admin@example.test');
assert(in_array('admin', $account['roles'], true));
assert(in_array('user', $account['roles'], true));
assert(Auth::passwordMatches($account, 'a-long-enough-password'));
assert(!Auth::passwordMatches($account, 'incorrect-password'));
assert(!InitialAdminSetup::isAvailable($store, $config));

$failed = false;
try {
    InitialAdminSetup::create($store, $config, $config['initial_admin_setup_key'], 'second@example.test', 'another-long-enough-password');
} catch (RuntimeException) {
    $failed = true;
}
assert($failed);
assert(count($store->all('accounts')) === 1);

foreach (glob($dir . '/*') ?: [] as $path) @unlink($path);
@rmdir($dir);
echo "Initial administrator setup tests passed.\n";
