<?php
declare(strict_types=1);

require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\JsonStore;
use OvertePHP\Auth;

$dir = sys_get_temp_dir() . '/overte-php-test-' . bin2hex(random_bytes(4));
$store = new JsonStore($dir);
$record = $store->insert('accounts', ['username' => 'test-user']);
assert($record['id'] !== '');
assert(count($store->all('accounts')) === 1);
$updated = $store->update('accounts', $record['id'], ['email' => 'test@example.invalid']);
assert($updated['email'] === 'test@example.invalid');
assert($store->delete('accounts', $record['id']) === true);
assert(count($store->all('accounts')) === 0);

$account = ['passwordSalt' => '0123456789abcdef', 'passwordHash' => hash_hmac('sha512', 'secret', '0123456789abcdef')];
assert(Auth::passwordMatches($account, 'secret'));
assert(!Auth::passwordMatches($account, 'wrong'));

foreach (glob($dir . '/*') ?: [] as $path) {
    @unlink($path);
}
@rmdir($dir);
echo "Smoke tests passed.\n";
