<?php
declare(strict_types=1);

require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\Auth;
use OvertePHP\JsonStore;
use OvertePHP\Logger;

$root = sys_get_temp_dir() . '/overte-debug-log-test-' . bin2hex(random_bytes(4));
$log = $root . '/logs/test.log';
$config = ['storage_path' => $root, 'debug' => ['enabled' => true, 'auth_logging' => true, 'log_file' => $log]];

// Generic diagnostics are written only when debug.enabled is true.
Logger::debug($config, 'test.event', ['status' => 'ok', 'api_key' => 'must-not-appear']);
assert(is_file($log));
$contents = (string)file_get_contents($log);
assert(str_contains($contents, 'test.event'));
assert(str_contains($contents, '[REDACTED]'));
assert(!str_contains($contents, 'must-not-appear'));

// Authentication logging captures useful metadata, but never the access token.
$store = new JsonStore($root . '/store');
$account = $store->insert('accounts', ['username' => 'debug-user']);
$token = $store->insert('tokens', [
    'id' => JsonStore::uuid(), 'token' => 'sensitive-access-token',
    'refreshToken' => 'sensitive-refresh-token', 'accountId' => $account['id'],
    'scope' => ['owner'], 'expirationTime' => gmdate('c', time() + 3600),
]);
$oldServer = $_SERVER;
$oldGet = $_GET;
$_SERVER = ['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/api/v1/domains?access_token=do-not-log', 'HTTP_AUTHORIZATION' => 'Bearer ' . $token['token']];
$_GET = [];
$auth = new Auth($store, $config);
assert(($auth->currentAccount()['id'] ?? null) === $account['id']);
$contents = (string)file_get_contents($log);
assert(str_contains($contents, 'auth.authentication_check'));
assert(str_contains($contents, 'HTTP_AUTHORIZATION'));
assert(str_contains($contents, '"matching_token_record":true'));
assert(str_contains($contents, '"token_expired":false'));
assert(str_contains($contents, '"authenticated":true'));
assert(!str_contains($contents, 'sensitive-access-token'));
assert(!str_contains($contents, 'sensitive-refresh-token'));
assert(!str_contains($contents, 'do-not-log'));

// Both switches off means no new records are appended.
$before = filesize($log);
Logger::auth(['storage_path' => $root, 'debug' => ['enabled' => false, 'auth_logging' => true, 'log_file' => $log]], 'disabled', []);
assert(filesize($log) === $before);

$_SERVER = $oldServer;
$_GET = $oldGet;
foreach (glob($root . '/logs/*') ?: [] as $file) @unlink($file);
@rmdir($root . '/logs');
foreach (glob($root . '/store/*') ?: [] as $file) @unlink($file);
@rmdir($root . '/store');
@rmdir($root);
echo "Debug logging tests passed.\n";
