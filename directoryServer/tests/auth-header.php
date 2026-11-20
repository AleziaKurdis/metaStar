<?php
declare(strict_types=1);

require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\Auth;
use OvertePHP\JsonStore;

$dir = sys_get_temp_dir() . '/overte-auth-header-test-' . bin2hex(random_bytes(4));
$store = new JsonStore($dir);
$account = $store->insert('accounts', ['username' => 'auth-test-user']);
$token = $store->insert('tokens', [
    'id' => JsonStore::uuid(),
    'token' => 'test-access-token-123',
    'refreshToken' => 'test-refresh-token',
    'accountId' => $account['id'],
    'scope' => ['owner'],
    'expirationTime' => gmdate('c', time() + 3600),
]);
$auth = new Auth($store, []);

$originalServer = $_SERVER;
$originalGet = $_GET;

// Standard Apache/FastCGI variable.
$_SERVER = ['HTTP_AUTHORIZATION' => 'Bearer ' . $token['token']];
$_GET = [];
assert(($auth->currentAccount()['id'] ?? null) === $account['id']);
assert($auth->authenticationDiagnostics()['authorization_source'] === 'HTTP_AUTHORIZATION');

// LiteSpeed / Apache rewrite fallback.
$_SERVER = ['REDIRECT_HTTP_AUTHORIZATION' => 'Bearer ' . $token['token']];
assert(($auth->currentAccount()['id'] ?? null) === $account['id']);
assert($auth->authenticationDiagnostics()['authorization_source'] === 'REDIRECT_HTTP_AUTHORIZATION');

// Generic CGI variable.
$_SERVER = ['AUTHORIZATION' => 'Bearer ' . $token['token']];
assert(($auth->currentAccount()['id'] ?? null) === $account['id']);

// Legacy raw token header remains accepted.
$_SERVER = ['HTTP_AUTHORIZATION' => $token['token']];
assert(($auth->currentAccount()['id'] ?? null) === $account['id']);

// Query-string fallback remains accepted when no Authorization header exists.
$_SERVER = [];
$_GET = ['access_token' => $token['token']];
assert(($auth->currentAccount()['id'] ?? null) === $account['id']);

// Invalid token diagnostics contain no credential value.
$_SERVER = ['REDIRECT_HTTP_AUTHORIZATION' => 'Bearer definitely-not-valid'];
$_GET = [];
assert($auth->currentAccount() === null);
$diagnostics = $auth->authenticationDiagnostics();
assert($diagnostics['authorization_header_present'] === true);
assert($diagnostics['matching_token_record'] === false);
assert(!in_array('definitely-not-valid', $diagnostics, true));
assert(!array_key_exists('token', $diagnostics));

// Expired token is distinguished from a token that was never received.
$store->insert('tokens', [
    'id' => JsonStore::uuid(),
    'token' => 'expired-access-token',
    'refreshToken' => 'expired-refresh-token',
    'accountId' => $account['id'],
    'scope' => ['owner'],
    'expirationTime' => gmdate('c', time() - 3600),
]);
$_SERVER = ['HTTP_AUTHORIZATION' => 'Bearer expired-access-token'];
$diagnostics = $auth->authenticationDiagnostics();
assert($diagnostics['matching_token_record'] === true);
assert($diagnostics['token_expired'] === true);
assert($diagnostics['account_record_found'] === false);

$_SERVER = $originalServer;
$_GET = $originalGet;
foreach (glob($dir . '/*') ?: [] as $path) @unlink($path);
@rmdir($dir);
echo "Authentication header tests passed.\n";
