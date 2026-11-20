<?php
declare(strict_types=1);
require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\JsonStore;
use OvertePHP\SocialService;

$dir = sys_get_temp_dir() . '/overte-social-test-' . bin2hex(random_bytes(4));
$store = new JsonStore($dir);
$alice = $store->insert('accounts', [
    'username' => 'Alice', 'connections' => [], 'friends' => [], 'locationNodeId' => 'node-alice'
]);
$bob = $store->insert('accounts', [
    'username' => 'Bob', 'connections' => [], 'friends' => [], 'locationNodeId' => 'node-bob'
]);

$first = SocialService::handleConnectionRequest($store, $alice, 'node-alice', 'node-bob', time(), [
    'handshake_request_expiration_minutes' => 1
]);
assert($first === ['connection' => 'pending']);
assert(count($store->all('requests')) === 1);

$accepted = SocialService::handleConnectionRequest($store, $bob, 'node-bob', 'node-alice', time(), [
    'handshake_request_expiration_minutes' => 1
]);
assert($accepted === ['connection' => ['new_connection' => true, 'username' => 'Alice']]);

$aliceNow = $store->first('accounts', static fn(array $a): bool => $a['id'] === $alice['id']);
$bobNow = $store->first('accounts', static fn(array $a): bool => $a['id'] === $bob['id']);
assert($aliceNow['connections'] === ['Bob']);
assert($bobNow['connections'] === ['Alice']);

$confirmed = SocialService::handleConnectionRequest($store, $aliceNow, 'node-alice', 'node-bob', time(), [
    'handshake_request_expiration_minutes' => 1
]);
assert($confirmed === ['connection' => ['new_connection' => true, 'username' => 'Bob']]);

// Repeated confirmation is idempotent and does not duplicate either connection.
$aliceNow = $store->first('accounts', static fn(array $a): bool => $a['id'] === $alice['id']);
$bobNow = $store->first('accounts', static fn(array $a): bool => $a['id'] === $bob['id']);
assert($aliceNow['connections'] === ['Bob'] && $bobNow['connections'] === ['Alice']);

// Cancellation removes a pending request involving the user's active node.
$charlie = $store->insert('accounts', [
    'username' => 'Charlie', 'connections' => [], 'friends' => [], 'locationNodeId' => 'node-charlie'
]);
SocialService::handleConnectionRequest($store, $charlie, 'node-charlie', 'node-nobody', time(), []);
assert(SocialService::cancelConnectionRequests($store, $charlie) === 1);

// Expired requests are removed during maintenance or before the next handshake.
$store->insert('requests', [
    'requestType' => 'handshake', 'requesterNodeId' => 'old-a', 'targetNodeId' => 'old-b',
    'expirationTime' => gmdate('c', time() - 60)
]);
assert(SocialService::cleanupExpired($store, time()) === 1);

$pem = "-----BEGIN PUBLIC KEY-----\nQUJDREVGRw==\n-----END PUBLIC KEY-----\n";
assert(SocialService::simplifiedPublicKey($pem) === 'QUJDREVGRw==');
assert(SocialService::simplifiedPublicKey(null) === '');
assert(SocialService::publicKeyPemFromDer('not-a-der-key') === null);

// Verify the same PKCS#1 DER format emitted by Overte's i2d_RSAPublicKey().
$derFixture = file_get_contents(__DIR__ . '/fixtures/rsa-2048-public-pkcs1.der');
assert(is_string($derFixture) && strlen($derFixture) > 200);
$conversionDiagnostics = [];
$convertedPem = SocialService::publicKeyPemFromDer($derFixture, $conversionDiagnostics);
assert(is_string($convertedPem) && str_starts_with($convertedPem, "-----BEGIN PUBLIC KEY-----"));
$convertedKey = openssl_pkey_get_public($convertedPem);
$convertedDetails = $convertedKey ? openssl_pkey_get_details($convertedKey) : false;
assert(is_array($convertedDetails) && ($convertedDetails['type'] ?? null) === OPENSSL_KEYTYPE_RSA);
assert(($convertedDetails['bits'] ?? 0) === 2048);

assert(($conversionDiagnostics['format_attempts'][0] ?? '') === 'pkcs1_der_to_spki');
assert(($conversionDiagnostics['key_type'] ?? null) === OPENSSL_KEYTYPE_RSA);

// Also accept a client that already supplies SubjectPublicKeyInfo DER.
$spkiPem = $convertedDetails['key'];
$spkiBody = preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\\s+/', '', $spkiPem);
$spkiDerFixture = base64_decode((string)$spkiBody, true);
assert(is_string($spkiDerFixture) && $spkiDerFixture !== '');
$spkiDiagnostics = [];
$spkiConvertedPem = SocialService::publicKeyPemFromDer($spkiDerFixture, $spkiDiagnostics);
assert(is_string($spkiConvertedPem) && str_starts_with($spkiConvertedPem, "-----BEGIN PUBLIC KEY-----"));
$spkiConvertedKey = openssl_pkey_get_public($spkiConvertedPem);
$spkiConvertedDetails = $spkiConvertedKey ? openssl_pkey_get_details($spkiConvertedKey) : false;
assert(is_array($spkiConvertedDetails) && ($spkiConvertedDetails['bits'] ?? 0) === 2048);

// Exercise the PUT multipart parser with a quoted boundary and an empty api_key
// part, matching the shape observed in the Domain Server diagnostics.
$boundary = 'boundary_.oOo._test+boundary/with=characters';
$multipart = '--' . $boundary . "\r\n" .
    'Content-Disposition: form-data; name="public_key"; filename="public_key"' . "\r\n" .
    'Content-Type: application/octet-stream' . "\r\n\r\n" .
    $derFixture . "\r\n--" . $boundary . "\r\n" .
    'Content-Disposition: form-data; name="api_key"' . "\r\n\r\n" .
    "\r\n--" . $boundary . "--\r\n";
$multipartDiagnostics = [];
$extractedDer = SocialService::extractPublicKeyDerFromMultipart(
    $multipart,
    'multipart/form-data; boundary="' . $boundary . '"',
    $multipartDiagnostics
);
assert($extractedDer === $derFixture);
assert(($multipartDiagnostics['der_bytes'] ?? 0) === strlen($derFixture));

foreach (glob($dir . '/*') ?: [] as $path) @unlink($path);
@rmdir($dir);
echo "Social and connection-request tests passed.\n";
