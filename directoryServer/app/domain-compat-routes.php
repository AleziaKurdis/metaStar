<?php
declare(strict_types=1);

use OvertePHP\Auth;
use OvertePHP\DomainService;
use OvertePHP\Http;
use OvertePHP\Logger;
use OvertePHP\JsonStore;
use OvertePHP\Router;
use OvertePHP\SocialService;

/** @var Router $router */

/** Extract a text field from a PUT multipart/form-data request. */
function domainMultipartTextField(string $name): ?string
{
    $contentType = (string)($_SERVER['CONTENT_TYPE'] ?? '');
    if (!preg_match('/multipart\/form-data;\s*boundary=(?:"([^"]+)"|([^;\s]+))/i', $contentType, $matches)) {
        return null;
    }
    $boundary = $matches[1] !== '' ? $matches[1] : ($matches[2] ?? '');
    if ($boundary === '') return null;
    $raw = file_get_contents('php://input');
    if (!is_string($raw) || $raw === '') {
        OvertePHP\Logger::debug($GLOBALS['overte_php_config'] ?? [], 'http.request_payload', [
            'content_type' => $contentType,
            'payload_format' => 'multipart/form-data',
            'body_bytes' => 0,
            'requested_field' => $name,
            'field_present' => false,
        ]);
        return null;
    }

    $fieldNames = [];
    if (preg_match_all('/Content-Disposition: form-data;[^\r\n]*name="([^"]+)"/i', $raw, $allFieldMatches)) {
        $fieldNames = array_values(array_unique($allFieldMatches[1]));
    }
    foreach (explode('--' . $boundary, $raw) as $part) {
        $separator = strpos($part, "\r\n\r\n");
        if ($separator === false) continue;
        $headers = substr($part, 0, $separator);
        if (!preg_match('/Content-Disposition: form-data;[^\r\n]*name="' . preg_quote($name, '/') . '"/i', $headers)) continue;
        $value = substr($part, $separator + 4);
        $value = preg_replace('/\r\n--?\s*$/', '', $value) ?? $value;
        $value = preg_replace('/\r\n$/', '', $value) ?? $value;
        OvertePHP\Logger::debug($GLOBALS['overte_php_config'] ?? [], 'http.request_payload', [
            'content_type' => $contentType,
            'payload_format' => 'multipart/form-data',
            'body_bytes' => strlen($raw),
            'field_names' => array_values(array_unique($fieldNames)),
            'requested_field' => $name,
            'field_present' => true,
            'field_value_present' => trim($value) !== '',
            'field_value_length' => strlen(trim($value)),
            'public_key_file' => isset($_FILES['public_key']) ? [
                'name' => $_FILES['public_key']['name'] ?? '',
                'type' => $_FILES['public_key']['type'] ?? '',
                'size' => $_FILES['public_key']['size'] ?? null,
                'error' => $_FILES['public_key']['error'] ?? null,
            ] : null,
        ]);
        return trim($value);
    }
    OvertePHP\Logger::debug($GLOBALS['overte_php_config'] ?? [], 'http.request_payload', [
        'content_type' => $contentType,
        'payload_format' => 'multipart/form-data',
        'body_bytes' => strlen($raw),
        'field_names' => array_values(array_unique($fieldNames)),
        'requested_field' => $name,
        'field_present' => false,
        'public_key_file' => isset($_FILES['public_key']) ? [
            'name' => $_FILES['public_key']['name'] ?? '',
            'type' => $_FILES['public_key']['type'] ?? '',
            'size' => $_FILES['public_key']['size'] ?? null,
            'error' => $_FILES['public_key']['error'] ?? null,
        ] : null,
    ]);
    return null;
}

/** Match Iamus verifyDomainAccess: bearer tokens must be domain-scoped and owned by the sponsor;
 * when no bearer token is supplied, the domain API key is used instead.
 */
function verifyIamusDomainWriteAccess(JsonStore $store, Auth $auth, array &$domain, ?string $apiKey): bool
{
    $authorization = trim((string)($_SERVER['HTTP_AUTHORIZATION'] ?? ''));
    $hasBearer = $authorization !== '' || trim((string)($_GET['access_token'] ?? '')) !== '';
    if ($hasBearer) {
        $account = $auth->currentAccount();
        $token = currentAuthToken($store);
        if (!$account || !$token || !in_array('domain', $token['scope'] ?? [], true)) return false;

        // Iamus assigns an unclaimed domain to the account presenting its domain token.
        if (empty($domain['sponsorAccountId'])) {
            $domain = $store->update('domains', (string)$domain['id'], [
                'sponsorAccountId' => (string)$account['id']
            ]) ?? $domain;
        }
        return (string)($domain['sponsorAccountId'] ?? '') === (string)$account['id'];
    }

    return is_string($apiKey) && $apiKey !== '' && !empty($domain['apiKey']) &&
        hash_equals((string)$domain['apiKey'], $apiKey);
}

$router->add('GET', '/api/v1/domains/{domainId}/public_key', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $domain = $store->first('domains', static fn(array $item): bool => ($item['id'] ?? '') === $params['domainId']);
    if (!$domain) Http::failure('No domain', 401);

    // Iamus returns the legacy single-line PEM body without BEGIN/END markers.
    Http::success(['public_key' => DomainService::fieldValue($domain, 'public_key') ?? '']);
});

$router->add('PUT', '/api/v1/domains/{domainId}/public_key', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $domain = $store->first('domains', static fn(array $item): bool => ($item['id'] ?? '') === $params['domainId']);
    if (!$domain) Http::failure('No such domain', 401);

    $apiKey = domainMultipartTextField('api_key');
    if (!verifyIamusDomainWriteAccess($store, $auth, $domain, $apiKey)) {
        Http::failure('Domain not authorized', 401);
    }

    $uploadDiagnostics = [];
    $der = SocialService::uploadedPublicKeyDer($uploadDiagnostics);
    if ($der === null) {
        Logger::debug($config, 'domain.public_key_upload', [
            'domain_id' => $params['domainId'],
            'stage' => 'multipart_extraction_failed',
            'upload' => $uploadDiagnostics,
        ]);
        Http::failure('no public key supplied');
    }

    $conversionDiagnostics = [];
    $pem = SocialService::publicKeyPemFromDer($der, $conversionDiagnostics);
    Logger::debug($config, 'domain.public_key_upload', [
        'domain_id' => $params['domainId'],
        'stage' => $pem === null ? 'conversion_failed' : 'conversion_succeeded',
        'upload' => $uploadDiagnostics,
        'conversion' => $conversionDiagnostics,
    ]);
    if ($pem === null) Http::failure('exception converting public key', 400);

    $store->update('domains', (string)$domain['id'], ['publicKey' => $pem]);
    Http::success();
});

$router->add('PUT', '/api/v1/domains/{domainId}/ice_server_address', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $domain = $store->first('domains', static fn(array $item): bool => ($item['id'] ?? '') === $params['domainId']);
    if (!$domain) Http::failure('No such domain', 401);

    $body = Http::body();
    $input = $body['domain'] ?? null;
    if (!is_array($input)) Http::failure('Badly formatted request');
    $apiKey = isset($input['api_key']) && is_string($input['api_key']) ? $input['api_key'] : null;
    if (!verifyIamusDomainWriteAccess($store, $auth, $domain, $apiKey)) {
        Http::failure('Domain not authorized', 401);
    }

    if (isset($input['ice_server_address']) && is_string($input['ice_server_address']) &&
        DomainService::isUsableIceServerAddress($input['ice_server_address'])) {
        $store->update('domains', (string)$domain['id'], ['iceServerAddr' => trim($input['ice_server_address'])]);
    }
    Http::success();
});
