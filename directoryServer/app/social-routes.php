<?php
use OvertePHP\Http;
use OvertePHP\Logger;
use OvertePHP\JsonStore;
use OvertePHP\Router;
use OvertePHP\Auth;
use OvertePHP\SocialService;
use OvertePHP\RelationshipRequestService;

/** @var Router $router */
$router->add('POST', '/api/v1/user/connection_request', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in');
    $body = Http::body();
    $request = $body['user_connection_request'] ?? null;
    if (!is_array($request)) Http::failure('badly formed request');
    $thisNode = $request['node_id'] ?? null;
    $otherNode = $request['proposed_node_id'] ?? null;
    if (!is_string($thisNode) || !is_string($otherNode)) Http::failure('badly formed request');
    Http::success(SocialService::handleConnectionRequest($store, $account, $thisNode, $otherNode, time(), $config));
});

$router->add('DELETE', '/api/v1/user/connection_request', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in');
    SocialService::cancelConnectionRequests($store, $account);
    Http::success();
});

$router->add('GET', '/api/v1/user/locker', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in');
    $locker = $account['locker'] ?? null;
    Http::success(is_array($locker) && $locker ? $locker : (object)[]);
});

$router->add('POST', '/api/v1/user/locker', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in');
    $body = Http::body();
    $store->update('accounts', (string)$account['id'], ['locker' => $body]);
    Http::success();
});

$router->add('PUT', '/api/v1/user/public_key', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in');
    $uploadDiagnostics = [];
    $der = SocialService::uploadedPublicKeyDer($uploadDiagnostics);
    if ($der === null) {
        Logger::debug($config, 'account.public_key_upload', [
            'stage' => 'multipart_extraction_failed',
            'upload' => $uploadDiagnostics,
        ]);
        Http::failure('no public key supplied');
    }
    $conversionDiagnostics = [];
    $pem = SocialService::publicKeyPemFromDer($der, $conversionDiagnostics);
    Logger::debug($config, 'account.public_key_upload', [
        'stage' => $pem === null ? 'conversion_failed' : 'conversion_succeeded',
        'upload' => $uploadDiagnostics,
        'conversion' => $conversionDiagnostics,
    ]);
    if ($pem === null) Http::failure('exception converting public key');
    $store->update('accounts', (string)$account['id'], ['sessionPublicKey' => $pem]);
    Http::success();
});

$router->add('GET', '/api/v1/users/{accountId}/public_key', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $identifier = rawurldecode((string)$params['accountId']);
    $account = $store->first('accounts', static fn(array $a): bool =>
        ($a['id'] ?? '') === $identifier || strcasecmp((string)($a['username'] ?? ''), $identifier) === 0
    );
    if (!$account) Http::failure('Target account not found');
    Http::success([
        'public_key' => SocialService::simplifiedPublicKey($account['sessionPublicKey'] ?? null),
        'username' => $account['username'] ?? '',
        'accountid' => $account['id'] ?? ''
    ]);
});

// New PHP-native API for persistent account relationship requests.
$router->add('GET', '/api/v1/user/relationship-requests', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in', 401);
    Http::success(RelationshipRequestService::listFor($store, (string)$account['id'], time()));
});

$router->add('POST', '/api/v1/user/relationship-requests', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in', 401);
    $body = Http::body();
    $type = (string)($body['type'] ?? '');
    $target = (string)($body['target'] ?? $body['username'] ?? $body['accountId'] ?? '');
    Http::json(['status' => 'success', 'data' => RelationshipRequestService::create($store, $account, $target, $type, time(), $config)], 201);
});

$router->add('POST', '/api/v1/user/relationship-requests/{requestId}/accept', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in', 401);
    $id = rawurldecode((string)$params['requestId']);
    $request = $store->first('requests', static fn(array $r): bool => ($r['id'] ?? '') === $id);
    if (!$request) Http::failure('Request not found', 404);
    Http::success(RelationshipRequestService::accept($store, $request, (string)$account['id'], time()));
});

$router->add('POST', '/api/v1/user/relationship-requests/{requestId}/reject', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in', 401);
    $id = rawurldecode((string)$params['requestId']);
    $request = $store->first('requests', static fn(array $r): bool => ($r['id'] ?? '') === $id);
    if (!$request) Http::failure('Request not found', 404);
    RelationshipRequestService::reject($store, $request, (string)$account['id']);
    Http::success();
});

$router->add('DELETE', '/api/v1/user/relationship-requests/{requestId}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in', 401);
    $id = rawurldecode((string)$params['requestId']);
    $request = $store->first('requests', static fn(array $r): bool => ($r['id'] ?? '') === $id);
    if (!$request) Http::failure('Request not found', 404);
    RelationshipRequestService::cancel($store, $request, (string)$account['id']);
    Http::success();
});
