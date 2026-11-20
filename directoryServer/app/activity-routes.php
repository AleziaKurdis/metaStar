<?php
use OvertePHP\AccountActivity;
use OvertePHP\Http;
use OvertePHP\JsonStore;
use OvertePHP\Router;
use OvertePHP\Auth;

/** @var Router $router */
$updateUserLocation = static function (array $params, JsonStore $store, Auth $auth, bool $heartbeat): never {
    $account = $auth->currentAccount();
    if (!$account) {
        Http::failure('Not logged in');
    }

    $body = Http::body();
    $location = $body['location'] ?? null;
    if ($location !== null && !is_array($location)) {
        Http::failure('location must be an object');
    }

    $changes = [];
    if (is_array($location)) {
        $changes = AccountActivity::locationChanges($location);
    }

    // Iamus only records a heartbeat when the request includes location data.
    // Keep that behavior so older clients see the same online/offline semantics.
    if ($heartbeat && is_array($location) && $changes) {
        $changes['timeOfLastHeartbeat'] = gmdate('c');
    }

    if ($changes) {
        $store->update('accounts', (string)$account['id'], $changes);
    }

    if ($heartbeat) {
        $updated = $store->first('accounts', static fn(array $a): bool => ($a['id'] ?? '') === $account['id']) ?? $account;
        $sessionId = (string)($updated['locationNodeId'] ?? '');
        Http::success($sessionId !== '' ? ['session_id' => $sessionId] : null);
    }
    Http::success();
};

$router->add('PUT', '/api/v1/user/location', static function (array $params, JsonStore $store, Auth $auth, array $config) use ($updateUserLocation): never {
    $updateUserLocation($params, $store, $auth, false);
});

$router->add('PUT', '/api/v1/user/heartbeat', static function (array $params, JsonStore $store, Auth $auth, array $config) use ($updateUserLocation): never {
    $updateUserLocation($params, $store, $auth, true);
});

$router->add('GET', '/api/v1/users/{accountId}/location', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $viewer = $auth->currentAccount();
    if (!$viewer) {
        Http::failure('Not logged in');
    }
    $identifier = rawurldecode((string)$params['accountId']);
    $target = $store->first('accounts', static fn(array $a): bool =>
        ($a['id'] ?? '') === $identifier || strcasecmp((string)($a['username'] ?? ''), $identifier) === 0
    );
    if (!$target) {
        Http::failure('target account not found');
    }
    $isOwner = ($viewer['id'] ?? '') === ($target['id'] ?? '');
    $isAdmin = in_array('admin', $viewer['roles'] ?? [], true);
    $friends = array_map('strtolower', $target['friends'] ?? []);
    $connections = array_map('strtolower', $target['connections'] ?? []);
    $viewerName = strtolower((string)($viewer['username'] ?? ''));
    if (!$isOwner && !$isAdmin && !in_array($viewerName, $friends, true) && !in_array($viewerName, $connections, true)) {
        Http::failure('unauthorized');
    }
    Http::success(['location' => AccountActivity::locationInfo($store, $target, $config)]);
});
