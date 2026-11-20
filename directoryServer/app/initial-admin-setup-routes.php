<?php
use OvertePHP\Http;
use OvertePHP\JsonStore;
use OvertePHP\Auth;
use OvertePHP\InitialAdminSetup;

/** @var \OvertePHP\Router $router */
$router->add('GET', '/api/v1/setup/status', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $available = InitialAdminSetup::isAvailable($store, $config);
    Http::success([
        'available' => $available,
        'username' => $available ? (string)$config['base_admin_account'] : null
    ]);
});

$router->add('POST', '/api/v1/setup/admin', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $body = Http::body();
    try {
        $account = InitialAdminSetup::create(
            $store,
            $config,
            (string)($body['setup_key'] ?? ''),
            (string)($body['email'] ?? ''),
            (string)($body['password'] ?? '')
        );
    } catch (\RuntimeException $error) {
        $status = str_contains($error->getMessage(), 'already been completed') ? 409 : 400;
        Http::failure($error->getMessage(), $status);
    }
    Http::success(['accountId' => $account['id'], 'username' => $account['username'], 'roles' => $account['roles']]);
});
