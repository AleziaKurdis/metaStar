<?php
use OvertePHP\AccountActivity;
use OvertePHP\Auth;
use OvertePHP\DomainService;
use OvertePHP\Http;
use OvertePHP\JsonStore;
use OvertePHP\PlaceService;

/** @var \OvertePHP\Router $router */

$requireDashboardAdmin = static function (Auth $auth): array {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in', 401);
    if (!DomainService::isAdmin($account)) Http::failure('Administrator access required', 403);
    return $account;
};

$router->add('GET', '/api/v1/admin/dashboard', static function (array $params, JsonStore $store, Auth $auth, array $config) use ($requireDashboardAdmin): never {
    $requireDashboardAdmin($auth);
    $accounts = $store->all('accounts');
    $domains = $store->all('domains');
    $places = $store->all('places');
    $tokens = $store->all('tokens');
    $requests = $store->all('requests');

    $onlineAccounts = 0;
    $verifiedAccounts = 0;
    foreach ($accounts as $account) {
        if (AccountActivity::isOnline($account, $config)) $onlineAccounts++;
        if (($account['accountEmailVerified'] ?? true) !== false) $verifiedAccounts++;
    }

    $activeDomains = 0;
    $reportedUsers = 0;
    foreach ($domains as $domain) {
        if (!empty($domain['active'])) $activeDomains++;
        $reportedUsers += max(0, (int)($domain['numUsers'] ?? 0));
    }

    $pendingRequests = 0;
    foreach ($requests as $request) {
        if (($request['status'] ?? 'pending') === 'pending') $pendingRequests++;
    }

    Http::success([
        'server' => [
            'name' => (string)($config['metaverse_name'] ?? 'Overte'),
            'version' => $config['server_version'] ?? null,
            'php_version' => PHP_VERSION,
            'server_time' => gmdate('c')
        ],
        'counts' => [
            'accounts' => count($accounts),
            'online_accounts' => $onlineAccounts,
            'verified_accounts' => $verifiedAccounts,
            'domains' => count($domains),
            'active_domains' => $activeDomains,
            'places' => count($places),
            'reported_users' => $reportedUsers,
            'tokens' => count($tokens),
            'pending_requests' => $pendingRequests
        ]
    ]);
});

$router->add('GET', '/api/v1/admin/places', static function (array $params, JsonStore $store, Auth $auth, array $config) use ($requireDashboardAdmin): never {
    $requireDashboardAdmin($auth);
    $places = $store->all('places');
    usort($places, static fn(array $a, array $b): int => strcasecmp((string)($a['name'] ?? ''), (string)($b['name'] ?? '')));
    $page = max(1, (int)($_GET['page'] ?? 1));
    $perPage = max(1, min(100, (int)($_GET['per_page'] ?? 50)));
    $total = count($places);
    $places = array_slice($places, ($page - 1) * $perPage, $perPage);
    $GLOBALS['overte_php_config'] = $config;
    Http::success([
        'places' => array_map(static fn(array $place): array => PlaceService::info($store, $place), $places),
        'current_page' => $page,
        'per_page' => $perPage,
        'total_pages' => max(1, (int)ceil($total / $perPage)),
        'total_entries' => $total
    ]);
});


$router->add('GET', '/api/v1/admin/ice/status', static function (array $params, JsonStore $store, Auth $auth, array $config) use ($requireDashboardAdmin): never {
    $requireDashboardAdmin($auth);
    try {
        $service = new IceRegistrationService($store, $config);
        Http::success($service->status());
    } catch (\\Throwable $error) {
        Http::success([
            'configured' => false,
            'registered' => false,
            'message' => $error->getMessage()
        ]);
    }
});

$router->add('POST', '/api/v1/admin/ice/enroll', static function (array $params, JsonStore $store, Auth $auth, array $config) use ($requireDashboardAdmin): never {
    $requireDashboardAdmin($auth);
    $body = Http::body();
    try {
        $service = new IceRegistrationService($store, $config);
        $result = $service->enroll((string)($body['enrollment_secret'] ?? ''));
        Http::success($result);
    } catch (\\Throwable $error) {
        Http::failure($error->getMessage(), 400);
    }
});

$router->add('POST', '/api/v1/admin/ice/recover', static function (array $params, JsonStore $store, Auth $auth, array $config) use ($requireDashboardAdmin): never {
    $requireDashboardAdmin($auth);
    $body = Http::body();
    try {
        $service = new IceRegistrationService($store, $config);
        $result = $service->recover((string)($body['enrollment_secret'] ?? ''));
        Http::success($result);
    } catch (\\Throwable $error) {
        Http::failure($error->getMessage(), 400);
    }
});

$router->add('POST', '/api/v1/admin/ice/sync', static function (array $params, JsonStore $store, Auth $auth, array $config) use ($requireDashboardAdmin): never {
    $requireDashboardAdmin($auth);
    try {
        $service = new IceRegistrationService($store, $config);
        $result = $service->sync();
        Http::success($result);
    } catch (\\Throwable $error) {
        Http::failure($error->getMessage(), 400);
    }
});
