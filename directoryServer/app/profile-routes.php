<?php
use OvertePHP\AccountActivity;
use OvertePHP\Http;
use OvertePHP\JsonStore;
use OvertePHP\Router;
use OvertePHP\Auth;
use OvertePHP\ProfileService;

/** @var Router $router */
$router->add('GET', '/api/v1/user/friends', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in');
    $page = ProfileService::page(is_array($account['friends'] ?? null) ? $account['friends'] : []);
    Http::success(['friends' => $page['items'], 'current_page' => $page['current_page'], 'per_page' => $page['per_page'],
        'total_pages' => $page['total_pages'], 'total_entries' => $page['total_entries']]);
});

$router->add('POST', '/api/v1/user/friends', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in');
    $username = Http::body()['username'] ?? null;
    if (!is_string($username) || trim($username) === '') Http::failure('badly formed request');
    ProfileService::addFriend($store, $account, $username);
    Http::success();
});

$router->add('DELETE', '/api/v1/user/friends/{param1}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in');
    ProfileService::removeFriend($store, $account, rawurldecode((string)$params['param1']));
    Http::success();
});

$router->add('GET', '/api/v1/user/connections', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in');
    $page = ProfileService::page(is_array($account['connections'] ?? null) ? $account['connections'] : []);
    Http::success(['connections' => $page['items'], 'current_page' => $page['current_page'], 'per_page' => $page['per_page'],
        'total_pages' => $page['total_pages'], 'total_entries' => $page['total_entries']]);
});

$router->add('POST', '/api/v1/user/connections', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    Http::failure('cannot add connections this way');
});

$router->add('DELETE', '/api/v1/user/connections/{param1}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in');
    ProfileService::removeConnection($store, $account, rawurldecode((string)$params['param1']));
    Http::success();
});

$router->add('GET', '/api/v1/users/connections', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in');
    $names = is_array($account['connections'] ?? null) ? $account['connections'] : [];
    $items = [];
    foreach ($names as $name) {
        if (!is_string($name)) continue;
        $other = $store->first('accounts', static fn(array $a): bool => strcasecmp((string)($a['username'] ?? ''), $name) === 0);
        if ($other) {
            $items[] = [
                'username' => $name,
                'connection' => ProfileService::hasName($account['friends'] ?? [], $name) ? 'friend' : 'connection',
                'images' => ProfileService::imageInfo($other),
                'location' => AccountActivity::locationInfo($store, $other, $config)
            ];
        } else {
            $items[] = ['username' => $name, 'connection' => 'unknown'];
        }
    }
    $page = ProfileService::page($items);
    Http::success(['users' => $page['items'], 'current_page' => $page['current_page'], 'per_page' => $page['per_page'],
        'total_pages' => $page['total_pages'], 'total_entries' => $page['total_entries']]);
});

$router->add('GET', '/api/v1/profile/{accountId}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $identifier = rawurldecode((string)$params['accountId']);
    $target = $store->first('accounts', static fn(array $a): bool =>
        ($a['id'] ?? '') === $identifier || strcasecmp((string)($a['username'] ?? ''), $identifier) === 0
    );
    if (!$target) Http::failure('Target account not found');
    $viewer = $auth->currentAccount();
    $availability = is_array($target['availability'] ?? null) ? $target['availability'] : ['all'];
    $publicAvailability = in_array('all', $availability, true);
    if (!$publicAvailability && (!$viewer || !ProfileService::canViewProfile($viewer, $target))) {
        Http::failure('Unauthorized');
    }
    Http::success(['account' => ProfileService::profileInfo($store, $target, $config)]);
});

$router->add('GET', '/api/v1/profiles', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $accounts = array_values(array_filter($store->all('accounts'), static fn(array $a): bool =>
        in_array('all', is_array($a['availability'] ?? null) ? $a['availability'] : ['all'], true)
    ));
    usort($accounts, static fn(array $a, array $b): int => strcasecmp((string)($a['username'] ?? ''), (string)($b['username'] ?? '')));
    $page = ProfileService::page($accounts);
    Http::success(['profiles' => array_map(static fn(array $a): array => ProfileService::profileInfo($store, $a, $config), $page['items']),
        'current_page' => $page['current_page'], 'per_page' => $page['per_page'],
        'total_pages' => $page['total_pages'], 'total_entries' => $page['total_entries']]);
});

$router->add('GET', '/api/v1/user/profile', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in');
    Http::success(['user' => [
        'username' => $account['username'] ?? '',
        'accountid' => $account['id'] ?? '',
        'xmpp_password' => $account['xmppPassword'] ?? null,
        'discourse_api_key' => $account['discourseApiKey'] ?? null,
        'wallet_id' => $account['walletId'] ?? null
    ]]);
});
