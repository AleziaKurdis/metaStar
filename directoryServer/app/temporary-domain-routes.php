<?php
use OvertePHP\DomainService;
use OvertePHP\PlaceService;
use OvertePHP\JsonStore;
use OvertePHP\Auth;
use OvertePHP\Http;
use OvertePHP\Router;

/** @var Router $router */
$router->add('POST', '/api/v1/domains/temporary', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    if (empty($config['allow_temp_domain_creation'])) {
        Http::failure('domain temporary names not available');
    }

    $account = $auth->currentAccount();
    $colors = ['amber', 'azure', 'black', 'blue', 'copper', 'crimson', 'gold', 'indigo', 'jade', 'silver', 'violet'];
    $animals = ['badger', 'cougar', 'falcon', 'fox', 'lynx', 'otter', 'owl', 'panda', 'raven', 'tiger', 'wolf'];
    $name = '';
    for ($attempt = 0; $attempt < 20; $attempt++) {
        $candidate = $colors[random_int(0, count($colors) - 1)] . '-' . $animals[random_int(0, count($animals) - 1)];
        if (!$store->first('domains', static fn(array $d): bool => strcasecmp((string)($d['name'] ?? ''), $candidate) === 0)) {
            $name = $candidate;
            break;
        }
    }
    if ($name === '') Http::failure('domain temporary names not available', 503);

    $senderKey = $_SERVER['REMOTE_ADDR'] ?? null;
    $domain = DomainService::create($account ?? ['id' => null], ['label' => $name], is_string($senderKey) ? $senderKey : null);
    $domain['apiKey'] = JsonStore::uuid();
    $domain['sponsorAccountId'] = $account['id'] ?? null;

    $placeName = $name;
    if ($store->first('places', static fn(array $p): bool => strcasecmp((string)($p['name'] ?? ''), $placeName) === 0)) {
        $placeName .= '-' . strtolower(substr(str_replace('-', '', JsonStore::uuid()), 0, 5));
    }
    $token = $account ? $auth->createToken($account, ['place'], -1) : null;
    $now = gmdate('c');
    $place = [
        'id' => JsonStore::uuid(), 'name' => $placeName, 'displayName' => $placeName,
        'description' => 'A place in ' . $name, 'visibility' => 'open',
        'maturity' => $domain['maturity'] ?? 'unrated', 'tags' => [], 'domainId' => $domain['id'],
        'managers' => $account ? [(string)($account['username'] ?? '')] : [],
        'path' => '/0,0,0/0,0,0,1', 'thumbnail' => null, 'images' => [],
        'currentAttendance' => 0, 'currentImages' => [], 'currentInfo' => '',
        'currentLastUpdateTime' => null, 'currentAPIKeyTokenId' => $token['id'] ?? null,
        'iPAddrOfFirstContact' => is_string($senderKey) ? $senderKey : null,
        'whenCreated' => $now, 'lastActivity' => null,
        'sponsorAccountId' => $account['id'] ?? null
    ];

    $store->insert('domains', $domain);
    $store->insert('places', $place);
    $GLOBALS['overte_php_config'] = $config;
    $domainInfo = DomainService::info($domain, $store, $config, false);
    $domainInfo['api_key'] = $domain['apiKey'];
    $placeInfo = PlaceService::info($store, $place);
    if ($token) $placeInfo['current_api_key'] = $token['token'];
    Http::success(['domain' => $domainInfo, 'place' => $placeInfo]);
});
