<?php
use OvertePHP\PlaceService;
use OvertePHP\DomainService;
use OvertePHP\JsonStore;
use OvertePHP\Auth;
use OvertePHP\Http;
use OvertePHP\Router;

/** @var Router $router */

$placeFind = static function (JsonStore $store, string $id): ?array {
    return $store->first('places', static fn(array $p): bool => ($p['id'] ?? '') === $id);
};
$placeTokenForRequest = static function (JsonStore $store): ?array { return currentAuthToken($store); };

// Public place discovery. The original service only exposes open places in this listing.
$router->add('GET', '/api/v1/places', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $query = trim((string)($_GET['search'] ?? ''));
    $maturity = trim((string)($_GET['maturity'] ?? ''));
    $tags = array_values(array_filter(array_map('trim', explode(',', (string)($_GET['tag'] ?? '')))));
    $places = array_values(array_filter($store->all('places'), static function (array $place) use ($query, $maturity, $tags, $store): bool {
        if (($place['visibility'] ?? 'open') !== 'open') return false;
        if ($query !== '' && stripos((string)($place['name'] ?? '') . ' ' . (string)($place['displayName'] ?? ''), $query) === false) return false;
        if ($maturity !== '' && ($place['maturity'] ?? 'unrated') !== $maturity) return false;
        if ($tags) {
            $placeTags = array_map('strtolower', $place['tags'] ?? []);
            $matched = false;
            foreach ($tags as $tag) if (in_array(strtolower($tag), $placeTags, true)) $matched = true;
            if (!$matched) return false;
        }
        return true;
    }));
    $order = array_map('trim', explode(',', (string)($_GET['order'] ?? 'ascending')));
    usort($places, static function (array $a, array $b) use ($order, $store): int {
        foreach ($order as $criterion) {
            if ($criterion === 'num_users') {
                $da = PlaceService::domainFor($store, $a); $db = PlaceService::domainFor($store, $b);
                $cmp = (int)($db['numUsers'] ?? 0) <=> (int)($da['numUsers'] ?? 0);
                if ($cmp !== 0) return $cmp;
            } elseif ($criterion === 'name' || $criterion === 'ascending') {
                $cmp = strcasecmp((string)($a['name'] ?? ''), (string)($b['name'] ?? ''));
                if ($cmp !== 0) return $cmp;
            } elseif ($criterion === 'descending') {
                $cmp = strcasecmp((string)($b['name'] ?? ''), (string)($a['name'] ?? ''));
                if ($cmp !== 0) return $cmp;
            }
        }
        return 0;
    });
    $perPage = max(1, min(100, (int)($_GET['per_page'] ?? 50)));
    $page = max(0, (int)($_GET['page_num'] ?? $_GET['page'] ?? 0));
    $total = count($places);
    $places = array_slice($places, $page * $perPage, $perPage);
    $GLOBALS['overte_php_config'] = $config;
    Http::success(['places' => array_map(static fn(array $p): array => PlaceService::info($store, $p), $places),
        'maturity-categories' => ['unrated', 'everyone', 'teen', 'mature', 'adult'],
        'pagination' => ['page_num' => $page, 'per_page' => $perPage, 'total' => $total]]);
});

// Current activity endpoint is deliberately API-key authenticated, not session authenticated.
$router->add('POST', '/api/v1/places/current', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $body = Http::body();
    $id = (string)($body['placeId'] ?? '');
    $place = $id !== '' ? $store->first('places', static fn(array $p): bool => ($p['id'] ?? '') === $id) : null;
    if (!$place) Http::failure('Place specified by placeId does not exist');
    $key = (string)($body['current_api_key'] ?? '');
    $expected = PlaceService::currentApiKey($store, $place);
    if ($key === '' || !$expected || !hash_equals($expected, $key)) Http::failure('current_api_key does not match Places key', 401);
    $changes = [];
    if (array_key_exists('current_attendance', $body)) {
        if (!is_numeric($body['current_attendance']) || (float)$body['current_attendance'] < 0) Http::failure('current_attendance must be a non-negative number');
        $changes['currentAttendance'] = (float)$body['current_attendance'];
    }
    if (array_key_exists('current_images', $body)) {
        if (!is_array($body['current_images'])) Http::failure('current_images must be an array');
        foreach ($body['current_images'] as $item) if (!is_string($item)) Http::failure('current_images values must be strings');
        $changes['currentImages'] = array_values($body['current_images']);
    }
    if (array_key_exists('current_info', $body)) {
        if (!is_string($body['current_info'])) Http::failure('current_info must be a string');
        $changes['currentInfo'] = $body['current_info'];
    }
    $changes['currentLastUpdateTime'] = gmdate('c');
    $updated = $store->update('places', $place['id'], $changes) ?? $place;
    Http::success();
});

$router->add('POST', '/api/v1/places/current/refreshkey', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $body = Http::body();
    $place = $store->first('places', static fn(array $p): bool => ($p['id'] ?? '') === (string)($body['placeId'] ?? ''));
    if (!$place) Http::failure('Place specified by placeId does not exist');
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in', 401);
    $domain = PlaceService::domainFor($store, $place);
    $admin = DomainService::isAdmin($account);
    if (!PlaceService::canManage($account, $place, $domain)) Http::failure('Unauthorized', 403);
    $oldKey = (string)($body['current_api_key'] ?? '');
    if (!$admin || !filter_var($_GET['asAdmin'] ?? false, FILTER_VALIDATE_BOOLEAN)) {
        $expected = PlaceService::currentApiKey($store, $place);
        if ($oldKey === '' || !$expected || !hash_equals($expected, $oldKey)) Http::failure('current_api_key does not match Places key', 401);
    }
    $oldId = (string)($place['currentAPIKeyTokenId'] ?? '');
    if ($oldId !== '') $store->delete('tokens', $oldId);
    $newToken = $auth->createToken($account, ['place'], -1);
    $store->update('places', $place['id'], ['currentAPIKeyTokenId' => $newToken['id']]);
    Http::success(['current_api_key' => $newToken['token']]);
});

$router->add('GET', '/api/v1/user/domains', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in', 401);

    $domains = array_values(array_filter($store->all('domains'), static fn(array $domain): bool =>
        ($domain['sponsorAccountId'] ?? '') === ($account['id'] ?? '')
    ));
    usort($domains, static fn(array $a, array $b): int => strcmp(
        (string)($b['whenCreated'] ?? ''), (string)($a['whenCreated'] ?? '')
    ));

    Http::success(['domains' => array_map(static fn(array $domain): array =>
        DomainService::info($domain, $store, $config), $domains
    )]);
});

$router->add('GET', '/api/v1/user/places', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in', 401);
    $domains = [];
    foreach ($store->all('domains') as $domain) if (($domain['sponsorAccountId'] ?? '') === ($account['id'] ?? '')) $domains[$domain['id']] = true;
    $places = array_values(array_filter($store->all('places'), static fn(array $p): bool => isset($domains[$p['domainId'] ?? ''])));
    $GLOBALS['overte_php_config'] = $config;
    Http::success(['places' => array_map(static fn(array $p): array => PlaceService::info($store, $p), $places),
        'maturity-categories' => ['unrated', 'everyone', 'teen', 'mature', 'adult']]);
});

$router->add('POST', '/api/v1/user/places', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in', 401);
    $body = Http::body(); $input = $body['place'] ?? $body;
    if (!is_array($input)) Http::failure('Badly formed place data');
    $name = trim((string)($input['name'] ?? $input['place_id'] ?? ''));
    $address = (string)($input['address'] ?? $input['path'] ?? '');
    $domainId = (string)($input['domainId'] ?? $input['domain_id'] ?? '');
    if ($name === '' || $address === '' || $domainId === '') Http::failure('name, address, and domainId must be specified');
    if (!PlaceService::validateName($name, (int)($config['max_name_length'] ?? 32))) Http::failure('Invalid place name');
    if (isset($input['displayName']) && !is_string($input['displayName'])) Http::failure('displayName must be a string');
    if (isset($input['description']) && !is_string($input['description'])) Http::failure('description must be a string');
    if (!preg_match('~^(/[^\s]*)$~', $address)) Http::failure('Invalid place address');
    $domain = $store->first('domains', static fn(array $d): bool => ($d['id'] ?? '') === $domainId);
    if (!$domain) Http::failure('Domain not found', 404);
    if (!DomainService::isAdmin($account) && !DomainService::canSponsor($account, $domain)) Http::failure('Unauthorized', 403);
    if ($store->first('places', static fn(array $p): bool => strcasecmp((string)($p['name'] ?? ''), $name) === 0)) Http::failure('Place name already exists');
    $token = $auth->createToken($account, ['place'], -1);
    $now = gmdate('c');
    $place = [
        'id' => JsonStore::uuid(), 'name' => $name, 'displayName' => (string)($input['displayName'] ?? $name),
        'description' => (string)($input['description'] ?? ''), 'visibility' => 'open',
        'maturity' => $domain['maturity'] ?? 'unrated', 'tags' => [], 'domainId' => $domainId,
        'managers' => [$account['username'] ?? ''], 'path' => $address, 'thumbnail' => null, 'images' => [],
        'currentAttendance' => 0, 'currentImages' => [], 'currentInfo' => '', 'currentLastUpdateTime' => null,
        'currentAPIKeyTokenId' => $token['id'], 'iPAddrOfFirstContact' => $_SERVER['REMOTE_ADDR'] ?? null,
        'whenCreated' => $now, 'lastActivity' => null, 'sponsorAccountId' => $domain['sponsorAccountId'] ?? $account['id']
    ];
    $store->insert('places', $place);
    $GLOBALS['overte_php_config'] = $config;
    $info = PlaceService::info($store, $place);
    $info['current_api_key'] = $token['token'];
    Http::success(['place' => $info, 'maturity-categories' => ['unrated', 'everyone', 'teen', 'mature', 'adult']]);
});

$router->add('GET', '/api/v1/places/{placeId}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $place = $store->first('places', static fn(array $p): bool => ($p['id'] ?? '') === $params['placeId']);
    if (!$place) Http::failure('No such place', 404);
    $GLOBALS['overte_php_config'] = $config;
    $info = PlaceService::info($store, $place);
    $account = $auth->currentAccount(); $domain = PlaceService::domainFor($store, $place);
    if ($account && $domain && (DomainService::isAdmin($account) || DomainService::canSponsor($account, $domain))) {
        $info['current_api_key'] = PlaceService::currentApiKey($store, $place);
    }
    Http::success(['place' => $info, 'maturity-categories' => ['unrated', 'everyone', 'teen', 'mature', 'adult']]);
});

$router->add('GET', '/api/v1/user/places/{placeId}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount(); if (!$account) Http::failure('Not logged in', 401);
    $place = $store->first('places', static fn(array $p): bool => ($p['id'] ?? '') === $params['placeId']);
    if (!$place) Http::failure('No such place', 404);
    $domain = PlaceService::domainFor($store, $place);
    if (!PlaceService::canManage($account, $place, $domain)) Http::failure('Unauthorized', 403);
    $GLOBALS['overte_php_config'] = $config;
    $info = PlaceService::info($store, $place); $info['current_api_key'] = PlaceService::currentApiKey($store, $place);
    Http::success(['place' => $info, 'maturity-categories' => ['unrated', 'everyone', 'teen', 'mature', 'adult']]);
});

$router->add('PUT', '/api/v1/places/{placeId}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount(); if (!$account) Http::failure('Not logged in', 401);
    $place = $store->first('places', static fn(array $p): bool => ($p['id'] ?? '') === $params['placeId']);
    if (!$place) Http::failure('Target place not found', 404);
    $domain = PlaceService::domainFor($store, $place);
    if (!DomainService::isAdmin($account) && (!$domain || !DomainService::canSponsor($account, $domain))) Http::failure('Unauthorized', 403);
    $body = Http::body(); $input = $body['place'] ?? null;
    if (!is_array($input)) Http::failure('badly formed data');
    $changes = [];
    if (!empty($input['pointee_query']) && $input['pointee_query'] !== ($place['domainId'] ?? '')) {
        $newDomain = $store->first('domains', static fn(array $d): bool => ($d['id'] ?? '') === (string)$input['pointee_query']);
        if (!$newDomain || (!DomainService::isAdmin($account) && !DomainService::canSponsor($account, $newDomain))) Http::failure('Unauthorized to assign place to target domain', 403);
        $changes['domainId'] = $newDomain['id'];
    }
    foreach (['path', 'description', 'thumbnail'] as $field) {
        if (!array_key_exists($field, $input)) continue;
        if (!is_string($input[$field])) Http::failure($field . ' must be a string');
        if ($field === 'path' && !preg_match('~^/[^\s]*$~', $input[$field])) Http::failure('Invalid place address');
        $changes[$field] = $input[$field];
    }
    $updated = $store->update('places', $place['id'], $changes) ?? $place;
    $GLOBALS['overte_php_config'] = $config;
    Http::success(['place' => PlaceService::info($store, $updated)]);
});

$deletePlace = static function (array $params, JsonStore $store, Auth $auth): never {
    $account = $auth->currentAccount(); if (!$account) Http::failure('Not logged in', 401);
    $place = $store->first('places', static fn(array $p): bool => ($p['id'] ?? '') === $params['placeId']);
    if (!$place) Http::failure('Target place not found', 404);
    $domain = PlaceService::domainFor($store, $place);
    if (!DomainService::isAdmin($account) && (!$domain || !DomainService::canSponsor($account, $domain))) Http::failure('Unauthorized', 403);
    $tokenId = (string)($place['currentAPIKeyTokenId'] ?? '');
    if ($tokenId !== '') $store->delete('tokens', $tokenId);
    $store->delete('places', $place['id']);
    Http::success();
};
$router->add('DELETE', '/api/v1/places/{placeId}', static function (array $params, JsonStore $store, Auth $auth, array $config) use ($deletePlace): never { $deletePlace($params, $store, $auth); });
$router->add('DELETE', '/api/v1/user/places/{placeId}', static function (array $params, JsonStore $store, Auth $auth, array $config) use ($deletePlace): never { $deletePlace($params, $store, $auth); });

$router->add('GET', '/api/v1/places/{placeId}/field/{fieldname}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $place = $store->first('places', static fn(array $p): bool => ($p['id'] ?? '') === $params['placeId']);
    if (!$place) Http::failure('Place not found', 404);
    $field = $params['fieldname'];
    $allowed = array_merge(array_keys(PlaceService::FIELD_MAP), ['current_last_update_time_s', 'when_place_entry_created_s']);
    if (!in_array($field, $allowed, true)) Http::failure('Unknown field name');
    if ($field === 'current_api_key') {
        $account = $auth->currentAccount(); $domain = PlaceService::domainFor($store, $place);
        if (!$account || !$domain || (!DomainService::isAdmin($account) && !DomainService::canSponsor($account, $domain))) Http::failure('Unauthorized', 403);
    }
    Http::json(['status' => 'success', 'data' => PlaceService::fieldValue($store, $place, $field)]);
});

$router->add('POST', '/api/v1/places/{placeId}/field/{fieldname}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $place = $store->first('places', static fn(array $p): bool => ($p['id'] ?? '') === $params['placeId']);
    if (!$place) Http::failure('Place not found', 404);
    $account = $auth->currentAccount(); if (!$account) Http::failure('Not logged in', 401);
    $domain = PlaceService::domainFor($store, $place);
    if (!PlaceService::canManage($account, $place, $domain)) Http::failure('Unauthorized', 403);
    $field = $params['fieldname']; $map = PlaceService::FIELD_MAP;
    $readOnly = ['placeId', 'id', 'domainId', 'current_attendance', 'current_last_update_time', 'current_last_update_time_s', 'current_api_key', 'addr_of_first_contact', 'when_place_entry_created', 'when_place_entry_created_s'];
    if (!isset($map[$field]) || in_array($field, $readOnly, true)) Http::failure('Unknown or non-editable field');
    if ($field === 'managers' && !DomainService::isAdmin($account) && !($domain && DomainService::canSponsor($account, $domain))) Http::failure('Domain sponsor or administrator required', 403);
    $body = Http::body(); if (!array_key_exists('set', $body)) Http::failure('no set value given');
    $value = $body['set']; $arrayFields = ['tags', 'managers', 'images', 'current_images'];
    if (in_array($field, $arrayFields, true)) {
        if (!is_array($value)) Http::failure($field . ' must be an array or array manipulator');
        if (isset($value['set']) || isset($value['add']) || isset($value['remove'])) {
            $current = is_array($place[$map[$field]] ?? null) ? $place[$map[$field]] : [];
            if (isset($value['set'])) { if (!is_array($value['set'])) Http::failure('set must be an array'); $current = array_values($value['set']); }
            if (isset($value['add'])) { if (!is_array($value['add'])) Http::failure('add must be an array'); $current = array_merge($current, $value['add']); }
            if (isset($value['remove'])) { if (!is_array($value['remove'])) Http::failure('remove must be an array'); $current = array_values(array_filter($current, static fn($v): bool => !in_array($v, $value['remove'], true))); }
            $value = array_values(array_unique($current));
        }
        foreach ($value as $item) if (!is_string($item)) Http::failure($field . ' values must be strings');
        if ($field === 'managers') {
            foreach ($value as $username) {
                if (!$store->first('accounts', static fn(array $a): bool => strcasecmp((string)($a['username'] ?? ''), $username) === 0)) Http::failure('Unknown manager: ' . $username);
            }
        }
    } elseif (in_array($field, ['name', 'displayName', 'description', 'visibility', 'maturity', 'address', 'path', 'thumbnail', 'current_info'], true)) {
        if (!is_string($value)) Http::failure($field . ' must be a string');
    }
    if ($field === 'name' && !PlaceService::validateName($value, (int)($config['max_name_length'] ?? 32))) Http::failure('Invalid place name');
    if ($field === 'name') {
        $duplicate = $store->first('places', static fn(array $p): bool => ($p['id'] ?? '') !== $place['id'] && strcasecmp((string)($p['name'] ?? ''), $value) === 0);
        if ($duplicate) Http::failure('Place name already exists');
    }
    if ($field === 'visibility' && !in_array($value, ['open', 'friends', 'connections', 'private'], true)) Http::failure('Invalid visibility value');
    if ($field === 'maturity' && !in_array($value, ['unrated', 'everyone', 'teen', 'mature', 'adult'], true)) Http::failure('Invalid maturity value');
    if (in_array($field, ['address', 'path'], true) && !preg_match('~^/[^\s]*$~', $value)) Http::failure('Invalid place address');
    $store->update('places', $place['id'], [$map[$field] => $value]);
    Http::success();
});
