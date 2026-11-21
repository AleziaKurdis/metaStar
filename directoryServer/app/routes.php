<?php
use OvertePHP\Http;
use OvertePHP\JsonStore;
use OvertePHP\Router;
use OvertePHP\Auth;
use OvertePHP\DomainService;
use OvertePHP\AccountActivity;
use OvertePHP\ProfileService;
use OvertePHP\MaintenanceScheduler;

/** @var Router $router */
require __DIR__ . '/domain-compat-routes.php';
require __DIR__ . '/account-management-routes.php';
require __DIR__ . '/initial-admin-setup-routes.php';
$router->add('GET', '/api/metaverse_info', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    metaverseInfo($config);
});
$router->add('GET', '/api/v1/metaverse_info', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    metaverseInfo($config);
});

$router->add('POST', '/oauth/token', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $body = Http::body();
    $grant = (string)($body['grant_type'] ?? '');

    if ($grant === 'refresh_token') {
        $refresh = (string)($body['refresh_token'] ?? '');
        $oldToken = $auth->tokenForRefresh($refresh);
        if (!$oldToken) {
            Http::json(['error' => 'Invalid refresh token'], 400);
        }
        $account = $store->first('accounts', static fn(array $a): bool => ($a['id'] ?? null) === ($oldToken['accountId'] ?? null));
        if (!$account) {
            Http::json(['error' => 'Account not found'], 400);
        }
        $refreshExpiry = strtotime((string)($oldToken['expirationTime'] ?? '1970-01-01')) ?: 0;
        if ($refreshExpiry <= time()) {
            Http::json(['error' => 'refresh token expired'], 400);
        }
        $requestingAccount = $auth->currentAccount();
        if (!$requestingAccount || ($requestingAccount['id'] ?? '') !== ($account['id'] ?? '')) {
            Http::json(['error' => 'refresh token not owned by accessing account'], 400);
        }
        $scopes = is_array($oldToken['scope'] ?? null) ? $oldToken['scope'] : ['owner'];
        // Iamus issues a replacement token without immediately revoking the old one.
        $newToken = $auth->createToken($account, $scopes);
        Http::json(Auth::oauthBody($account, $newToken));
    }

    if ($grant !== 'password') {
        Http::json(['error' => 'Unsupported grant_type: ' . $grant], 400);
    }

    $scope = (string)($body['scope'] ?? 'owner');
    if (!in_array($scope, ['owner', 'domain', 'place'], true)) {
        Http::json(['error' => 'Invalid scope'], 400);
    }

    $login = trim((string)($body['username'] ?? ''));
    $password = (string)($body['password'] ?? '');
    $account = $store->first('accounts', static fn(array $a): bool =>
        strcasecmp((string)($a['username'] ?? ''), $login) === 0 ||
        strcasecmp((string)($a['email'] ?? ''), $login) === 0
    );

    if (!$account) {
        Http::json(['error' => 'Unknown user'], 400);
    }
    if (($account['accountEmailVerified'] ?? true) === false) {
        Http::json(['error' => 'Account not verified'], 400);
    }
    if (!Auth::passwordMatches($account, $password)) {
        Http::json(['error' => 'Invalid password'], 400);
    }

    $token = $auth->createToken($account, [$scope]);
    Http::json(Auth::oauthBody($account, $token));
});

$router->add('GET', '/api/v1/users', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $viewer = $auth->currentAccount();
    if (!$viewer) {
        Http::failure('Not logged in');
    }

    $accounts = $store->all('accounts');
    $isAdminScope = in_array('admin', $viewer['roles'] ?? [], true) && ($_GET['asAdmin'] ?? '') === 'true';
    if (!$isAdminScope) {
        $accounts = array_values(array_filter($accounts, static fn(array $a): bool => ($a['id'] ?? '') === $viewer['id']));
    }

    $filters = array_filter(array_map('trim', explode(',', strtolower((string)($_GET['filter'] ?? '')))));
    $search = trim((string)($_GET['search'] ?? ''));
    $statuses = array_filter(array_map('trim', explode(',', strtolower((string)($_GET['status'] ?? '')))));
    $friendNames = is_array($viewer['friends'] ?? null) ? $viewer['friends'] : [];
    $connectionNames = is_array($viewer['connections'] ?? null) ? $viewer['connections'] : [];
    $domainStatuses = array_values(array_filter($statuses, static fn(string $v): bool => $v !== 'online'));

    $accounts = array_values(array_filter($accounts, static function (array $a) use ($filters, $search, $statuses, $domainStatuses, $friendNames, $connectionNames, $config): bool {
        if ($filters && !in_array('all', $filters, true)) {
            $matches = false;
            if (in_array('friends', $filters, true)) {
                $matches = $matches || ProfileService::hasName($friendNames, (string)($a['username'] ?? ''));
            }
            if (in_array('connections', $filters, true)) {
                $matches = $matches || ProfileService::hasName($connectionNames, (string)($a['username'] ?? ''));
            }
            if (!$matches) return false;
        }
        if ($search !== '' && stripos((string)($a['username'] ?? ''), $search) === false) return false;
        if ((in_array('online', $statuses, true) || $domainStatuses) && !AccountActivity::isOnline($a, $config)) return false;
        if ($domainStatuses && !in_array((string)($a['locationDomainId'] ?? ''), $domainStatuses, true)) return false;
        return true;
    }));

    $page = ProfileService::page($accounts);
    $users = array_map(static function (array $account) use ($viewer, $store, $config): array {
        $info = ProfileService::userInfo($store, $account, $config);
        if (($viewer['id'] ?? '') === ($account['id'] ?? '')) $info['connection'] = 'self';
        return $info;
    }, $page['items']);
    Http::success(['users' => $users, 'current_page' => $page['current_page'], 'per_page' => $page['per_page'],
        'total_pages' => $page['total_pages'], 'total_entries' => $page['total_entries']]);
});

$router->add('GET', '/api/v1/domains', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) {
        Http::failure('Not logged in', 401);
    }
    $perPage = max(1, min(100, (int)($_GET['per_page'] ?? 50)));
    $page = max(0, (int)($_GET['page'] ?? 0));
    // Iamus AccountScopeFilter limits this endpoint to domains sponsored by
    // the authenticated account. Visibility does not broaden this list.
    $domains = array_values(array_filter($store->all('domains'), static function (array $domain) use ($account): bool {
        return ($domain['sponsorAccountId'] ?? '') === ($account['id'] ?? '');
    }));
    usort($domains, static fn(array $a, array $b): int => strcmp((string)($b['whenCreated'] ?? ''), (string)($a['whenCreated'] ?? '')));
    $total = count($domains);
    $domains = array_slice($domains, $page * $perPage, $perPage);
    Http::success(['domains' => array_map(static fn(array $d): array => DomainService::info($d, $store, $config), $domains),
        'pagination' => ['page' => $page, 'per_page' => $perPage, 'total' => $total]]);
});

$router->add('POST', '/api/v1/domains', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) {
        Http::failure('Not logged in', 401);
    }
    $body = Http::body();
    $input = $body['domain'] ?? null;
    if (!is_array($input) || !isset($input['label'])) {
        Http::failure('no label supplied');
    }
    if (!is_string($input['label'])) {
        Http::failure('domain name must be a simple string');
    }
    $name = trim($input['label']);
    if ($name === '') {
        Http::failure('label was empty');
    }
    if (strlen($name) > (int)($config['max_name_length'] ?? 32)) {
        Http::failure('domain name too long');
    }
    if (!preg_match('/^[A-Za-z][A-Za-z0-9+\-_.]*$/', $name)) {
        Http::failure('domain name characters must be A-Za-z0-9+-_.');
    }
    if ($store->first('domains', static fn(array $d): bool => strcasecmp((string)($d['name'] ?? ''), $name) === 0)) {
        Http::failure('Domain name already exists');
    }
    if (isset($input['network_address']) && !is_string($input['network_address'])) {
        Http::failure('network_address must be a string');
    }
    if (isset($input['network_port']) && (!is_numeric($input['network_port']) || (int)$input['network_port'] < 1 || (int)$input['network_port'] > 65535)) {
        Http::failure('network_port must be between 1 and 65535');
    }
    $domain = DomainService::create($account, $input, $_SERVER['REMOTE_ADDR'] ?? null);
    $placeName = $name;
    while ($store->first('places', static fn(array $p): bool => strcasecmp((string)($p['name'] ?? ''), $placeName) === 0)) {
        $suffix = strtolower(substr(str_replace('-', '', JsonStore::uuid()), 0, 5));
        $placeName = $name . '-' . $suffix;
    }
    $placeToken = $auth->createToken($account, ['place'], -1);
    $place = [
        'id' => JsonStore::uuid(), 'name' => $placeName, 'displayName' => $placeName,
        'description' => 'A place in ' . $name, 'visibility' => 'open', 'maturity' => $domain['maturity'],
        'tags' => [], 'domainId' => $domain['id'], 'managers' => [$account['username']],
        'path' => '/0,0,0/0,0,0,1', 'thumbnail' => null, 'images' => [], 'currentAttendance' => 0,
        'currentImages' => [], 'currentInfo' => '', 'currentLastUpdateTime' => null,
        'currentAPIKeyTokenId' => $placeToken['id'], 'iPAddrOfFirstContact' => $_SERVER['REMOTE_ADDR'] ?? null,
        'whenCreated' => gmdate('c'), 'lastActivity' => null, 'sponsorAccountId' => $account['id']
    ];
    $store->insert('domains', $domain);
    $store->insert('places', $place);
    // A registry change must be synchronized immediately, even after a recent sync.
    MaintenanceScheduler::onDomainRegistryChanged($store, $config);
    $domainInfo = DomainService::info($domain, $store, $config, false);
    $domainInfo['api_key'] = $domain['apiKey'];
    $placeInfo = DomainService::placeInfo($place, $domain);
    $placeInfo['domain'] = DomainService::info($domain, $store, $config, false);
    Http::json(['status' => 'success', 'data' => ['domain' => $domainInfo, 'place' => $placeInfo], 'domain' => $domainInfo]);
});

$router->add('GET', '/api/v1/domains/{domainId}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $domain = $store->first('domains', static fn(array $d): bool => ($d['id'] ?? '') === $params['domainId']);
    if (!$domain) {
        Http::failure('Domain not found', 404);
    }
    $info = DomainService::info($domain, $store, $config);
    Logger::debug($config, 'domain.ice_server_address', [
        'domain_id' => (string)$domain['id'],
        'ice_server_address' => $info['ice_server_address'] ?? null,
        'source' => array_key_exists('iceServerAddr', $domain) && $domain['iceServerAddr'] !== null
            ? 'domain_record'
            : 'default_ice_server_url',
    ]);
    Http::json(['status' => 'success', 'data' => ['domain' => $info], 'domain' => $info]);
});

$router->add('PUT', '/api/v1/domains/{domainId}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $domain = $store->first('domains', static fn(array $d): bool => ($d['id'] ?? '') === $params['domainId']);
    if (!$domain) {
        Http::failure('Domain not found', 404);
    }
    $body = Http::body();
    $input = $body['domain'] ?? null;
    if (!is_array($input)) {
        Http::failure('Badly formatted request');
    }
    $account = $auth->currentAccount();
    $token = currentAuthToken($store);
    $apiKeyAccess = isset($input['api_key']) && isset($domain['apiKey']) &&
        hash_equals((string)$domain['apiKey'], (string)$input['api_key']);
    $isAdmin = $account && DomainService::isAdmin($account);
    $isSponsor = $account && DomainService::canSponsor($account, $domain);
    $isDomainToken = $account && DomainService::canDomain($account, $token, $domain);
    if (!$apiKeyAccess && !$isAdmin && !$isSponsor && !$isDomainToken) {
        Http::failure('Unauthorized', 401);
    }

    $changes = [];
    $fieldMap = [
        'name' => 'name', 'version' => 'version', 'protocol' => 'protocol',
        'network_address' => 'networkAddr', 'network_port' => 'networkPort',
        'automatic_networking' => 'networkingMode', 'restricted' => 'restricted',
        'capacity' => 'capacity', 'description' => 'description', 'maturity' => 'maturity',
        'restriction' => 'restriction', 'managers' => 'managers', 'tags' => 'tags',
        'public_key' => 'publicKey', 'contact_info' => 'contactInfo', 'thumbnail' => 'thumbnail',
        'images' => 'images', 'visibility' => 'visibility', 'sponsor_account_id' => 'sponsorAccountId'
    ];
    $domainOnly = ['version', 'protocol', 'network_address', 'network_port', 'automatic_networking', 'public_key'];
    $domainOrSponsor = ['name', 'visibility', 'sponsor_account_id', 'restricted', 'capacity', 'description', 'maturity', 'restriction', 'tags', 'contact_info', 'thumbnail', 'images'];
    foreach ($fieldMap as $inputName => $fieldName) {
        if (!array_key_exists($inputName, $input)) {
            continue;
        }
        if (in_array($inputName, $domainOnly, true) && !$apiKeyAccess && !$isDomainToken) {
            Http::failure('Domain token required to set ' . $inputName, 403);
        }
        if (in_array($inputName, $domainOrSponsor, true) && !$apiKeyAccess && !$isDomainToken && !$isSponsor && !$isAdmin) {
            Http::failure('Domain, sponsor, or administrator access required to set ' . $inputName, 403);
        }
        if ($inputName === 'managers' && !$isSponsor && !$isAdmin) {
            Http::failure('Domain sponsor or administrator required to set managers', 403);
        }
        if (in_array($inputName, ['num_users', 'num_anon_users'], true) && !$apiKeyAccess && !$isDomainToken && !$isAdmin) {
            Http::failure('Domain token required to set ' . $inputName, 403);
        }
        $value = $input[$inputName];
        $stringFields = ['name', 'version', 'protocol', 'network_address', 'automatic_networking',
            'description', 'maturity', 'restriction', 'public_key', 'contact_info', 'thumbnail', 'sponsor_account_id'];
        if (in_array($inputName, $stringFields, true) && !is_string($value)) {
            Http::failure($inputName . ' must be a string');
        }
        if (in_array($inputName, ['capacity', 'network_port'], true) && !is_numeric($value)) {
            Http::failure($inputName . ' must be numeric');
        }
        if ($inputName === 'restricted' && !is_bool($value)) {
            Http::failure('restricted must be a boolean');
        }
        if (in_array($inputName, ['managers', 'tags', 'images'], true)) {
            if (!is_array($value)) Http::failure($inputName . ' must be an array');
            foreach ($value as $item) {
                if (!is_string($item)) Http::failure($inputName . ' values must be strings');
            }
        }
        if (in_array($inputName, ['name'], true) && (!is_string($value) || !preg_match('/^[A-Za-z][A-Za-z0-9+\-_.]*$/', $value) || strlen($value) > (int)($config['max_name_length'] ?? 32))) {
            Http::failure('Invalid domain name');
        }
        if ($inputName === 'maturity' && !in_array($value, ['unrated', 'everyone', 'teen', 'mature', 'adult'], true)) {
            Http::failure('Invalid maturity value');
        }
        if ($inputName === 'restriction' && !in_array($value, ['open', 'hifi', 'acl'], true)) {
            Http::failure('Invalid restriction value');
        }
        if ($inputName === 'visibility' && !in_array($value, ['open', 'friends', 'connections', 'group', 'private'], true)) {
            Http::failure('Invalid visibility value');
        }
        if ($inputName === 'managers') {
            foreach ($value as $username) {
                if (!$store->first('accounts', static fn(array $a): bool => strcasecmp((string)($a['username'] ?? ''), (string)$username) === 0)) {
                    Http::failure('Unknown manager: ' . (string)$username);
                }
            }
        }
        if ($inputName === 'restricted') {
            $value = (bool)$value;
        }
        if (in_array($inputName, ['capacity', 'network_port'], true)) {
            $value = max(0, (int)$value);
        }
        $changes[$fieldName] = $value;
    }
    if (isset($input['heartbeat']) && is_array($input['heartbeat'])) {
        if (!$apiKeyAccess && !$isDomainToken && !$isAdmin) {
            Http::failure('Domain token required for heartbeat', 403);
        }
        if (isset($input['heartbeat']['num_users'])) {
            $changes['numUsers'] = max(0, (int)$input['heartbeat']['num_users']);
        }
        if (isset($input['heartbeat']['anon_users'])) {
            $changes['anonUsers'] = max(0, (int)$input['heartbeat']['anon_users']);
        }
    }
    if (isset($input['meta']) && is_array($input['meta'])) {
        foreach (['capacity' => 'capacity', 'contact_info' => 'contactInfo', 'description' => 'description',
            'images' => 'images', 'managers' => 'managers', 'restriction' => 'restriction',
            'tags' => 'tags', 'thumbnail' => 'thumbnail', 'world_name' => 'name'] as $key => $target) {
            if (array_key_exists($key, $input['meta']) && !array_key_exists($target, $changes)) {
                if ($key === 'managers') {
                    if (!$isSponsor && !$isAdmin) Http::failure('Domain sponsor required to update managers');
                } elseif (!$apiKeyAccess && !$isDomainToken && !$isSponsor && !$isAdmin) {
                    Http::failure('Domain, sponsor, or administrator access required to update meta');
                }
                if (in_array($key, ['world_name', 'contact_info', 'description', 'restriction', 'thumbnail'], true) && !is_string($input['meta'][$key])) {
                    Http::failure($key . ' must be a string');
                }
                if ($key === 'world_name' && (!preg_match('/^[A-Za-z][A-Za-z0-9+\-_.]*$/', $input['meta'][$key]) || strlen($input['meta'][$key]) > (int)($config['max_name_length'] ?? 32))) Http::failure('Invalid domain name');
                if ($key === 'capacity' && !is_numeric($input['meta'][$key])) Http::failure('capacity must be numeric');
                if ($key === 'maturity' && !in_array($input['meta'][$key], ['unrated', 'everyone', 'teen', 'mature', 'adult'], true)) Http::failure('Invalid maturity value');
                if ($key === 'restriction' && !in_array($input['meta'][$key], ['open', 'hifi', 'acl'], true)) Http::failure('Invalid restriction value');
                if (in_array($key, ['managers', 'tags', 'images'], true)) {
                    if (!is_array($input['meta'][$key])) Http::failure($key . ' must be an array');
                    foreach ($input['meta'][$key] as $item) {
                        if (!is_string($item)) Http::failure($key . ' values must be strings');
                    }
                }
                if ($key === 'managers') {
                    foreach ($input['meta'][$key] as $username) {
                        if (!$store->first('accounts', static fn(array $a): bool => strcasecmp((string)($a['username'] ?? ''), (string)$username) === 0)) Http::failure('Unknown manager: ' . (string)$username);
                    }
                }
                $changes[$target] = $input['meta'][$key];
            }
        }
    }
    $changes['timeOfLastHeartbeat'] = gmdate('c');
    $changes['active'] = true;
    if (isset($_SERVER['REMOTE_ADDR'])) {
        $changes['lastSenderKey'] = $_SERVER['REMOTE_ADDR'];
    }
    $updated = $store->update('domains', $domain['id'], $changes) ?? $domain;
    // Queue due cross-service work locally; the heartbeat response never waits on ICE.
    MaintenanceScheduler::onDomainHeartbeat($store, $config);
    Http::success(['domain' => DomainService::info($updated, $store, $config)]);
});

$router->add('DELETE', '/api/v1/domains/{domainId}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) {
        Http::failure('Not logged in', 401);
    }
    $domain = $store->first('domains', static fn(array $d): bool => ($d['id'] ?? '') === $params['domainId']);
    if (!$domain) {
        Http::failure('Domain not found', 404);
    }
    if (!DomainService::isAdmin($account) && !DomainService::canSponsor($account, $domain)) {
        Http::failure('Only the domain sponsor or an administrator may delete it', 403);
    }
    $deleted = $store->delete('domains', $domain['id']);
    if ($deleted) {
        // Queue reconciliation so ICE drops ownership for the deleted domain.
        MaintenanceScheduler::onDomainRegistryChanged($store, $config);
    }
    // Iamus deliberately leaves associated places in place when a domain is deleted.
    Http::success();
});

$router->add('GET', '/api/v1/domains/{domainId}/field/{fieldname}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $domain = $store->first('domains', static fn(array $d): bool => ($d['id'] ?? '') === $params['domainId']);
    if (!$domain) {
        Http::failure('Domain not found', 404);
    }
    $field = $params['fieldname'];
    $allowed = array_merge(array_keys(DomainService::FIELD_MAP), ['when_domain_entry_created_s', 'time_of_last_heartbeat_s']);
    if (!in_array($field, $allowed, true)) {
        Http::failure('Unknown field name');
    }
    Http::json(['status' => 'success', 'data' => DomainService::fieldValue($domain, $field)]);
});

$router->add('POST', '/api/v1/domains/{domainId}/field/{fieldname}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $domain = $store->first('domains', static fn(array $d): bool => ($d['id'] ?? '') === $params['domainId']);
    if (!$domain) {
        Http::failure('Domain not found', 404);
    }
    $account = $auth->currentAccount();
    $token = currentAuthToken($store);
    $field = $params['fieldname'];
    $map = DomainService::FIELD_MAP;
    $readonly = ['domainId', 'id',
        'addr_of_first_contact', 'when_domain_entry_created', 'when_domain_entry_created_s',
        'time_of_last_heartbeat', 'time_of_last_heartbeat_s', 'last_sender_key'];
    if (!isset($map[$field]) || in_array($field, $readonly, true)) {
        Http::failure('Unknown or non-editable field');
    }
    $isAdmin = $account && DomainService::isAdmin($account);
    $isSponsor = $account && DomainService::canSponsor($account, $domain);
    $isDomain = $account && DomainService::canDomain($account, $token, $domain);
    $domainFields = ['version', 'protocol', 'network_address', 'network_port', 'automatic_networking', 'public_key'];
    $domainOrSponsorFields = ['name', 'world_name', 'visibility', 'visiblity', 'sponsor_account_id', 'restricted',
        'capacity', 'description', 'contact_info', 'maturity', 'restriction', 'tags', 'thumbnail', 'images'];
    if ($field === 'managers') {
        $fieldPermissions = $isSponsor || $isAdmin;
    } elseif (in_array($field, $domainFields, true)) {
        $fieldPermissions = $isDomain;
    } elseif (in_array($field, ['num_users', 'num_anon_users'], true)) {
        $fieldPermissions = $isDomain || $isAdmin;
    } elseif (in_array($field, $domainOrSponsorFields, true)) {
        $fieldPermissions = $isDomain || $isSponsor || $isAdmin;
    } else {
        $fieldPermissions = false;
    }
    if (!$fieldPermissions) {
        Http::failure('Unauthorized', 403);
    }
    $body = Http::body();
    if (!array_key_exists('set', $body)) {
        Http::failure('no set value given');
    }
    $value = $body['set'];
    if (in_array($field, ['tags', 'images', 'managers'], true)) {
        $current = is_array($domain[$map[$field]] ?? null) ? $domain[$map[$field]] : [];
        if (!is_array($value)) {
            Http::failure($field . ' must be an array or array manipulator');
        }
        if (array_key_exists('set', $value) || array_key_exists('add', $value) || array_key_exists('remove', $value)) {
            if (isset($value['set'])) {
                if (!is_array($value['set'])) Http::failure('set must be an array');
                $current = array_values(array_unique(array_map('strval', $value['set'])));
            }
            if (isset($value['add'])) {
                if (!is_array($value['add'])) Http::failure('add must be an array');
                $current = array_values(array_unique(array_merge($current, array_map('strval', $value['add']))));
            }
            if (isset($value['remove'])) {
                if (!is_array($value['remove'])) Http::failure('remove must be an array');
                $remove = array_map('strval', $value['remove']);
                $current = array_values(array_filter($current, static fn($item): bool => !in_array((string)$item, $remove, true)));
            }
            $value = $current;
        }
        foreach ($value as $item) {
            if (!is_string($item)) Http::failure($field . ' values must be strings');
        }
        if ($field === 'managers') {
            foreach ($value as $username) {
                if (!$store->first('accounts', static fn(array $a): bool => strcasecmp((string)($a['username'] ?? ''), $username) === 0)) {
                    Http::failure('Unknown manager: ' . $username);
                }
            }
        }
    }
    if (in_array($field, ['name', 'world_name'], true) && (!is_string($value) || !preg_match('/^[A-Za-z][A-Za-z0-9+\-_.]*$/', $value) || strlen($value) > (int)($config['max_name_length'] ?? 32))) Http::failure('Invalid domain name');
    if ($field === 'maturity' && !in_array($value, ['unrated', 'everyone', 'teen', 'mature', 'adult'], true)) Http::failure('Invalid maturity value');
    if ($field === 'restriction' && !in_array($value, ['open', 'hifi', 'acl'], true)) Http::failure('Invalid restriction value');
    if ($field === 'visibility' && !in_array($value, ['open', 'friends', 'connections', 'group', 'private'], true)) Http::failure('Invalid visibility value');
    if ($field === 'restricted') {
        if (!is_bool($value)) Http::failure('restricted must be a boolean');
        $value = (bool)$value;
    }
    if ($field === 'capacity' || $field === 'network_port') {
        if (!is_numeric($value)) Http::failure($field . ' must be numeric');
        $value = max(0, (int)$value);
    }
    $store->update('domains', $domain['id'], [$map[$field] => $value]);
    Http::success();
});

function currentAuthToken(JsonStore $store): ?array
{
    $header = trim((string)($_SERVER['HTTP_AUTHORIZATION'] ?? ''));
    if (preg_match('/^Bearer\\s+(.+)$/i', $header, $matches)) {
        $value = trim($matches[1]);
    } elseif ($header !== '') {
        $value = $header;
    } else {
        $value = (string)($_GET['access_token'] ?? '');
    }
    if ($value === '') return null;
    return $store->first('tokens', static fn(array $t): bool =>
        hash_equals((string)($t['token'] ?? ''), $value) &&
        (strtotime((string)($t['expirationTime'] ?? '1970-01-01')) ?: 0) > time()
    );
}

function accountInfo(array $account, ?JsonStore $store = null, array $config = []): array
{
    $created = isset($account['whenCreated']) ? strtotime((string)$account['whenCreated']) : false;
    $heartbeat = isset($account['timeOfLastHeartbeat']) ? strtotime((string)$account['timeOfLastHeartbeat']) : false;
    $publicKey = (string)($account['sessionPublicKey'] ?? '');
    $publicKey = preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\\s+/', '', $publicKey);
    $location = $store !== null
        ? AccountActivity::locationInfo($store, $account, $config)
        : ['node_id' => $account['locationNodeId'] ?? null, 'online' => AccountActivity::isOnline($account, $config)];
    return [
        'accountId' => $account['id'],
        'id' => $account['id'],
        'username' => $account['username'] ?? '',
        'email' => $account['email'] ?? '',
        'administrator' => in_array('admin', $account['roles'] ?? [], true),
        'enabled' => ($account['accountEmailVerified'] ?? true) !== false,
        'roles' => $account['roles'] ?? ['user'],
        'availability' => $account['availability'] ?? ['all'],
        'public_key' => $publicKey,
        'images' => [
            'hero' => $account['imagesHero'] ?? null,
            'tiny' => $account['imagesTiny'] ?? null,
            'thumbnail' => $account['imagesThumbnail'] ?? null
        ],
        'profile_detail' => $account['profileDetail'] ?? null,
        'location' => $location,
        'friends' => $account['friends'] ?? [],
        'connections' => $account['connections'] ?? [],
        'when_account_created' => $created ? gmdate('Y-m-d\\TH:i:s.000\\Z', $created) : null,
        'when_account_created_s' => $created ? (string)($created * 1000) : null,
        'time_of_last_heartbeat' => $heartbeat ? gmdate('Y-m-d\\TH:i:s.000\\Z', $heartbeat) : null,
        'time_of_last_heartbeat_s' => $heartbeat ? (string)($heartbeat * 1000) : null
    ];
}

function tokenInfo(array $token): array
{
    $created = strtotime((string)($token['whenCreated'] ?? '')) ?: 0;
    $expires = strtotime((string)($token['expirationTime'] ?? '')) ?: 0;
    return [
        'tokenId' => $token['id'],
        'id' => $token['id'],
        'token' => $token['token'],
        'accountId' => $token['accountId'],
        'refresh_token' => $token['refreshToken'],
        'scope' => $token['scope'] ?? [],
        'creation_time' => $created ? gmdate('c', $created) : null,
        'creation_time_s' => (string)($created * 1000),
        'expiration_time' => $expires ? gmdate('c', $expires) : null,
        'expiration_time_s' => (string)($expires * 1000)
    ];
}

function metaverseInfo(array $config): never
{
    $baseUrl = trim((string)$config['metaverse_server_url']);
    if ($baseUrl === '') {
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $baseUrl = $scheme . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost');
    }
    $configuredIceUrl = trim((string)$config['default_ice_server_url']);
    $iceUrl = $configuredIceUrl;
    $iceUrlSource = 'default_ice_server_url';
    if ($iceUrl === '') {
        $iceUrl = $baseUrl;
        $iceUrlSource = 'metaverse_server_url_fallback';
    }

    Logger::debug($config, 'metaverse_info.ice_server_url', [
        'metaverse_url' => rtrim($baseUrl, '/'),
        'ice_server_url' => $iceUrl,
        'source' => $iceUrlSource,
    ]);

    $data = [
        'metaverse_name' => $config['metaverse_name'],
        'metaverse_nick_name' => $config['metaverse_nick_name'],
        'metaverse_url' => rtrim($baseUrl, '/'),
        'ice_server_url' => $iceUrl,
        'metaverse_server_version' => $config['server_version']
    ];

    $additional = $config['metaverse_info_addition_file'];
    if ($additional !== '' && is_file($additional)) {
        $extra = json_decode((string)file_get_contents($additional), true);
        if (is_array($extra)) {
            $data = array_replace_recursive($data, $extra);
        }
    }
    Http::success($data);
}

require __DIR__ . '/activity-routes.php';
require __DIR__ . '/email-routes.php';
require __DIR__ . '/profile-routes.php';
require __DIR__ . '/social-routes.php';
require __DIR__ . '/place-routes.php';
require __DIR__ . '/temporary-domain-routes.php';
require __DIR__ . '/admin-dashboard-routes.php';
