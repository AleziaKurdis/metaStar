<?php
use OvertePHP\AccountManagement;
use OvertePHP\Http;
use OvertePHP\JsonStore;
use OvertePHP\Auth;
use OvertePHP\AccountActivity;
use OvertePHP\ProfileService;
use OvertePHP\AccountEmailService;

/** @var \OvertePHP\Router $router */

$router->add('POST', '/api/v1/users', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    // When a first administrator is configured, force the initial account
    // through the protected one-time setup endpoint. This prevents someone
    // from claiming the configured administrator username via public signup.
    if (trim((string)($config['base_admin_account'] ?? '')) !== '' && count($store->all('accounts')) === 0) {
        Http::failure('Initial administrator setup must be completed first', 403);
    }
    $body = Http::body();
    $user = $body['user'] ?? null;
    if (!is_array($user)) Http::failure('Badly formatted request');
    $username = trim((string)($user['username'] ?? ''));
    $password = (string)($user['password'] ?? '');
    $email = strtolower(trim((string)($user['email'] ?? '')));
    $maxName = (int)($config['max_name_length'] ?? 32);
    if ($username === '' || strlen($username) > $maxName || !preg_match('/^[A-Za-z][A-Za-z0-9+_.-]*$/', $username)) {
        Http::failure('username can contain only A-Za-z0-9+-_. and must start with a letter');
    }
    if ($email === '' || substr_count($email, '@') !== 1) Http::failure('email address needs one AT sign');
    if (strlen($password) < (int)($config['minimum_password_length'] ?? 1)) Http::failure('password is too short');
    if ($store->first('accounts', static fn(array $a): bool => strcasecmp((string)($a['username'] ?? ''), $username) === 0)) {
        Http::failure('Account already exists');
    }
    if ($store->first('accounts', static fn(array $a): bool => strcasecmp((string)($a['email'] ?? ''), $email) === 0)) {
        Http::failure('Email already exists');
    }
    $salt = bin2hex(random_bytes(8));
    $roles = ['user'];
    if (($config['base_admin_account'] ?? '') !== '' && strcasecmp($username, (string)$config['base_admin_account']) === 0) $roles[] = 'admin';
    $verificationEnabled = !empty($config['email_verification_enabled']);
    if ($verificationEnabled && empty($config['email_enabled'])) {
        Http::failure('Email verification is enabled but email delivery is not configured', 503);
    }
    if ($verificationEnabled && !filter_var((string)($config['email_from'] ?? ''), FILTER_VALIDATE_EMAIL)) {
        Http::failure('Email verification requires a valid email_from address in the server configuration', 503);
    }
    $account = $store->insert('accounts', [
        'id' => JsonStore::uuid(), 'username' => $username, 'email' => $email,
        'passwordSalt' => $salt, 'passwordHash' => hash_hmac('sha512', $password, $salt),
        'roles' => $roles, 'friends' => [], 'connections' => [], 'availability' => ['all'],
        'accountEmailVerified' => $verificationEnabled ? false : null,
        'whenCreated' => gmdate('c')
    ]);
    $verificationEmailSent = null;
    if ($verificationEnabled) {
        $verificationEmailSent = AccountEmailService::issueVerification($store, $account, $config);
    }
    Http::success([
        'accountId' => $account['id'], 'username' => $account['username'],
        'accountIsActive' => !$verificationEnabled, 'accountAwaitingVerification' => $verificationEnabled,
        'verificationEmailSent' => $verificationEmailSent
    ]);
});

$router->add('GET', '/api/v1/account/{accountId}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $viewer = $auth->currentAccount();
    if (!$viewer) Http::failure('Not logged in');
    $target = AccountManagement::findAccount($store, (string)$params['accountId']);
    if (!$target) Http::failure('Target account not found');
    if (($viewer['id'] ?? '') !== ($target['id'] ?? '') && !AccountManagement::isAdmin($viewer)) Http::failure('Unauthorized');
    Http::success(['account' => accountInfo($target, $store, $config)]);
});

$router->add('POST', '/api/v1/account/{accountId}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $viewer = $auth->currentAccount();
    if (!$viewer) Http::failure('Not logged in');
    $target = AccountManagement::findAccount($store, (string)$params['accountId']);
    if (!$target) Http::failure('Target account not found');
    if (($viewer['id'] ?? '') !== ($target['id'] ?? '') && !AccountManagement::isAdmin($viewer)) Http::failure('Unauthorized');
    $body = Http::body();
    $values = $body['accounts'] ?? null;
    if (!is_array($values)) Http::failure('Badly formatted account update');
    if (array_key_exists('email', $values)) AccountManagement::setField($store, $viewer, $target, 'email', $values['email'], $config);
    if (array_key_exists('public_key', $values)) {
        $target = AccountManagement::findAccount($store, (string)$target['id']) ?? $target;
        AccountManagement::setField($store, $viewer, $target, 'public_key', $values['public_key'], $config);
    }
    if (isset($values['images']) && is_array($values['images'])) {
        foreach (['hero' => 'images_hero', 'tiny' => 'images_tiny', 'thumbnail' => 'images_thumbnail'] as $key => $field) {
            if (array_key_exists($key, $values['images'])) {
                $target = AccountManagement::findAccount($store, (string)$target['id']) ?? $target;
                AccountManagement::setField($store, $viewer, $target, $field, $values['images'][$key], $config);
            }
        }
    }
    Http::success();
});

$router->add('DELETE', '/api/v1/account/{accountId}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $viewer = $auth->currentAccount();
    if (!$viewer || !AccountManagement::isAdmin($viewer)) Http::failure('Not an administrator');
    $target = AccountManagement::findAccount($store, (string)$params['accountId']);
    if (!$target) Http::failure('Target account does not exist');
    if (($viewer['id'] ?? '') === ($target['id'] ?? '')) {
        Http::failure('You cannot delete the administrator account currently in use', 409);
    }
    if (AccountManagement::isAdmin($target)) {
        $administratorCount = count(array_filter($store->all('accounts'), static fn(array $account): bool => AccountManagement::isAdmin($account)));
        if ($administratorCount <= 1) Http::failure('The last administrator account cannot be deleted', 409);
    }
    AccountManagement::removeAccountContext($store, $target);
    Http::success();
});

$router->add('GET', '/api/v1/account/{accountId}/field/{fieldname}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $viewer = $auth->currentAccount();
    if (!$viewer) Http::failure('Not logged in');
    $target = AccountManagement::findAccount($store, (string)$params['accountId']);
    if (!$target) Http::failure('Target account not found');
    Http::success(AccountManagement::getField($viewer, $target, (string)$params['fieldname']));
});

$router->add('POST', '/api/v1/account/{accountId}/field/{fieldname}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $viewer = $auth->currentAccount();
    if (!$viewer) Http::failure('Not logged in');
    $target = AccountManagement::findAccount($store, (string)$params['accountId']);
    if (!$target) Http::failure('Target account not found');
    $body = Http::body();
    if (!array_key_exists('set', $body)) Http::failure('no set value given');
    if ((string)$params['fieldname'] === 'roles' && is_array($body['set']) && !in_array('admin', $body['set'], true) && AccountManagement::isAdmin($target)) {
        if (($viewer['id'] ?? '') === ($target['id'] ?? '')) {
            Http::failure('You cannot remove administrator privileges from the account currently in use', 409);
        }
        $administratorCount = count(array_filter($store->all('accounts'), static fn(array $account): bool => AccountManagement::isAdmin($account)));
        if ($administratorCount <= 1) Http::failure('The last administrator must retain administrator privileges', 409);
    }
    AccountManagement::setField($store, $viewer, $target, (string)$params['fieldname'], $body['set'], $config);
    Http::success();
});

$router->add('POST', '/api/v1/token/new', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $account = $auth->currentAccount();
    if (!$account) Http::failure('Not logged in');
    $scope = (string)($_GET['scope'] ?? 'owner');
    if (!in_array($scope, ['owner', 'domain', 'place'], true)) Http::failure('incorrect scope');
    $token = $auth->createToken($account, [$scope]);
    $expires = max(0, (strtotime((string)$token['expirationTime']) ?: 0) - (strtotime((string)$token['whenCreated']) ?: 0));
    Http::success([
        'token' => $token['token'], 'token_id' => $token['id'], 'refresh_token' => $token['refreshToken'],
        'token_expiration_seconds' => $expires, 'account_name' => $account['username'],
        'account_roles' => $account['roles'] ?? ['user'], 'account_id' => $account['id']
    ]);
});

$router->add('GET', '/api/v1/account/{accountId}/tokens', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $viewer = $auth->currentAccount();
    if (!$viewer) Http::failure('Not logged in');
    $target = AccountManagement::findAccount($store, (string)$params['accountId']);
    if (!$target) Http::failure('Target account not found');
    if (($viewer['id'] ?? '') !== ($target['id'] ?? '') && !AccountManagement::isAdmin($viewer)) Http::failure('Unauthorized');
    $tokens = array_values(array_filter($store->all('tokens'), static fn(array $token): bool => ($token['accountId'] ?? '') === $target['id']));
    usort($tokens, static fn(array $a, array $b): int => strcmp((string)($b['whenCreated'] ?? ''), (string)($a['whenCreated'] ?? '')));
    $page = max(1, (int)($_GET['page'] ?? 1));
    $perPage = max(1, min(100, (int)($_GET['per_page'] ?? 50)));
    $total = count($tokens);
    $tokens = array_slice($tokens, ($page - 1) * $perPage, $perPage);
    Http::success(['tokens' => array_map('tokenInfo', $tokens), 'current_page' => $page,
        'per_page' => $perPage, 'total_pages' => max(1, (int)ceil($total / $perPage)), 'total_entries' => $total]);
});

$router->add('DELETE', '/api/v1/account/{accountId}/tokens', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $viewer = $auth->currentAccount();
    if (!$viewer) Http::failure('Not logged in');
    $target = AccountManagement::findAccount($store, (string)$params['accountId']);
    if (!$target) Http::failure('Target account not found');
    if (($viewer['id'] ?? '') !== ($target['id'] ?? '') && !AccountManagement::isAdmin($viewer)) Http::failure('Unauthorized');

    $revoked = 0;
    foreach ($store->all('tokens') as $token) {
        if (($token['accountId'] ?? '') === ($target['id'] ?? '') && $store->delete('tokens', (string)($token['id'] ?? ''))) {
            $revoked++;
        }
    }
    Http::success(['revoked_count' => $revoked]);
});

$router->add('DELETE', '/api/v1/account/{accountId}/tokens/{tokenId}', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $viewer = $auth->currentAccount();
    if (!$viewer) Http::failure('Not logged in');
    $target = AccountManagement::findAccount($store, (string)$params['accountId']);
    if (!$target) Http::failure('Target account not found');
    $token = $store->first('tokens', static fn(array $item): bool => ($item['id'] ?? '') === $params['tokenId']);
    if (!$token) Http::failure('Token not found');
    if (($token['accountId'] ?? '') !== ($target['id'] ?? '')) Http::failure('Token account does not match requested account');
    if (($viewer['id'] ?? '') !== ($target['id'] ?? '') && !AccountManagement::isAdmin($viewer)) Http::failure('Unauthorized');
    $store->delete('tokens', (string)$token['id']);
    Http::success();
});

$router->add('GET', '/api/v1/tokens', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $viewer = $auth->currentAccount();
    if (!$viewer) Http::failure('Not logged in');
    $allAccounts = AccountManagement::isAdmin($viewer) && (($_GET['asAdmin'] ?? '') === 'true');
    $tokens = array_values(array_filter($store->all('tokens'), static fn(array $token): bool =>
        ($token['accountId'] ?? '') === ($viewer['id'] ?? '') || ($allAccounts && AccountManagement::isAdmin($viewer))
    ));
    usort($tokens, static fn(array $a, array $b): int => strcmp((string)($b['whenCreated'] ?? ''), (string)($a['whenCreated'] ?? '')));
    $page = max(1, (int)($_GET['page'] ?? 1));
    $perPage = max(1, min(100, (int)($_GET['per_page'] ?? 50)));
    $total = count($tokens);
    $tokens = array_slice($tokens, ($page - 1) * $perPage, $perPage);
    Http::success(['tokens' => array_map('tokenInfo', $tokens), 'current_page' => $page,
        'per_page' => $perPage, 'total_pages' => max(1, (int)ceil($total / $perPage)), 'total_entries' => $total]);
});

$router->add('GET', '/api/v1/accounts', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $viewer = $auth->currentAccount();
    if (!$viewer) Http::failure('Not logged in');
    $isAdmin = AccountManagement::isAdmin($viewer);
    $asAdmin = $isAdmin && (($_GET['asAdmin'] ?? '') === 'true');
    $filters = array_filter(array_map('trim', explode(',', strtolower((string)($_GET['filter'] ?? 'connections')))));
    $names = [];
    if (!$asAdmin) {
        if (in_array('all', $filters, true)) $filters = ['connections'];
        if (in_array('friends', $filters, true)) $names = array_merge($names, $viewer['friends'] ?? []);
        if (in_array('connections', $filters, true)) $names = array_merge($names, $viewer['connections'] ?? []);
        $names = array_values(array_unique(array_filter($names, 'is_string')));
    }
    $accounts = $store->all('accounts');
    if (!$asAdmin) {
        $accounts = array_values(array_filter($accounts, static fn(array $a): bool =>
            ($a['id'] ?? '') === ($viewer['id'] ?? '') || ProfileService::hasName($names, (string)($a['username'] ?? ''))
        ));
    }
    $search = trim((string)($_GET['search'] ?? ''));
    if ($search !== '') $accounts = array_values(array_filter($accounts, static fn(array $a): bool => stripos((string)($a['username'] ?? ''), $search) !== false));
    $statuses = array_filter(array_map('trim', explode(',', strtolower((string)($_GET['status'] ?? '')))));
    if ($statuses) $accounts = array_values(array_filter($accounts, static function (array $a) use ($statuses, $config): bool {
        if (in_array('online', $statuses, true) && !AccountActivity::isOnline($a, $config)) return false;
        $domainIds = array_values(array_filter($statuses, static fn(string $s): bool => $s !== 'online'));
        if ($domainIds && !in_array((string)($a['locationDomainId'] ?? ''), $domainIds, true)) return false;
        return true;
    }));
    usort($accounts, static fn(array $a, array $b): int => strcasecmp((string)($a['username'] ?? ''), (string)($b['username'] ?? '')));
    $page = max(1, (int)($_GET['page'] ?? 1));
    $perPage = max(1, min(100, (int)($_GET['per_page'] ?? 50)));
    $total = count($accounts);
    $accounts = array_slice($accounts, ($page - 1) * $perPage, $perPage);
    Http::success(['accounts' => array_map(static fn(array $a): array => accountInfo($a, $store, $config), $accounts),
        'current_page' => $page, 'per_page' => $perPage, 'total_pages' => max(1, (int)ceil($total / $perPage)),
        'total_entries' => $total]);
});
