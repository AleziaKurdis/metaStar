<?php
use OvertePHP\AccountEmailService;
use OvertePHP\Http;
use OvertePHP\JsonStore;
use OvertePHP\EmailService;
use OvertePHP\Auth;

/** @var \OvertePHP\Router $router */

$router->add('GET', '/api/v1/account/verify/email', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $accountId = trim((string)($_GET['a'] ?? ''));
    $code = trim((string)($_GET['v'] ?? ''));
    $verified = $accountId !== '' && $code !== '' && AccountEmailService::verify($store, $accountId, $code);
    $redirect = trim((string)($config[$verified ? 'email_verification_success_redirect' : 'email_verification_failure_redirect'] ?? ''));
    if ($redirect !== '') {
        $redirect = str_replace(['METAVERSE_SERVER_URL', 'ACCOUNT_ID'], [EmailService::baseUrl($config), rawurlencode($accountId)], $redirect);
    } else {
        $redirect = EmailService::baseUrl($config) . '/verify-email/?status=' . ($verified ? 'success' : 'failure');
    }
    header('Location: ' . $redirect, true, 302);
    exit;
});

$router->add('POST', '/api/v1/account/verify/email/resend', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $body = Http::body();
    $email = strtolower(trim((string)($body['email'] ?? '')));
    $account = $email !== '' ? $store->first('accounts', static fn(array $a): bool => strcasecmp((string)($a['email'] ?? ''), $email) === 0) : null;
    if ($account && ($account['accountEmailVerified'] ?? true) === false) {
        AccountEmailService::issueVerification($store, $account, $config);
    }
    Http::success(['message' => 'If the address belongs to an account that still needs verification and the request is eligible, instructions will be sent.']);
});

$router->add('POST', '/api/v1/account/password/reset/request', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $body = Http::body();
    AccountEmailService::requestPasswordReset($store, $config, (string)($body['email'] ?? ''));
    Http::success(['message' => 'If an account matches that email address, password reset instructions have been sent.']);
});

$router->add('POST', '/api/v1/account/password/reset', static function (array $params, JsonStore $store, Auth $auth, array $config): never {
    $body = Http::body();
    $token = trim((string)($body['token'] ?? ''));
    $password = (string)($body['password'] ?? '');
    if (!AccountEmailService::resetPassword($store, $config, $token, $password)) {
        Http::failure('Password reset token is invalid, expired, or the password is too short', 400);
    }
    Http::success(['message' => 'Password has been changed. Please sign in again.']);
});
