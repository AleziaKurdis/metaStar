<?php
declare(strict_types=1);

require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\AccountEmailService;
use OvertePHP\Auth;
use OvertePHP\JsonStore;

$dir = sys_get_temp_dir() . '/overte-email-test-' . bin2hex(random_bytes(5));
$store = new JsonStore($dir);
$config = [
    'email_enabled' => false,
    'email_from' => '',
    'email_from_name' => 'Test Metaverse',
    'metaverse_name' => 'Test Metaverse',
    'metaverse_server_url' => 'https://example.test',
    'email_verification_timeout_minutes' => 30,
    'password_reset_timeout_minutes' => 30,
    'minimum_password_length' => 8
];

function check(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

try {
    $account = $store->insert('accounts', [
        'id' => JsonStore::uuid(), 'username' => 'EmailUser', 'email' => 'email@example.test',
        'passwordSalt' => 'oldsalt', 'passwordHash' => hash_hmac('sha512', 'oldpassword', 'oldsalt'),
        'accountEmailVerified' => false
    ]);

    // Failed mail handoffs must not leave stale requests or activate a cooldown.
    check(!AccountEmailService::issueVerification($store, $account, $config), 'verification handoff should fail when email is disabled');
    check($store->first('requests', static fn(array $r): bool => ($r['requestType'] ?? '') === 'verifyEmail') === null, 'failed verification handoff must not leave a request');
    check(!AccountEmailService::requestPasswordReset($store, $config, $account['email']), 'password reset handoff should fail when email is disabled');
    check($store->first('requests', static fn(array $r): bool => ($r['requestType'] ?? '') === 'passwordReset') === null, 'failed password reset handoff must not leave a request');

    // Verification request is time-limited and single-use.
    $request = $store->insert('requests', [
        'id' => JsonStore::uuid(), 'requestType' => 'verifyEmail', 'requestingAccountId' => $account['id'],
        'verificationCode' => bin2hex(random_bytes(24)), 'whenCreated' => gmdate('c'),
        'expirationTime' => gmdate('c', time() + 1800)
    ]);
    check($request !== null, 'verification request should be stored');
    check(AccountEmailService::verify($store, $account['id'], $request['verificationCode']), 'valid verification should succeed');
    $verified = $store->first('accounts', static fn(array $a): bool => $a['id'] === $account['id']);
    check(($verified['accountEmailVerified'] ?? false) === true, 'account should be verified');
    check(!AccountEmailService::verify($store, $account['id'], $request['verificationCode']), 'verification code should be single-use');

    // Password reset token is stored hashed, changes password, and revokes old tokens.
    $token = bin2hex(random_bytes(32));
    $store->insert('requests', [
        'id' => JsonStore::uuid(), 'requestType' => 'passwordReset', 'requestingAccountId' => $account['id'],
        'tokenHash' => hash('sha256', $token), 'whenCreated' => gmdate('c'),
        'expirationTime' => gmdate('c', time() + 1800)
    ]);
    $auth = new Auth($store, ['owner_token_expire_hours' => 1, 'domain_token_expire_hours' => 1]);
    $auth->createToken($verified, ['owner']);
    check(AccountEmailService::resetPassword($store, $config, $token, 'newpassword123'), 'valid reset token should work');
    $updated = $store->first('accounts', static fn(array $a): bool => $a['id'] === $account['id']);
    check(Auth::passwordMatches($updated, 'newpassword123'), 'new password should validate');
    check(!Auth::passwordMatches($updated, 'oldpassword'), 'old password should no longer validate');
    check(count($store->find('tokens', static fn(array $t): bool => ($t['accountId'] ?? '') === $account['id'])) === 0, 'existing access tokens should be revoked');
    check(!AccountEmailService::resetPassword($store, $config, $token, 'anotherpassword'), 'reset token should be single-use');

    echo "Email account tests passed.\n";
} finally {
    foreach (glob($dir . '/*') ?: [] as $file) @unlink($file);
    @rmdir($dir);
}
