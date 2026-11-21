<?php
declare(strict_types=1);

/*
 * Copy this file to config/local.php and edit local.php.
 * Keep the storage directory outside public/ whenever possible.
 */
$defaults = [
    'storage_path' => dirname(__DIR__) . '/data',
    'metaverse_name' => 'My Overte Metaverse',
    'metaverse_nick_name' => 'My Metaverse',
    'metaverse_server_url' => '',
    'default_ice_server_url' => '',
    // ICE control API is separate from default_ice_server_url (the client-advertised ICE address).
    'ice_control_url' => '',
    'ice_control_ca_file' => '',
    'ice_directory_id' => '',
    // Heartbeats queue ICE synchronization; the CLI scheduler worker executes it.
    'ice_sync_interval_seconds' => 300,
    'scheduler_retry_seconds' => 60,
    'server_version' => ['major' => 1, 'minor' => 0, 'patch' => 0],
    'metaverse_info_addition_file' => '',
    'session_timeout_minutes' => 5,
    'heartbeat_seconds_until_offline' => 300,
    'handshake_request_expiration_minutes' => 1,
    'relationship_request_expiration_days' => 14,
    // Email is disabled until the host mail transport and sender address are configured.
    'email_enabled' => false,
    'email_from' => '',
    'email_from_name' => 'Overte',
    'email_verification_enabled' => false,
    'email_verification_timeout_minutes' => 1440,
    'email_verification_success_redirect' => '',
    'email_verification_failure_redirect' => '',
    'password_reset_timeout_minutes' => 60,
    'email_resend_cooldown_seconds' => 60,
    'password_reset_url' => '',
    // Iamus-compatible activity maintenance. Temporary domains remain disabled by default.
    'allow_temp_domain_creation' => false,
    'domain_seconds_until_offline' => 600,
    'domain_seconds_check_if_online' => 120,
    'place_current_timeout_minutes' => 5,
    'place_check_last_activity_seconds' => 175,
    'domain_token_expire_hours' => 8760,
    'owner_token_expire_hours' => 168,
    'max_name_length' => 32,
    'minimum_password_length' => 1,
    'base_admin_account' => '',
    // Set to a random secret of at least 32 characters for one-time first-admin setup.
    'initial_admin_setup_key' => '',
    'cors_origins' => ['*'],
    // Application-owned diagnostics. Disabled by default; enable in local.php while testing.
    'debug' => [
        'enabled' => false,
        'auth_logging' => false,
        'log_file' => ''
    ]
];

$localFile = __DIR__ . '/local.php';
$local = is_file($localFile) ? require $localFile : [];
return array_replace($defaults, is_array($local) ? $local : []);
