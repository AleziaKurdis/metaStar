<?php
declare(strict_types=1);

require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\DomainService;

// An explicitly configured public ICE address takes precedence.
$configured = [
    'default_ice_server_url' => 'https://ice.example.org:443',
    'metaverse_server_url' => 'https://directory.example.org'
];
assert(DomainService::effectiveIceServerUrl($configured) === 'https://ice.example.org:443');
assert(DomainService::isValidHttpUrl(DomainService::effectiveIceServerUrl($configured)));

// Preserve the existing metaverse-info fallback when no dedicated ICE address is configured.
$fallback = [
    'default_ice_server_url' => '',
    'metaverse_server_url' => 'https://directory.example.org/'
];
assert(DomainService::effectiveIceServerUrl($fallback) === 'https://directory.example.org/');
assert(DomainService::isValidHttpUrl(DomainService::effectiveIceServerUrl($fallback)));

// Preserve the legacy request-host fallback when neither URL is configured.
$previousHttps = $_SERVER['HTTPS'] ?? null;
$previousHost = $_SERVER['HTTP_HOST'] ?? null;
$_SERVER['HTTPS'] = 'on';
$_SERVER['HTTP_HOST'] = 'directory.example.test';
$requestFallback = [
    'default_ice_server_url' => '',
    'metaverse_server_url' => ''
];
assert(DomainService::effectiveIceServerUrl($requestFallback) === 'https://directory.example.test');
assert(DomainService::isValidHttpUrl(DomainService::effectiveIceServerUrl($requestFallback)));
if ($previousHttps === null) unset($_SERVER['HTTPS']); else $_SERVER['HTTPS'] = $previousHttps;
if ($previousHost === null) unset($_SERVER['HTTP_HOST']); else $_SERVER['HTTP_HOST'] = $previousHost;

// Discovery must not publish malformed or non-HTTP(S) configuration values.
assert(!DomainService::isValidHttpUrl(''));
assert(!DomainService::isValidHttpUrl('ice.example.org'));
assert(!DomainService::isValidHttpUrl('ftp://ice.example.org'));
assert(!DomainService::isValidHttpUrl('https://user:secret@ice.example.org'));

echo "ICE server discovery tests passed.\n";
