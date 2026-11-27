<?php
declare(strict_types=1);

use OvertePHP\DomainService;

require_once dirname(__DIR__) . '/app/bootstrap.php';

/**
 * Run isolated checks for public ICE URL discovery.
 *
 * The explicit check helper is used instead of PHP assert(), which may be
 * disabled by the hosting configuration.
 */
function runIceServerDiscoveryChecks(): array
{
    $results = [];
    $check = static function (string $name, bool $passed) use (&$results): void {
        $results[] = ['name' => $name, 'passed' => $passed];
    };

    $configured = [
        'default_ice_server_url' => 'https://ice.example.org:443',
        'metaverse_server_url' => 'https://directory.example.org'
    ];
    $effective = DomainService::effectiveIceServerUrl($configured);
    $check('Configured ICE URL takes precedence', $effective === 'https://ice.example.org:443');
    $check('Configured ICE URL is valid HTTP(S)', DomainService::isValidHttpUrl($effective));

    $fallback = [
        'default_ice_server_url' => '',
        'metaverse_server_url' => 'https://directory.example.org/'
    ];
    $effective = DomainService::effectiveIceServerUrl($fallback);
    $check('Metaverse URL is used when no ICE URL is configured', $effective === 'https://directory.example.org/');
    $check('Metaverse URL fallback is valid HTTP(S)', DomainService::isValidHttpUrl($effective));

    $previousHttps = $_SERVER['HTTPS'] ?? null;
    $previousHost = $_SERVER['HTTP_HOST'] ?? null;
    try {
        $_SERVER['HTTPS'] = 'on';
        $_SERVER['HTTP_HOST'] = 'directory.example.test';
        $requestFallback = [
            'default_ice_server_url' => '',
            'metaverse_server_url' => ''
        ];
        $effective = DomainService::effectiveIceServerUrl($requestFallback);
        $check('Request host is used as the legacy fallback', $effective === 'https://directory.example.test');
        $check('Request-host fallback is valid HTTP(S)', DomainService::isValidHttpUrl($effective));
    } finally {
        if ($previousHttps === null) {
            unset($_SERVER['HTTPS']);
        } else {
            $_SERVER['HTTPS'] = $previousHttps;
        }
        if ($previousHost === null) {
            unset($_SERVER['HTTP_HOST']);
        } else {
            $_SERVER['HTTP_HOST'] = $previousHost;
        }
    }

    $check('Empty URL is rejected', !DomainService::isValidHttpUrl(''));
    $check('URL without a scheme is rejected', !DomainService::isValidHttpUrl('ice.example.org'));
    $check('Non-HTTP(S) URL is rejected', !DomainService::isValidHttpUrl('ftp://ice.example.org'));
    $check('URL containing embedded credentials is rejected', !DomainService::isValidHttpUrl('https://user:secret@ice.example.org'));

    return $results;
}

// Preserve direct command-line execution while allowing the protected browser
// runner to include this file and display the same checks.
if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    $results = runIceServerDiscoveryChecks();
    foreach ($results as $result) {
        echo ($result['passed'] ? 'PASS' : 'FAIL') . ' — ' . $result['name'] . PHP_EOL;
    }
    $failed = count(array_filter($results, static fn(array $result): bool => !$result['passed']));
    echo count($results) - $failed . ' passed, ' . $failed . ' failed.' . PHP_EOL;
    exit($failed === 0 ? 0 : 1);
}
