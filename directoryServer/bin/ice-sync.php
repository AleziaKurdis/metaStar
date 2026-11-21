<?php
declare(strict_types=1);

use OvertePHP\IceRegistrationService;
use OvertePHP\JsonStore;

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/app/bootstrap.php';

$command = $argv[1] ?? '';
if (!in_array($command, ['enroll', 'recover', 'sync'], true) || count($argv) !== 2) {
    fwrite(STDERR, "Usage: php bin/ice-sync.php enroll|recover|sync\n");
    exit(2);
}

try {
    $config = require dirname(__DIR__) . '/config/config.php';
    $store = new JsonStore((string)$config['storage_path']);
    $service = new IceRegistrationService($store, $config);

    if ($command === 'enroll' || $command === 'recover') {
        $secret = getenv('OVERTE_ICE_ENROLLMENT_SECRET');
        if (!is_string($secret) || trim($secret) === '') {
            throw new RuntimeException('Set OVERTE_ICE_ENROLLMENT_SECRET in the shell environment for enrollment or token recovery.');
        }
        $result = $command === 'enroll' ? $service->enroll($secret) : $service->recover($secret);
        echo ($command === 'enroll' ? "ICE enrollment succeeded; synchronized " : "ICE token recovery succeeded; synchronized ") . $result['domain_count'] . " domain(s).\n";
        echo "The issued registration token was saved in the private Directory Server storage directory.\n";
    } else {
        $result = $service->sync();
        echo "ICE registration synchronized " . $result['domain_count'] . " domain(s): " . $result['message'] . "\n";
    }
} catch (Throwable $error) {
    fwrite(STDERR, "ICE registration failed: " . $error->getMessage() . "\n");
    exit(1);
}
