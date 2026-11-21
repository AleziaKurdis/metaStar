<?php
declare(strict_types=1);

require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\JsonStore;
use OvertePHP\MaintenanceScheduler;

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$config = require dirname(__DIR__) . '/config/config.php';
$store = new JsonStore($config['storage_path']);

try {
    $result = MaintenanceScheduler::runPending($store, $config);
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    if (($result['success'] ?? true) === false) {
        exit(1);
    }
} catch (Throwable $error) {
    fwrite(STDERR, 'Scheduler failed: ' . $error->getMessage() . PHP_EOL);
    exit(1);
}
