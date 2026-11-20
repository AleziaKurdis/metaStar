<?php
declare(strict_types=1);

require dirname(__DIR__) . '/app/bootstrap.php';

// Keep API failures machine-readable. Without this, a PHP exception or fatal
// error can produce an empty response, leaving browser clients with a JSON.parse error.
set_exception_handler(static function (Throwable $error): void {
    error_log('[Overte PHP] Unhandled exception: ' . $error);
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
    }
    echo json_encode([
        'status' => 'failure',
        'error' => 'Internal server error. Check the server PHP error log for details.'
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
});

register_shutdown_function(static function (): void {
    $error = error_get_last();
    if (!$error || !in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        return;
    }
    error_log('[Overte PHP] Fatal error: ' . ($error['message'] ?? 'Unknown error') . ' in ' . ($error['file'] ?? 'unknown file') . ':' . ($error['line'] ?? 0));
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
    }
    echo json_encode([
        'status' => 'failure',
        'error' => 'Internal server error. Check the server PHP error log for details.'
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
});

use OvertePHP\Http;
use OvertePHP\Router;
use OvertePHP\JsonStore;
use OvertePHP\Auth;
use OvertePHP\Maintenance;

$config = require dirname(__DIR__) . '/config/config.php';
$store = new JsonStore($config['storage_path']);
$auth = new Auth($store, $config);
$GLOBALS['overte_php_config'] = $config;

// Throttled activity maintenance runs during normal traffic; no daemon is required.
Maintenance::run($store, $config);

$router = new Router();
require dirname(__DIR__) . '/app/routes.php';

Http::cors($config);
$requestPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

// Overte Domain Server addresses the Directory Service under the /server
// URL prefix (for example /server/api/v1/domains/{id}/public_key). The PHP
// application keeps its route definitions prefix-free so the same API can
// also be used directly at the site root. Normalize both forms here.
if ($requestPath === '/server') {
    $requestPath = '/';
} elseif (strncmp($requestPath, '/server/', 8) === 0) {
    $requestPath = substr($requestPath, 7);
}

$router->dispatch($_SERVER['REQUEST_METHOD'] ?? 'GET', $requestPath, $store, $auth, $config);
