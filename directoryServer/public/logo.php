<?php
declare(strict_types=1);

// Serve the operator-customizable SVG stored at the Directory Server project root.
$logo = dirname(__DIR__) . '/logo.svg';
if (!is_file($logo) || !is_readable($logo)) {
    http_response_code(404);
    exit;
}
header('Content-Type: image/svg+xml; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-cache, must-revalidate');
readfile($logo);
