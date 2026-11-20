<?php
declare(strict_types=1);

namespace OvertePHP;

final class Http
{
    public static function cors(array $config): void
    {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        $allowed = $config['cors_origins'] ?? ['*'];
        if (in_array('*', $allowed, true) || ($origin !== '' && in_array($origin, $allowed, true))) {
            header('Access-Control-Allow-Origin: ' . (in_array('*', $allowed, true) ? '*' : $origin));
        }
        header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Authorization, Content-Type, X-Vircadia-Error-Handle');
        header('Access-Control-Max-Age: 86400');
        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
            http_response_code(204);
            exit;
        }
    }

    public static function body(): array
    {
        $contentType = strtolower($_SERVER['CONTENT_TYPE'] ?? '');
        if (str_contains($contentType, 'application/x-www-form-urlencoded')) {
            $data = $_POST;
            self::logDomainRequestPayload($data, $contentType, null);
            return $data;
        }
        $raw = file_get_contents('php://input');
        if ($raw === false || trim($raw) === '') {
            self::logDomainRequestPayload([], $contentType, ['body_bytes' => 0, 'json_valid' => null]);
            return [];
        }
        $data = json_decode($raw, true);
        $parsed = is_array($data) ? $data : [];
        self::logDomainRequestPayload($parsed, $contentType, [
            'body_bytes' => strlen($raw),
            'json_valid' => is_array($data),
        ]);
        return $parsed;
    }

    public static function json(mixed $data, int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        if (self::isDomainDiagnosticRequest()) {
            Logger::debug($GLOBALS['overte_php_config'] ?? [], 'http.response_payload', [
                'response_status' => $status,
                'content_type' => 'application/json; charset=utf-8',
                'payload' => $data,
            ]);
        }
        echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }

    private static function logDomainRequestPayload(array $payload, string $contentType, ?array $metadata): void
    {
        if (!self::isDomainDiagnosticRequest()) {
            return;
        }
        $context = ['content_type' => $contentType, 'payload' => $payload];
        if ($metadata !== null) {
            $context['body_metadata'] = $metadata;
        }
        Logger::debug($GLOBALS['overte_php_config'] ?? [], 'http.request_payload', $context);
    }

    private static function isDomainDiagnosticRequest(): bool
    {
        $path = parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH) ?: '';
        return (bool)preg_match('#(?:^|/)api/v1/domains(?:/|$)#', $path);
    }

    public static function success(mixed $data = null): never
    {
        $response = ['status' => 'success'];
        if ($data !== null) {
            $response['data'] = $data;
        }
        self::json($response);
    }

    public static function failure(string $message, int $status = 200, ?string $info = null): never
    {
        $response = ['status' => 'failure', 'error' => $message];
        if ($info !== null && $info !== '') {
            $response['errorInfo'] = $info;
        }
        self::json($response, $status);
    }
}
