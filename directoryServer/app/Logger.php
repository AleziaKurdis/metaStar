<?php
declare(strict_types=1);

namespace OvertePHP;

/** Small file logger for application diagnostics; never writes credentials. */
final class Logger
{
    public static function debug(array $config, string $event, array $context = []): void
    {
        $debug = is_array($config['debug'] ?? null) ? $config['debug'] : [];
        if (empty($debug['enabled'])) {
            return;
        }
        self::append($config, $event, $context);
    }

    public static function auth(array $config, string $event, array $context = []): void
    {
        $debug = is_array($config['debug'] ?? null) ? $config['debug'] : [];
        if (empty($debug['enabled']) || empty($debug['auth_logging'])) {
            return;
        }
        self::append($config, 'auth.' . $event, $context);
    }

    private static function append(array $config, string $event, array $context): void
    {
        $debug = is_array($config['debug'] ?? null) ? $config['debug'] : [];
        $storagePath = (string)($config['storage_path'] ?? dirname(__DIR__) . '/data');
        $logPath = trim((string)($debug['log_file'] ?? ''));
        if ($logPath === '') {
            $logPath = rtrim($storagePath, DIRECTORY_SEPARATOR) . '/logs/overte-debug.log';
        }

        $directory = dirname($logPath);
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            return;
        }

        $record = [
            'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
            'level' => 'DEBUG',
            'event' => $event,
            'method' => (string)($_SERVER['REQUEST_METHOD'] ?? 'CLI'),
            'path' => parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH) ?: '',
            'context' => self::sanitize($context),
        ];
        $line = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($line)) {
            return;
        }
        $handle = @fopen($logPath, 'ab');
        if ($handle === false) {
            return;
        }
        @chmod($logPath, 0600);
        if (@flock($handle, LOCK_EX)) {
            fwrite($handle, $line . PHP_EOL);
            fflush($handle);
            flock($handle, LOCK_UN);
        }
        fclose($handle);
    }

    /** Redact sensitive values defensively, even if a caller passes them by mistake. */
    private static function sanitize(array $data): array
    {
        $safe = [];
        foreach ($data as $key => $value) {
            $name = strtolower((string)$key);
            if (preg_match('/access.?token|refresh.?token|password|secret|authorization|api.?key|private.?key/', $name) || in_array($name, ['token', 'token_value', 'credential', 'credential_value'], true)) {
                $safe[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $safe[$key] = self::sanitize($value);
            } elseif (is_scalar($value) || $value === null) {
                $safe[$key] = $value;
            } else {
                $safe[$key] = gettype($value);
            }
        }
        return $safe;
    }
}
