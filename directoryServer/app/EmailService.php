<?php
declare(strict_types=1);

namespace OvertePHP;

/** Native PHP mail() wrapper. The host must have a configured mail transport. */
final class EmailService
{
    public static function send(array $config, string $to, string $subject, string $body): bool
    {
        if (empty($config['email_enabled'])) return false;
        if (!filter_var($to, FILTER_VALIDATE_EMAIL)) return false;

        $from = trim((string)($config['email_from'] ?? ''));
        if (!filter_var($from, FILTER_VALIDATE_EMAIL)) {
            error_log('Overte PHP: email_from is missing or invalid in the server configuration.');
            return false;
        }
        $name = trim((string)($config['email_from_name'] ?? $config['metaverse_name'] ?? 'Overte'));
        $name = str_replace(["\r", "\n", '"'], ['', '', '\\"'], $name);
        $subject = trim(str_replace(["\r", "\n"], '', $subject));
        $headers = [
            'From: ' . ($name !== '' ? '"' . $name . '" ' : '') . '<' . $from . '>',
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: 8bit'
        ];
        $sent = @mail($to, $subject, $body, implode("\r\n", $headers));
        if (!$sent) error_log('Overte PHP: mail() could not hand off a message to the server mail transport.');
        return $sent;
    }

    public static function baseUrl(array $config): string
    {
        $url = rtrim(trim((string)($config['metaverse_server_url'] ?? '')), '/');
        if ($url !== '') return $url;
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        return $scheme . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost');
    }
}
