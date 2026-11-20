<?php
/**
 * Minimal example for registering a Directory Service with the Go ICE Server.
 *
 * The caller must supply the complete current domain UUID list. Call this when
 * domains are added/removed and periodically to refresh the registration.
 * Keep the token private and keep TLS verification enabled.
 */
function overteIceRegisterDirectory(
    string $iceServerIp,
    int $icePort,
    string $directoryId,
    string $registrationToken,
    string $directoryBaseUrl,
    array $domainUuids,
    string $iceCaCertificateFile
): array {
    if (!function_exists('curl_init')) {
        return ['success' => false, 'error' => 'PHP cURL extension is required.'];
    }

    $url = 'https://' . $iceServerIp . ':' . $icePort . '/v1/register';
    $payload = json_encode([
        'directory_id' => $directoryId,
        'base_url' => rtrim($directoryBaseUrl, '/'),
        'domains' => array_values($domainUuids),
    ], JSON_UNESCAPED_SLASHES);

    if ($payload === false) {
        return ['success' => false, 'error' => 'Could not encode registration JSON.'];
    }

    $curl = curl_init($url);
    curl_setopt_array($curl, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $registrationToken,
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_CAINFO => $iceCaCertificateFile,
    ]);

    $response = curl_exec($curl);
    $curlError = curl_error($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
    curl_close($curl);

    if ($response === false) {
        return ['success' => false, 'error' => 'ICE registration request failed: ' . $curlError];
    }

    $decoded = json_decode($response, true);
    if ($status !== 200 || !is_array($decoded) || ($decoded['status'] ?? '') !== 'success') {
        return [
            'success' => false,
            'http_status' => $status,
            'error' => is_array($decoded) ? ($decoded['message'] ?? 'ICE registration rejected.') : 'Invalid ICE response.',
        ];
    }

    return ['success' => true, 'message' => $decoded['message'] ?? 'Registered.'];
}
