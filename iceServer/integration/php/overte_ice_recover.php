<?php
/**
 * Recover a lost ICE registration token for an already-enrolled Directory Service.
 *
 * Recovery requires the out-of-band enrollment secret configured on the ICE
 * Server. It rotates the token, immediately invalidating the previous one.
 * Keep both the enrollment secret and returned token private.
 */
function metaStarIceRecover(
    string $ip,
    int $port,
    string $directoryId,
    string $enrollmentSecret,
    string $caCert
): array {
    if (!function_exists('curl_init')) {
        return ['success' => false, 'error' => 'PHP cURL extension is required.'];
    }
    if (trim($directoryId) === '' || trim($enrollmentSecret) === '') {
        return ['success' => false, 'error' => 'Directory ID and enrollment secret are required.'];
    }
    if (!is_file($caCert) || !is_readable($caCert)) {
        return ['success' => false, 'error' => 'The ICE CA certificate file is missing or unreadable.'];
    }

    $payload = json_encode(['directory_id' => $directoryId], JSON_UNESCAPED_SLASHES);
    if ($payload === false) {
        return ['success' => false, 'error' => 'Could not encode recovery JSON.'];
    }

    $curl = curl_init('https://' . $ip . ':' . $port . '/v1/recover');
    curl_setopt_array($curl, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $enrollmentSecret,
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_CAINFO => $caCert,
    ]);

    $response = curl_exec($curl);
    $curlError = curl_error($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
    curl_close($curl);

    if ($response === false) {
        return ['success' => false, 'error' => 'ICE recovery request failed: ' . $curlError];
    }

    $decoded = json_decode($response, true);
    $token = is_array($decoded) ? (string) ($decoded['registration_token'] ?? '') : '';
    if ($status !== 200 || !is_array($decoded) || ($decoded['status'] ?? '') !== 'success'
        || preg_match('/^[a-f0-9]{64}$/i', $token) !== 1) {
        return [
            'success' => false,
            'http_status' => $status,
            'error' => is_array($decoded) ? ($decoded['message'] ?? 'ICE recovery was rejected or returned an invalid token.') : 'Invalid ICE response.',
        ];
    }

    return ['success' => true, 'registration_token' => $token];
}
