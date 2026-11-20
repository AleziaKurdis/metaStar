<?php
/** First-time directory enrollment. Keep the enrollment secret and issued token private.
 * The ICE certificate must be trusted; never disable peer verification.
 * Use this only during initial setup. Subsequent updates use overteIceRegisterDirectory().
 */
function metaStarIceEnroll(string $ip, int $port, string $directoryId, string $baseUrl,
    array $domainUuids, string $enrollmentSecret, string $caCert): array {
    $ch = curl_init('https://' . $ip . ':' . $port . '/v1/enroll');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode(['directory_id'=>$directoryId, 'base_url'=>$baseUrl,
            'domains'=>array_values($domainUuids)], JSON_UNESCAPED_SLASHES),
        CURLOPT_HTTPHEADER => ['Content-Type: application/json','Authorization: Bearer '.$enrollmentSecret],
        CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20,
        CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_CAINFO => $caCert,
    ]);
    $response = curl_exec($ch);
    $error = curl_error($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($response === false) return ['success'=>false,'error'=>$error];
    $body = json_decode($response, true);
    if ($status !== 200 || !is_array($body) || ($body['status']??'')!=='success')
        return ['success'=>false,'error'=>$body['message']??'Enrollment failed'];
    return ['success'=>true,'registration_token'=>$body['registration_token']];
}
