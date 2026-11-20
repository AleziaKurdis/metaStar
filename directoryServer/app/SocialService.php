<?php
declare(strict_types=1);

namespace OvertePHP;

final class SocialService
{
    public static function handleConnectionRequest(JsonStore $store, array $account, string $thisNode, string $otherNode, int $now, array $config): array
    {
        $thisNode = trim($thisNode);
        $otherNode = trim($otherNode);
        if ($thisNode === '' || $otherNode === '' || $thisNode === $otherNode) {
            Http::failure('badly formed request');
        }

        self::cleanupExpired($store, $now);
        $request = $store->first('requests', static function (array $item) use ($thisNode, $otherNode, $now): bool {
            if (($item['requestType'] ?? '') !== 'handshake') return false;
            $expires = strtotime((string)($item['expirationTime'] ?? ''));
            if (!$expires || $expires <= $now) return false;
            return (($item['requesterNodeId'] ?? '') === $thisNode && ($item['targetNodeId'] ?? '') === $otherNode) ||
                (($item['requesterNodeId'] ?? '') === $otherNode && ($item['targetNodeId'] ?? '') === $thisNode);
        });

        if (!$request) {
            $minutes = max(1, (int)($config['handshake_request_expiration_minutes'] ?? 1));
            $store->insert('requests', [
                'id' => JsonStore::uuid(),
                'requestType' => 'handshake',
                'requesterNodeId' => $thisNode,
                'targetNodeId' => $otherNode,
                'requesterAccepted' => true,
                'targetAccepted' => false,
                'requestingAccountId' => (string)$account['id'],
                'whenCreated' => gmdate('c', $now),
                'expirationTime' => gmdate('c', $now + $minutes * 60)
            ]);
            return ['connection' => 'pending'];
        }

        if (($request['requesterNodeId'] ?? '') === $thisNode) {
            // The initiating avatar is polling to learn whether the other avatar accepted.
            if (empty($request['targetAccepted'])) {
                return ['connection' => 'pending'];
            }
            $otherAccountId = (string)($request['targetAccountId'] ?? '');
            $requestingAccountId = (string)($request['requestingAccountId'] ?? '');
        } else {
            // The target avatar has accepted by initiating the same handshake in reverse.
            $otherAccountId = (string)($request['requestingAccountId'] ?? '');
            $requestingAccountId = (string)$account['id'];
            $request = $store->update('requests', (string)$request['id'], [
                'targetAccepted' => true,
                'targetAccountId' => (string)$account['id']
            ]) ?? $request;
        }

        if ($requestingAccountId === '' || $otherAccountId === '' || $requestingAccountId === $otherAccountId) {
            Http::failure('could not identify both accounts for connection');
        }
        $requesting = $store->first('accounts', static fn(array $a): bool => ($a['id'] ?? '') === $requestingAccountId);
        $target = $store->first('accounts', static fn(array $a): bool => ($a['id'] ?? '') === $otherAccountId);
        if (!$requesting || !$target) {
            Http::failure('account not found while making connection');
        }

        self::connectAccounts($store, $requesting, $target);
        $otherUsername = ($requestingAccountId === (string)$account['id'])
            ? (string)($target['username'] ?? 'UNKNOWN')
            : (string)($requesting['username'] ?? 'UNKNOWN');
        return ['connection' => ['new_connection' => true, 'username' => $otherUsername]];
    }

    public static function connectAccounts(JsonStore $store, array $first, array $second): void
    {
        $firstFresh = $store->first('accounts', static fn(array $a): bool => ($a['id'] ?? '') === ($first['id'] ?? '')) ?? $first;
        $secondFresh = $store->first('accounts', static fn(array $a): bool => ($a['id'] ?? '') === ($second['id'] ?? '')) ?? $second;
        $firstConnections = is_array($firstFresh['connections'] ?? null) ? $firstFresh['connections'] : [];
        $secondConnections = is_array($secondFresh['connections'] ?? null) ? $secondFresh['connections'] : [];
        $store->update('accounts', (string)$firstFresh['id'], [
            'connections' => ProfileService::addName($firstConnections, (string)$secondFresh['username'])
        ]);
        $store->update('accounts', (string)$secondFresh['id'], [
            'connections' => ProfileService::addName($secondConnections, (string)$firstFresh['username'])
        ]);
    }

    public static function cancelConnectionRequests(JsonStore $store, array $account): int
    {
        $nodeId = (string)($account['locationNodeId'] ?? '');
        $removed = 0;
        foreach ($store->all('requests') as $request) {
            if (($request['requestType'] ?? '') !== 'handshake') continue;
            $belongsToAccount = ($request['requestingAccountId'] ?? '') === ($account['id'] ?? '') ||
                ($request['targetAccountId'] ?? '') === ($account['id'] ?? '');
            $belongsToNode = $nodeId !== '' && (
                ($request['requesterNodeId'] ?? '') === $nodeId || ($request['targetNodeId'] ?? '') === $nodeId
            );
            if ($belongsToAccount || $belongsToNode) {
                if ($store->delete('requests', (string)$request['id'])) $removed++;
            }
        }
        return $removed;
    }

    public static function cleanupExpired(JsonStore $store, ?int $now = null): int
    {
        $now ??= time();
        $removed = 0;
        foreach ($store->all('requests') as $request) {
            $expires = strtotime((string)($request['expirationTime'] ?? ''));
            if ($expires && $expires <= $now && $store->delete('requests', (string)$request['id'])) {
                $removed++;
            }
        }
        return $removed;
    }

    public static function simplifiedPublicKey(?string $pem): string
    {
        if (!is_string($pem) || $pem === '') return '';
        $lines = preg_split('/\r?\n/', trim($pem)) ?: [];
        $lines = array_values(array_filter($lines, static fn(string $line): bool =>
            $line !== '' && !str_contains($line, 'BEGIN PUBLIC KEY') && !str_contains($line, 'END PUBLIC KEY')
        ));
        return implode('', $lines);
    }

    public static function uploadedPublicKeyDer(?array &$diagnostics = null): ?string
    {
        $diagnostics = [
            'source' => 'none',
            'content_type' => (string)($_SERVER['CONTENT_TYPE'] ?? ''),
            'body_bytes' => null,
            'part_found' => false,
            'der_bytes' => 0,
            'der_prefix_hex' => '',
        ];

        // PHP populates $_FILES for POST uploads, but the Overte client sends PUT.
        $file = $_FILES['public_key'] ?? null;
        if (is_array($file)) {
            $diagnostics['source'] = 'files';
            $diagnostics['upload_error'] = $file['error'] ?? null;
            $diagnostics['upload_size'] = $file['size'] ?? null;
            if (($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_OK && isset($file['tmp_name'])) {
                $contents = file_get_contents((string)$file['tmp_name']);
                if ($contents !== false && $contents !== '') {
                    $diagnostics['der_bytes'] = strlen($contents);
                    $diagnostics['der_prefix_hex'] = bin2hex(substr($contents, 0, 12));
                    return $contents;
                }
            }
        }

        $contentType = (string)($_SERVER['CONTENT_TYPE'] ?? '');
        $raw = file_get_contents('php://input');
        if (!is_string($raw)) $raw = '';
        $multipartDiagnostics = [];
        $contents = self::extractPublicKeyDerFromMultipart($raw, $contentType, $multipartDiagnostics);
        $diagnostics = array_merge($diagnostics, $multipartDiagnostics, [
            'source' => 'php_input',
            'body_bytes' => strlen($raw),
        ]);
        return $contents;
    }

    /** Extract the binary public_key part without trimming or modifying DER bytes. */
    public static function extractPublicKeyDerFromMultipart(string $raw, string $contentType, ?array &$diagnostics = null): ?string
    {
        $diagnostics = [
            'part_found' => false,
            'der_bytes' => 0,
            'der_prefix_hex' => '',
        ];
        if (!preg_match('/multipart\/form-data;\s*boundary=(?:"([^"]+)"|([^;\s]+))/i', $contentType, $matches)) {
            $diagnostics['error'] = 'multipart boundary missing';
            return null;
        }
        $boundary = ($matches[1] ?? '') !== '' ? $matches[1] : ($matches[2] ?? '');
        if ($boundary === '') {
            $diagnostics['error'] = 'multipart boundary empty';
            return null;
        }
        if ($raw === '') {
            $diagnostics['error'] = 'request body empty';
            return null;
        }

        foreach (explode('--' . $boundary, $raw) as $part) {
            $separator = strpos($part, "\r\n\r\n");
            if ($separator === false) continue;
            $headers = substr($part, 0, $separator);
            if (!preg_match('/Content-Disposition:\s*form-data;[^\r\n]*name="public_key"/i', $headers)) continue;

            $diagnostics['part_found'] = true;
            $contents = substr($part, $separator + 4);
            // The delimiter was removed by explode(); only remove the CRLF
            // immediately preceding it. Do not trim binary DER data.
            if (str_ends_with($contents, "\r\n")) {
                $contents = substr($contents, 0, -2);
            }
            if ($contents === '') {
                $diagnostics['error'] = 'public_key multipart part is empty';
                return null;
            }
            $diagnostics['der_bytes'] = strlen($contents);
            $diagnostics['der_prefix_hex'] = bin2hex(substr($contents, 0, 12));
            $diagnostics['der_sha256'] = hash('sha256', $contents);
            return $contents;
        }

        $diagnostics['error'] = 'public_key multipart part not found';
        return null;
    }

    /** Encode a DER length using ASN.1 definite-length encoding. */
    private static function derLength(int $length): string
    {
        if ($length < 0x80) return chr($length);
        $encoded = '';
        while ($length > 0) {
            $encoded = chr($length & 0xff) . $encoded;
            $length >>= 8;
        }
        return chr(0x80 | strlen($encoded)) . $encoded;
    }

    /** Wrap an ASN.1 value in a DER tag and length. */
    private static function derElement(int $tag, string $value): string
    {
        return chr($tag) . self::derLength(strlen($value)) . $value;
    }

    /** Convert PKCS#1 RSAPublicKey DER into SubjectPublicKeyInfo DER. */
    private static function pkcs1DerToSpkiDer(string $der): string
    {
        // AlgorithmIdentifier for rsaEncryption (1.2.840.113549.1.1.1) + NULL.
        $algorithmIdentifier = hex2bin('300d06092a864886f70d0101010500');
        if ($algorithmIdentifier === false) return '';

        // SubjectPublicKey is a BIT STRING whose first content byte is the
        // count of unused bits (zero for this byte-aligned RSA key).
        $subjectPublicKey = self::derElement(0x03, "\0" . $der);
        return self::derElement(0x30, $algorithmIdentifier . $subjectPublicKey);
    }

    public static function publicKeyPemFromDer(string $der, ?array &$diagnostics = null): ?string
    {
        $diagnostics = [
            'der_bytes' => strlen($der),
            'der_prefix_hex' => bin2hex(substr($der, 0, 12)),
            'der_sha256' => hash('sha256', $der),
            'format_attempts' => [],
        ];
        if ($der === '') {
            $diagnostics['error'] = 'empty key data';
            return null;
        }

        // Overte's RSAKeypairGenerator uses i2d_RSAPublicKey(), which emits
        // PKCS#1 DER. Rather than relying on PHP/OpenSSL accepting the legacy
        // "RSA PUBLIC KEY" PEM label, wrap PKCS#1 in the standard
        // SubjectPublicKeyInfo structure and pass it as "PUBLIC KEY" PEM.
        // Some clients may already send SPKI DER, so retain that as fallback.
        while (openssl_error_string() !== false) {
            // Clear stale errors before collecting this conversion's errors.
        }

        $spkiDer = self::pkcs1DerToSpkiDer($der);
        $diagnostics['format_attempts'][] = 'pkcs1_der_to_spki';
        $diagnostics['spki_der_bytes'] = strlen($spkiDer);
        $diagnostics['spki_der_prefix_hex'] = bin2hex(substr($spkiDer, 0, 16));
        $spkiPem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spkiDer), 64, "\n") . "-----END PUBLIC KEY-----\n";
        $key = $spkiDer !== '' ? @openssl_pkey_get_public($spkiPem) : false;

        if ($key === false) {
            $errors = [];
            while (($error = openssl_error_string()) !== false) $errors[] = $error;
            $diagnostics['pkcs1_der_to_spki_errors'] = $errors;

            // If the upload was already SubjectPublicKeyInfo DER, use it as-is.
            $diagnostics['format_attempts'][] = 'spki_der';
            $inputSpkiPem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
            $key = @openssl_pkey_get_public($inputSpkiPem);
            if ($key === false) {
                $errors = [];
                while (($error = openssl_error_string()) !== false) $errors[] = $error;
                $diagnostics['spki_errors'] = $errors;
                $diagnostics['error'] = 'OpenSSL could not parse the supplied public key';
                return null;
            }
        }

        $details = openssl_pkey_get_details($key);
        if (!is_array($details) || !isset($details['key'])) {
            $diagnostics['error'] = 'OpenSSL parsed the key but did not return PEM details';
            return null;
        }
        $diagnostics['key_type'] = $details['type'] ?? null;
        $diagnostics['key_bits'] = $details['bits'] ?? null;
        return $details['key'];
    }
}
