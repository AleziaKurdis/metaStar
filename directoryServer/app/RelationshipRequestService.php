<?php
declare(strict_types=1);

namespace OvertePHP;

/** Persistent account-to-account requests (connection, friend and follow). */
final class RelationshipRequestService
{
    public const TYPES = ['connection', 'friend', 'follow'];

    public static function create(JsonStore $store, array $requester, string $targetIdentifier, string $type, int $now, array $config): array
    {
        $type = strtolower(trim($type));
        if (!in_array($type, self::TYPES, true)) Http::failure('Unsupported relationship request type', 400);
        $targetIdentifier = trim($targetIdentifier);
        if ($targetIdentifier === '') Http::failure('Target account is required', 400);

        $target = $store->first('accounts', static fn(array $a): bool =>
            ($a['id'] ?? '') === $targetIdentifier || strcasecmp((string)($a['username'] ?? ''), $targetIdentifier) === 0
        );
        if (!$target) Http::failure('Target account not found', 404);
        if (($target['id'] ?? '') === ($requester['id'] ?? '')) Http::failure('Cannot create a relationship request to yourself', 400);

        $requesterId = (string)$requester['id'];
        $targetId = (string)$target['id'];
        $requesterFresh = $store->first('accounts', static fn(array $a): bool => ($a['id'] ?? '') === $requesterId) ?? $requester;
        $targetFresh = $store->first('accounts', static fn(array $a): bool => ($a['id'] ?? '') === $targetId) ?? $target;
        if (self::alreadyRelated($requesterFresh, $targetFresh, $type)) {
            Http::failure('Relationship already exists', 409);
        }

        // An opposite pending request can be accepted by the target's reply, so
        // avoid maintaining two competing records for the same pair and type.
        $existing = $store->first('requests', static fn(array $r): bool =>
            ($r['requestType'] ?? '') === $type &&
            ((($r['requestingAccountId'] ?? '') === $requesterId && ($r['targetAccountId'] ?? '') === $targetId) ||
             (($r['requestingAccountId'] ?? '') === $targetId && ($r['targetAccountId'] ?? '') === $requesterId)) &&
            self::expiresAfter($r, $now)
        );
        if ($existing) {
            if (($existing['requestingAccountId'] ?? '') === $targetId) {
                return self::accept($store, $existing, $requesterId, $now);
            }
            Http::failure('A request of this type is already pending', 409);
        }

        $days = max(1, min(90, (int)($config['relationship_request_expiration_days'] ?? 14)));
        return $store->insert('requests', [
            'id' => JsonStore::uuid(),
            'requestType' => $type,
            'requestingAccountId' => $requesterId,
            'targetAccountId' => $targetId,
            'whenCreated' => gmdate('c', $now),
            'expirationTime' => gmdate('c', $now + $days * 86400)
        ]);
    }

    public static function listFor(JsonStore $store, string $accountId, int $now): array
    {
        self::cleanupExpired($store, $now);
        return $store->find('requests', static fn(array $r): bool =>
            in_array(($r['requestType'] ?? ''), self::TYPES, true) &&
            (($r['requestingAccountId'] ?? '') === $accountId || ($r['targetAccountId'] ?? '') === $accountId)
        );
    }

    public static function accept(JsonStore $store, array $request, string $actorId, int $now): array
    {
        if (($request['targetAccountId'] ?? '') !== $actorId) Http::failure('Only the target account may accept this request', 403);
        if (!in_array(($request['requestType'] ?? ''), self::TYPES, true)) Http::failure('Unsupported request type', 400);
        if (!self::expiresAfter($request, $now)) {
            $store->delete('requests', (string)$request['id']);
            Http::failure('Request has expired', 410);
        }
        $requesterId = (string)$request['requestingAccountId'];
        $targetId = (string)$request['targetAccountId'];
        $requester = $store->first('accounts', static fn(array $a): bool => ($a['id'] ?? '') === $requesterId);
        $target = $store->first('accounts', static fn(array $a): bool => ($a['id'] ?? '') === $targetId);
        if (!$requester || !$target) Http::failure('Request account no longer exists', 404);

        $type = (string)$request['requestType'];
        if ($type === 'connection' || $type === 'friend') {
            self::addRelationship($store, $requester, $target, 'connections');
            self::addRelationship($store, $target, $requester, 'connections');
        }
        if ($type === 'friend') {
            self::addRelationship($store, $requester, $target, 'friends');
            self::addRelationship($store, $target, $requester, 'friends');
        }
        if ($type === 'follow') {
            self::addRelationship($store, $requester, $target, 'following');
            self::addRelationship($store, $target, $requester, 'followers');
        }
        $store->delete('requests', (string)$request['id']);
        return ['type' => $type, 'requester' => $requester['username'] ?? '', 'target' => $target['username'] ?? '', 'accepted' => true];
    }

    public static function reject(JsonStore $store, array $request, string $actorId): bool
    {
        if (($request['targetAccountId'] ?? '') !== $actorId) Http::failure('Only the target account may reject this request', 403);
        return $store->delete('requests', (string)$request['id']);
    }

    public static function cancel(JsonStore $store, array $request, string $actorId): bool
    {
        if (($request['requestingAccountId'] ?? '') !== $actorId) Http::failure('Only the requesting account may cancel this request', 403);
        return $store->delete('requests', (string)$request['id']);
    }

    public static function cleanupExpired(JsonStore $store, ?int $now = null): int
    {
        $now ??= time();
        $removed = 0;
        foreach ($store->all('requests') as $request) {
            if (!self::expiresAfter($request, $now) && $store->delete('requests', (string)($request['id'] ?? ''))) $removed++;
        }
        return $removed;
    }

    private static function expiresAfter(array $request, int $now): bool
    {
        $expires = strtotime((string)($request['expirationTime'] ?? ''));
        return $expires !== false && $expires > $now;
    }

    private static function alreadyRelated(array $first, array $second, string $type): bool
    {
        $a = (string)($second['username'] ?? '');
        $b = (string)($first['username'] ?? '');
        if ($type === 'follow') return self::contains($first['following'] ?? [], $a);
        if (self::contains($first['connections'] ?? [], $a) && self::contains($second['connections'] ?? [], $b)) {
            return $type !== 'friend' || (self::contains($first['friends'] ?? [], $a) && self::contains($second['friends'] ?? [], $b));
        }
        return false;
    }

    private static function addRelationship(JsonStore $store, array $owner, array $other, string $field): void
    {
        $fresh = $store->first('accounts', static fn(array $a): bool => ($a['id'] ?? '') === ($owner['id'] ?? '')) ?? $owner;
        $values = is_array($fresh[$field] ?? null) ? $fresh[$field] : [];
        $name = (string)($other['username'] ?? '');
        if ($name !== '' && !self::contains($values, $name)) {
            $values[] = $name;
            $store->update('accounts', (string)$fresh['id'], [$field => array_values($values)]);
        }
    }

    private static function contains(mixed $values, string $name): bool
    {
        if (!is_array($values)) return false;
        foreach ($values as $value) if (is_string($value) && strcasecmp($value, $name) === 0) return true;
        return false;
    }
}
