<?php
declare(strict_types=1);

namespace OvertePHP;

use RuntimeException;

/**
 * Small JSON-file document store.
 *
 * Each collection is a JSON array. A separate lock file serializes writers,
 * and writes are committed by rename so readers never see a half-written file.
 */
final class JsonStore
{
    private string $directory;

    public function __construct(string $directory)
    {
        $this->directory = rtrim($directory, DIRECTORY_SEPARATOR);
        if (!is_dir($this->directory) && !mkdir($this->directory, 0750, true) && !is_dir($this->directory)) {
            throw new RuntimeException('Unable to create JSON storage directory.');
        }
    }

    private function collectionPath(string $collection): string
    {
        if (!preg_match('/^[a-z][a-z0-9_-]{0,63}$/i', $collection)) {
            throw new RuntimeException('Invalid collection name.');
        }
        return $this->directory . DIRECTORY_SEPARATOR . strtolower($collection) . '.json';
    }

    private function readUnlocked(string $collection): array
    {
        $path = $this->collectionPath($collection);
        if (!is_file($path)) {
            return [];
        }
        $raw = file_get_contents($path);
        if ($raw === false || trim($raw) === '') {
            return [];
        }
        $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($data)) {
            throw new RuntimeException('Collection file must contain a JSON array: ' . basename($path));
        }
        return $data;
    }

    private function writeUnlocked(string $collection, array $records): void
    {
        $path = $this->collectionPath($collection);
        $json = json_encode(array_values($records), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        $temp = $path . '.' . bin2hex(random_bytes(6)) . '.tmp';
        if (file_put_contents($temp, $json . PHP_EOL, LOCK_EX) === false) {
            throw new RuntimeException('Unable to write collection: ' . $collection);
        }
        chmod($temp, 0640);
        if (!rename($temp, $path)) {
            @unlink($temp);
            throw new RuntimeException('Unable to commit collection: ' . $collection);
        }
    }

    public function all(string $collection): array
    {
        $lock = fopen($this->collectionPath($collection) . '.lock', 'c');
        if (!$lock) {
            throw new RuntimeException('Unable to open collection lock.');
        }
        try {
            flock($lock, LOCK_SH);
            return $this->readUnlocked($collection);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public function find(string $collection, callable $predicate): array
    {
        return array_values(array_filter($this->all($collection), $predicate));
    }

    public function first(string $collection, callable $predicate): ?array
    {
        foreach ($this->all($collection) as $record) {
            if ($predicate($record)) {
                return $record;
            }
        }
        return null;
    }

    public function insert(string $collection, array $record): array
    {
        $lock = fopen($this->collectionPath($collection) . '.lock', 'c');
        if (!$lock) {
            throw new RuntimeException('Unable to open collection lock.');
        }
        try {
            flock($lock, LOCK_EX);
            $records = $this->readUnlocked($collection);
            if (!isset($record['id']) || $record['id'] === '') {
                $record['id'] = self::uuid();
            }
            foreach ($records as $existing) {
                if (($existing['id'] ?? null) === $record['id']) {
                    throw new RuntimeException('Duplicate record id.');
                }
            }
            $records[] = $record;
            $this->writeUnlocked($collection, $records);
            return $record;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public function update(string $collection, string $id, array $changes): ?array
    {
        $lock = fopen($this->collectionPath($collection) . '.lock', 'c');
        if (!$lock) {
            throw new RuntimeException('Unable to open collection lock.');
        }
        try {
            flock($lock, LOCK_EX);
            $records = $this->readUnlocked($collection);
            $updated = null;
            foreach ($records as &$record) {
                if (($record['id'] ?? null) === $id) {
                    $record = array_replace($record, $changes);
                    $updated = $record;
                    break;
                }
            }
            unset($record);
            if ($updated !== null) {
                $this->writeUnlocked($collection, $records);
            }
            return $updated;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public function delete(string $collection, string $id): bool
    {
        $lock = fopen($this->collectionPath($collection) . '.lock', 'c');
        if (!$lock) {
            throw new RuntimeException('Unable to open collection lock.');
        }
        try {
            flock($lock, LOCK_EX);
            $records = $this->readUnlocked($collection);
            $remaining = array_values(array_filter($records, static fn(array $r): bool => ($r['id'] ?? null) !== $id));
            if (count($remaining) === count($records)) {
                return false;
            }
            $this->writeUnlocked($collection, $remaining);
            return true;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public static function uuid(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        $hex = bin2hex($bytes);
        return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4) . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20);
    }
}
