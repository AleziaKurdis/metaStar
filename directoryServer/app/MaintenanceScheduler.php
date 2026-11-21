<?php
declare(strict_types=1);

namespace OvertePHP;

use RuntimeException;
use Throwable;

/**
 * Heartbeat-triggered task queue for work that must not run inside an API response.
 *
 * Domain heartbeats only enqueue due work. A CLI worker (normally invoked by cron)
 * performs network operations after the heartbeat response has completed.
 */
final class MaintenanceScheduler
{
    /**
     * Mark ICE synchronization as pending when a domain heartbeat arrives.
     * This method performs local JSON storage operations only; it never contacts ICE.
     */
    public static function onDomainHeartbeat(JsonStore $store, array $config, ?int $now = null): array
    {
        $now ??= time();
        $storagePath = rtrim((string)($config['storage_path'] ?? ''), DIRECTORY_SEPARATOR);
        $tokenFile = $storagePath . DIRECTORY_SEPARATOR . 'ice-registration.json';

        // The scheduler remains dormant until this Directory Server has enrolled.
        if (empty($config['ice_control_url']) || $storagePath === '' || !is_file($tokenFile)) {
            return ['queued' => false, 'reason' => 'ice_not_enrolled_or_configured'];
        }

        $interval = max(60, (int)($config['ice_sync_interval_seconds'] ?? 300));
        $state = $store->first('scheduled_tasks', static fn(array $task): bool => ($task['id'] ?? '') === 'ice_sync');

        if (!empty($state['pending'])) {
            return ['queued' => true, 'reason' => 'already_pending'];
        }

        $lastSuccess = (int)($state['lastSuccess'] ?? 0);
        if ($lastSuccess > 0 && ($now - $lastSuccess) < $interval) {
            return ['queued' => false, 'reason' => 'not_due'];
        }

        $record = array_replace($state ?? [], [
            'id' => 'ice_sync',
            'pending' => true,
            'requestedAt' => $now,
            'nextAttemptAt' => 0,
            'intervalSeconds' => $interval
        ]);
        self::saveTask($store, $state, $record);
        return ['queued' => true, 'reason' => 'scheduled'];
    }

    /**
     * Execute pending tasks from CLI, never from the heartbeat request.
     * A private flock prevents overlapping workers on shared hosting.
     */
    public static function runPending(JsonStore $store, array $config, ?int $now = null): array
    {
        $now ??= time();
        $storagePath = rtrim((string)($config['storage_path'] ?? ''), DIRECTORY_SEPARATOR);
        if ($storagePath === '' || !is_dir($storagePath)) {
            throw new RuntimeException('Directory storage_path is not available.');
        }

        $lockPath = $storagePath . DIRECTORY_SEPARATOR . 'maintenance-scheduler.lock';
        $previousUmask = umask(0077);
        $lock = @fopen($lockPath, 'c');
        umask($previousUmask);
        if ($lock === false) {
            throw new RuntimeException('Could not open the maintenance scheduler lock.');
        }
        @chmod($lockPath, 0600);

        if (!flock($lock, LOCK_EX | LOCK_NB)) {
            fclose($lock);
            return ['skipped' => true, 'reason' => 'worker_already_running'];
        }

        try {
            $state = $store->first('scheduled_tasks', static fn(array $task): bool => ($task['id'] ?? '') === 'ice_sync');
            if (!$state || empty($state['pending'])) {
                return ['skipped' => true, 'reason' => 'no_pending_tasks'];
            }
            if ((int)($state['nextAttemptAt'] ?? 0) > $now) {
                return ['skipped' => true, 'reason' => 'retry_not_due'];
            }

            try {
                $service = new IceRegistrationService($store, $config);
                $result = $service->sync();
                $completedAt = time();
                $record = array_replace($state, [
                    'pending' => false,
                    'lastSuccess' => $completedAt,
                    'lastAttempt' => $completedAt,
                    'nextAttemptAt' => 0,
                    'attempts' => 0,
                    'lastError' => null,
                    'lastResult' => $result
                ]);
                $store->update('scheduled_tasks', 'ice_sync', $record);
                return ['skipped' => false, 'task' => 'ice_sync', 'success' => true, 'result' => $result];
            } catch (Throwable $error) {
                $attemptedAt = time();
                $retrySeconds = max(30, (int)($config['scheduler_retry_seconds'] ?? 60));
                $attempts = (int)($state['attempts'] ?? 0) + 1;
                $record = array_replace($state, [
                    'pending' => true,
                    'lastAttempt' => $attemptedAt,
                    'nextAttemptAt' => $attemptedAt + $retrySeconds,
                    'attempts' => $attempts,
                    'lastError' => substr($error->getMessage(), 0, 1000)
                ]);
                $store->update('scheduled_tasks', 'ice_sync', $record);
                return [
                    'skipped' => false,
                    'task' => 'ice_sync',
                    'success' => false,
                    'attempts' => $attempts,
                    'retry_at' => $attemptedAt + $retrySeconds,
                    'error' => $error->getMessage()
                ];
            }
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private static function saveTask(JsonStore $store, ?array $existing, array $record): void
    {
        if ($existing !== null) {
            $store->update('scheduled_tasks', 'ice_sync', $record);
            return;
        }

        try {
            $store->insert('scheduled_tasks', $record);
        } catch (RuntimeException $error) {
            // Two heartbeat requests may race to create the first task record.
            // The unique task ID makes the losing request safe to reconcile.
            $current = $store->first('scheduled_tasks', static fn(array $task): bool => ($task['id'] ?? '') === 'ice_sync');
            if ($current === null) {
                throw $error;
            }
            if (empty($current['pending'])) {
                $store->update('scheduled_tasks', 'ice_sync', $record);
            }
        }
    }
}
