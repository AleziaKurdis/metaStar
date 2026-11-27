<?php
declare(strict_types=1);

require dirname(__DIR__) . '/app/bootstrap.php';

use OvertePHP\Auth;
use OvertePHP\JsonStore;

$config = require dirname(__DIR__) . '/config/config.php';
$store = new JsonStore($config['storage_path']);

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');

    $authorization = trim((string)($_SERVER['HTTP_AUTHORIZATION'] ?? ''));
    if (!preg_match('/^Bearer\s+(.+)$/i', $authorization, $matches)) {
        http_response_code(401);
        echo json_encode(['status' => 'failure', 'error' => 'Administrator sign-in is required.']);
        exit;
    }

    $account = (new Auth($store, $config))->accountForBearer(trim($matches[1]));
    if (!$account || !in_array('admin', $account['roles'] ?? [], true)) {
        http_response_code(403);
        echo json_encode(['status' => 'failure', 'error' => 'Administrator access is required.']);
        exit;
    }

    require dirname(__DIR__) . '/tests/ice-server-discovery.php';
    $results = runIceServerDiscoveryChecks();
    $passed = count(array_filter($results, static fn(array $result): bool => $result['passed']));
    $failed = count($results) - $passed;
    if ($failed > 0) http_response_code(500);
    echo json_encode([
        'status' => $failed === 0 ? 'success' : 'failure',
        'summary' => ['passed' => $passed, 'failed' => $failed],
        'results' => $results
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title>ICE discovery checks · MetaStar</title>
    <link rel="stylesheet" href="register/register.css">
    <link rel="stylesheet" href="brand.css">
    <style>
        .test-results { margin-top: 22px; display: grid; gap: 8px; }
        .test-result { padding: 10px 12px; border: 1px solid var(--line); border-radius: 6px; }
        .test-result.pass { color: #b8eadf; border-color: #426b60; }
        .test-result.fail { color: var(--danger); border-color: #74494d; }
        .test-summary { margin-top: 14px; font-weight: 700; }
        .test-help { color: var(--muted); font-size: 12px; line-height: 1.5; }
    </style>
</head>
<body>
<main class="auth-shell">
    <section class="auth-card">
        <a class="brand" href="dashboard/" aria-label="MetaStar Directory Server administration">
            <img class="brand-logo" src="logo.php" alt="MetaStar">
            <span class="brand-subtitle">DIRECTORY SERVER</span>
        </a>
        <div class="eyebrow">ADMINISTRATOR TOOL</div>
        <h1>ICE discovery checks</h1>
        <p class="intro">Run the Directory Server's URL-discovery unit checks. These checks do not contact the ICE server or modify stored data.</p>
        <p class="test-help" id="test-status">Checking administrator session…</p>
        <button id="run-tests" type="button" disabled>Run tests</button>
        <div id="test-results" class="test-results" aria-live="polite"></div>
    </section>
</main>
<script>
(() => {
    const token = sessionStorage.getItem('overteDashboardToken') || '';
    const status = document.getElementById('test-status');
    const button = document.getElementById('run-tests');
    const results = document.getElementById('test-results');
    if (!token) {
        status.textContent = 'Sign in to the administration dashboard in this browser tab first, then open this test page from its link.';
        return;
    }
    status.textContent = 'Administrator session found. The test request will be authenticated using your existing dashboard token.';
    button.disabled = false;
    button.addEventListener('click', async () => {
        button.disabled = true;
        button.textContent = 'Running…';
        results.replaceChildren();
        try {
            const response = await fetch('ice-discovery-test.php', {
                method: 'POST',
                headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'application/json' }
            });
            const data = await response.json();
            (data.results || []).forEach(result => {
                const item = document.createElement('div');
                item.className = 'test-result ' + (result.passed ? 'pass' : 'fail');
                item.textContent = (result.passed ? 'PASS — ' : 'FAIL — ') + result.name;
                results.appendChild(item);
            });
            const summary = document.createElement('p');
            summary.className = 'test-summary';
            summary.textContent = (data.summary?.passed || 0) + ' passed, ' + (data.summary?.failed || 0) + ' failed.';
            results.appendChild(summary);
            if (!response.ok && !data.results) throw new Error(data.error || 'Test request failed.');
        } catch (error) {
            const item = document.createElement('div');
            item.className = 'test-result fail';
            item.textContent = error.message || 'Unable to run tests.';
            results.appendChild(item);
        } finally {
            button.disabled = false;
            button.textContent = 'Run tests again';
        }
    });
})();
</script>
</body>
</html>
