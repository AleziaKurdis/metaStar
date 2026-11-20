(() => {
    const statusBox = document.getElementById('status');
    const form = document.getElementById('setup-form');
    const submit = document.getElementById('submit');

    function showMessage(message, type = '') {
        statusBox.textContent = message;
        statusBox.className = `message ${type}`.trim();
    }

    async function readApiResponse(response, endpoint) {
        const body = await response.text();
        if (!body.trim()) {
            throw new Error(
                `The server returned an empty response for ${endpoint} (HTTP ${response.status}). ` +
                'The PHP API may have failed. Check the PHP error log and verify that API requests are routed to public/index.php.'
            );
        }

        try {
            return JSON.parse(body);
        } catch (error) {
            const contentType = response.headers.get('content-type') || 'unknown';
            throw new Error(
                `The server returned an unexpected response for ${endpoint} ` +
                `(HTTP ${response.status}, content type: ${contentType}; JSON was expected). ` +
                'Check the server rewrite rules and PHP error log.'
            );
        }
    }

    async function loadStatus() {
        const endpoint = new URL('../api/v1/setup/status', window.location.href);
        try {
            const response = await fetch(endpoint, { headers: { 'Accept': 'application/json' } });
            const result = await readApiResponse(response, endpoint.pathname);
            if (!response.ok || result.status !== 'success') throw new Error(result.error || 'Unable to check setup status.');
            if (!result.data.available) {
                showMessage('Initial setup is unavailable. An account may already exist, or the server setup key has not been configured.');
                return;
            }
            document.getElementById('username').value = result.data.username;
            form.hidden = false;
            showMessage('No accounts exist yet. You can create the first administrator account.');
        } catch (error) {
            showMessage(error.message, 'error');
        }
    }

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const password = document.getElementById('password').value;
        const confirmation = document.getElementById('password-confirm').value;
        if (password !== confirmation) {
            showMessage('The passwords do not match.', 'error');
            return;
        }
        submit.disabled = true;
        showMessage('Creating administrator account…');
        try {
            const endpoint = new URL('../api/v1/setup/admin', window.location.href);
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                body: JSON.stringify({
                    setup_key: document.getElementById('setup-key').value,
                    email: document.getElementById('email').value,
                    password
                })
            });
            const result = await readApiResponse(response, endpoint.pathname);
            if (!response.ok || result.status !== 'success') throw new Error(result.error || 'Administrator setup failed.');
            form.hidden = true;
            showMessage(`Administrator account “${result.data.username}” created. You can now sign in at /dashboard/.`, 'success');
        } catch (error) {
            showMessage(error.message, 'error');
            submit.disabled = false;
        }
    });

    loadStatus();
})();
