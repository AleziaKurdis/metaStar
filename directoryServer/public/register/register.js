(() => {
    'use strict';

    const form = document.getElementById('register-form');
    const message = document.getElementById('form-message');
    const submit = document.getElementById('submit-button');

    function showMessage(text, type) {
        message.textContent = text;
        message.className = 'message' + (type ? ' ' + type : '');
        message.hidden = false;
    }

    async function readResponse(response, endpoint) {
        const text = await response.text();
        if (!text.trim()) {
            throw new Error('The server returned an empty response. Please try again later.');
        }
        let result;
        try {
            result = JSON.parse(text);
        } catch (_) {
            throw new Error('The server returned an unexpected response. Please contact the server administrator.');
        }
        if (!response.ok || result.status !== 'success') {
            throw new Error(result.error || result.message || 'Account creation failed.');
        }
        return result.data || {};
    }

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const username = document.getElementById('username').value.trim();
        const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value;
        const confirmation = document.getElementById('password-confirm').value;

        if (password !== confirmation) {
            showMessage('The passwords do not match.', 'error');
            document.getElementById('password-confirm').focus();
            return;
        }

        submit.disabled = true;
        submit.textContent = 'Creating account…';
        message.hidden = true;

        try {
            const endpoint = new URL('../api/v1/users', window.location.href);
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                body: JSON.stringify({ user: { username, email, password } })
            });
            const data = await readResponse(response, endpoint.pathname);
            let destination;
            if (data.accountAwaitingVerification && data.verificationEmailSent === false) {
                destination = '../login/?registered=verification-failed';
            } else if (data.accountAwaitingVerification) {
                destination = '../login/?registered=verification';
            } else {
                destination = '../login/?registered=1';
            }
            window.location.replace(destination);
        } catch (error) {
            showMessage(error.message, 'error');
            submit.disabled = false;
            submit.textContent = 'Create account';
        }
    });
})();
