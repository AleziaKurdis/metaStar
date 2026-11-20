(() => {
    'use strict';

    const TOKEN_KEY = 'overteAccountToken';
    const USER_KEY = 'overteAccountUser';
    const ACCOUNT_KEY = 'overteAccountId';
    const ROLES_KEY = 'overteAccountRoles';
    const form = document.getElementById('login-form');
    const message = document.getElementById('login-message');
    const submit = document.getElementById('submit-button');

    function showMessage(text, type) {
        if (!message) return;
        message.textContent = text;
        message.className = 'message' + (type ? ' ' + type : '');
        message.hidden = false;
    }

    function continueToDashboard(roles) {
        if (roles.includes('admin')) {
            sessionStorage.setItem('overteDashboardToken', sessionStorage.getItem(TOKEN_KEY) || '');
            sessionStorage.setItem('overteDashboardUser', sessionStorage.getItem(USER_KEY) || '');
            sessionStorage.setItem('overteDashboardAccountId', sessionStorage.getItem(ACCOUNT_KEY) || '');
            window.location.replace('../dashboard/');
            return;
        }
        window.location.replace('../account/');
    }

    function clearSession() {
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.removeItem(USER_KEY);
        sessionStorage.removeItem(ACCOUNT_KEY);
        sessionStorage.removeItem(ROLES_KEY);
    }

    async function restoreSession() {
        const token = sessionStorage.getItem(TOKEN_KEY);
        const username = sessionStorage.getItem(USER_KEY);
        if (!token || !username) return;
        try {
            const response = await fetch('../api/v1/user/profile', {
                headers: { 'Accept': 'application/json', 'Authorization': 'Bearer ' + token }
            });
            const result = await response.json();
            if (!response.ok || result.status !== 'success') throw new Error('Session expired');
            let roles = [];
            try { roles = JSON.parse(sessionStorage.getItem(ROLES_KEY) || '[]'); } catch (_) {}
            continueToDashboard(roles);
        } catch (_) {
            clearSession();
        }
    }

    const resendForm = document.getElementById('resend-form');
    const resendMessage = document.getElementById('resend-message');
    const resendButton = document.getElementById('resend-button');
    const resendEmail = document.getElementById('resend-email');

    if (resendForm && resendMessage && resendButton && resendEmail) {
        resendForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            resendButton.disabled = true;
            resendButton.textContent = 'Requesting…';
            resendMessage.hidden = true;

            try {
                const response = await fetch('../api/v1/account/verify/email/resend', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                    body: JSON.stringify({ email: resendEmail.value.trim() })
                });
                const result = await response.json();

                if (!response.ok || result.status !== 'success') {
                    throw new Error(result.error || 'Unable to process the request.');
                }

                resendMessage.textContent = result.data && result.data.message
                    ? result.data.message
                    : 'If the address belongs to an account that still needs verification and the request is eligible, instructions will be sent.';
                resendMessage.className = 'message success';
                resendMessage.hidden = false;
            } catch (error) {
                resendMessage.textContent = error.message;
                resendMessage.className = 'message error';
                resendMessage.hidden = false;
            } finally {
                resendButton.disabled = false;
                resendButton.textContent = 'Request another email';
            }
        });
    }

    if (form && submit && message) {
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            submit.disabled = true;
            submit.textContent = 'Signing in…';
            message.hidden = true;
            try {
                const body = new URLSearchParams({
                    grant_type: 'password',
                    scope: 'owner',
                    username: document.getElementById('login').value.trim(),
                    password: document.getElementById('password').value
                });
                const response = await fetch('../oauth/token', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
                    body: body.toString()
                });
                const result = await response.json();
                if (!response.ok || result.error) {
                    if (result.error === 'Account not verified') {
                        throw new Error('Your email address has not been verified yet. Please use the verification link sent to you by email.');
                    }
                    throw new Error(result.error || 'Unable to sign in.');
                }
                sessionStorage.setItem(TOKEN_KEY, result.access_token);
                sessionStorage.setItem(USER_KEY, result.account_name || 'Overte user');
                sessionStorage.setItem(ACCOUNT_KEY, result.account_id || '');
                sessionStorage.setItem(ROLES_KEY, JSON.stringify(result.account_roles || []));
                continueToDashboard(result.account_roles || []);
            } catch (error) {
                showMessage(error.message, 'error');
            } finally {
                submit.disabled = false;
                submit.textContent = 'Sign in';
            }
        });
    }

    const signOutButton = document.getElementById('sign-out-button');
    if (signOutButton) {
        signOutButton.addEventListener('click', () => {
            clearSession();
            window.location.replace('../login/');
        });
    }

    const params = new URLSearchParams(window.location.search);
    if (params.get('registered') === '1') {
        showMessage('Your account has been created. You can now sign in.', 'success');
    } else if (params.get('registered') === 'verification') {
        showMessage('Your account has been created. Please verify your email address before signing in.', 'success');
    } else if (params.get('registered') === 'verification-failed') {
        showMessage('Your account was created, but the verification email could not be sent. Please use the request-another-email section below. If the problem continues, contact the server administrator.', 'error');
    }

    restoreSession();
})();
