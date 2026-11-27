(() => {
    'use strict';

    const TOKEN_KEY = 'overteAccountToken';
    const token = sessionStorage.getItem(TOKEN_KEY) || '';
    const accountId = sessionStorage.getItem('overteAccountId') || '';
    const status = document.getElementById('status');
    let latestGeneratedToken = '';

    function setStatus(message, type) {
        status.textContent = message;
        status.className = 'status' + (type ? ' ' + type : '');
    }

    function showInline(elementId, message, type) {
        const element = document.getElementById(elementId);
        element.textContent = message;
        element.className = 'inline-message' + (type ? ' ' + type : '');
        element.hidden = false;
    }

    function fail(message) {
        setStatus(message + ' Redirecting to sign in…', 'error');
        window.setTimeout(() => window.location.replace('../login/'), 1800);
    }

    async function request(path, options = {}) {
        const headers = Object.assign({
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + token
        }, options.headers || {});
        const response = await fetch(path, Object.assign({}, options, { headers }));
        let result;
        try { result = await response.json(); } catch (_) { throw new Error('The server returned an invalid response.'); }
        if (!response.ok || result.status !== 'success') {
            throw new Error(result.error || 'The request could not be completed.');
        }
        return result.data || {};
    }

    function formatDate(value) {
        if (!value) return 'Not yet reported';
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? 'Not yet reported' : date.toLocaleString();
    }

    function makeText(tag, className, value) {
        const element = document.createElement(tag);
        if (className) element.className = className;
        element.textContent = value;
        return element;
    }

    function openDomainDetails(domain) {
        const dialog = document.getElementById('domain-details-dialog');
        const title = document.getElementById('domain-details-title');
        const content = document.getElementById('domain-details-fields');
        title.textContent = domain.name || 'Domain details';
        content.textContent = '';
        const rows = [
            ['Domain Name', domain.name || '—'],
            ['Users', String(domain.num_users ?? 0)],
            ['ICE Server', domain.ice_server_address || '—'],
            ['Domain ID', domain.domainId || domain.id || '—'],
            ['Owner Account ID', domain.sponsor_account_id || '—'],
            ['Protocol', domain.protocol_version || '—'],
            ['Version', domain.version || '—']
        ];
        rows.forEach(([label, value]) => {
            const wrapper = document.createElement('div');
            wrapper.className = 'domain-detail-row';
            wrapper.append(makeText('dt', '', label), makeText('dd', '', value));
            content.appendChild(wrapper);
        });
        const keyDetails = document.createElement('details');
        keyDetails.className = 'domain-public-key';
        keyDetails.appendChild(makeText('summary', '', 'Public Key'));
        const key = document.createElement('pre');
        key.textContent = domain.public_key || 'No public key registered';
        keyDetails.appendChild(key);
        content.appendChild(keyDetails);
        dialog.showModal();
    }

    async function loadDomains() {
        const data = await request('../api/v1/user/domains');
        const container = document.getElementById('domains');
        container.textContent = '';
        const domains = Array.isArray(data.domains) ? data.domains : [];
        if (!domains.length) {
            container.appendChild(makeText('p', 'muted', 'No domains have registered with this directory for your account yet.'));
            return;
        }
        domains.forEach((domain) => {
            const card = document.createElement('article');
            card.className = 'domain-card';
            const heading = document.createElement('div');
            heading.className = 'domain-heading';
            const openDetails = makeText('button', 'domain-open-button', domain.name || 'Unnamed domain');
            openDetails.type = 'button';
            openDetails.addEventListener('click', () => openDomainDetails(domain));
            heading.appendChild(openDetails);
            const hasHeartbeat = !!domain.time_of_last_heartbeat;
            const isOnline = domain.active === true;
            const stateClass = isOnline ? 'state online' : (hasHeartbeat ? 'state offline' : 'state awaiting');
            const stateLabel = isOnline ? 'Online' : (hasHeartbeat ? 'Offline' : 'Awaiting first heartbeat');
            heading.appendChild(makeText('span', stateClass, stateLabel));
            card.appendChild(heading);
            const details = document.createElement('dl');
            details.className = 'domain-details';
            const rows = [
                ['Version', domain.version || '—'],
                ['Users', String(domain.num_users ?? 0)],
                ['Network address', [domain.network_address || '', domain.network_port || ''].filter(Boolean).join(':') || 'Not configured'],
                ['Last heartbeat', formatDate(domain.time_of_last_heartbeat)]
            ];
            rows.forEach(([label, value]) => {
                const wrapper = document.createElement('div');
                wrapper.append(makeText('dt', '', label), makeText('dd', '', value));
                details.appendChild(wrapper);
            });
            card.appendChild(details);
            container.appendChild(card);
        });
    }

    async function loadTokens() {
        const data = await request('../api/v1/tokens?per_page=100');
        const container = document.getElementById('domain-tokens');
        container.textContent = '';
        const tokens = (Array.isArray(data.tokens) ? data.tokens : []).filter((item) =>
            Array.isArray(item.scope) && item.scope.includes('domain')
        );
        if (!tokens.length) {
            container.appendChild(makeText('p', 'muted', 'No domain access tokens have been generated for this account.'));
            return;
        }
        tokens.forEach((item) => {
            const card = document.createElement('article');
            card.className = 'token-card';
            const info = document.createElement('div');
            info.appendChild(makeText('strong', '', 'Domain access token'));
            info.appendChild(makeText('span', 'token-meta', 'Created ' + formatDate(item.creation_time) + ' · Expires ' + formatDate(item.expiration_time)));
            const revoke = document.createElement('button');
            revoke.type = 'button';
            revoke.className = 'danger-button';
            revoke.textContent = 'Revoke';
            revoke.addEventListener('click', async () => {
                if (!window.confirm('Revoke this domain access token? Any domain server using it will lose access.')) return;
                revoke.disabled = true;
                try {
                    await request('../api/v1/account/' + encodeURIComponent(accountId) + '/tokens/' + encodeURIComponent(item.tokenId || item.id), { method: 'DELETE' });
                    await loadTokens();
                    showInline('token-management-message', 'Domain access token revoked.', 'success');
                } catch (error) {
                    revoke.disabled = false;
                    showInline('token-management-message', error.message, 'error');
                }
            });
            card.append(info, revoke);
            container.appendChild(card);
        });
    }

    async function loadPlaces() {
        const data = await request('../api/v1/user/places');
        const container = document.getElementById('places');
        container.textContent = '';
        const places = Array.isArray(data.places) ? data.places : [];
        if (!places.length) {
            container.appendChild(makeText('p', 'muted', 'You do not have any places associated with your account yet.'));
            return;
        }
        places.forEach((place) => {
            const item = document.createElement('article');
            item.className = 'place';
            item.append(makeText('strong', '', place.displayName || place.name || 'Unnamed place'));
            item.append(makeText('span', '', [place.name, place.path || place.address || ''].filter(Boolean).join(' · ')));
            container.appendChild(item);
        });
    }

    async function load() {
        if (!token) { fail('You are not signed in.'); return; }
        try {
            const profile = await request('../api/v1/user/profile');
            const user = profile.user || {};
            document.getElementById('username').textContent = user.username || 'Overte user';
            document.getElementById('signed-in-as').textContent = user.username || '';
            document.getElementById('account-username').textContent = user.username || '—';
            document.getElementById('account-id').textContent = user.accountid || '—';
            document.getElementById('admin-link').hidden = !JSON.parse(sessionStorage.getItem('overteAccountRoles') || '[]').includes('admin');
            await Promise.all([loadDomains(), loadTokens(), loadPlaces()]);
            setStatus('You are signed in.');
        } catch (error) {
            fail(error.message);
        }
    }

    document.getElementById('generate-domain-token').addEventListener('click', async (event) => {
        const button = event.currentTarget;
        button.disabled = true;
        button.textContent = 'Generating…';
        try {
            const data = await request('../api/v1/token/new?scope=domain', { method: 'POST' });
            latestGeneratedToken = data.token || '';
            if (!latestGeneratedToken) throw new Error('The server did not return an access token.');
            document.getElementById('new-token-value').textContent = latestGeneratedToken;
            document.getElementById('new-token').hidden = false;
            await loadTokens();
        } catch (error) {
            showInline('token-copy-message', error.message, 'error');
        } finally {
            button.disabled = false;
            button.textContent = 'Generate domain access token';
        }
    });

    document.getElementById('copy-token').addEventListener('click', async () => {
        if (!latestGeneratedToken) return;
        try {
            await navigator.clipboard.writeText(latestGeneratedToken);
            showInline('token-copy-message', 'Token copied to clipboard.', 'success');
        } catch (_) {
            showInline('token-copy-message', 'Clipboard access is unavailable. Select and copy the token above.', 'error');
        }
    });

    document.getElementById('refresh-domains').addEventListener('click', async () => {
        const button = document.getElementById('refresh-domains');
        button.disabled = true;
        button.textContent = 'Refreshing…';
        try {
            await Promise.all([loadDomains(), loadPlaces()]);
        } catch (error) {
            setStatus(error.message, 'error');
        } finally {
            button.disabled = false;
            button.textContent = 'Refresh';
        }
    });

    // Domain registration and heartbeat happen in the Domain Server. Refresh
    // the account view periodically so a newly registered domain appears
    // without requiring the user to reload this page.
    window.setInterval(() => {
        loadDomains().catch(() => {});
        loadPlaces().catch(() => {});
    }, 30000);

    document.getElementById('domain-details-close').addEventListener('click', () => document.getElementById('domain-details-dialog').close());
    document.getElementById('domain-details-close-bottom').addEventListener('click', () => document.getElementById('domain-details-dialog').close());

    document.getElementById('sign-out').addEventListener('click', () => {
        [TOKEN_KEY, 'overteAccountUser', 'overteAccountId', 'overteAccountRoles',
            'overteDashboardToken', 'overteDashboardUser', 'overteDashboardAccountId'].forEach((key) => sessionStorage.removeItem(key));
        window.location.replace('../login/');
    });

    load();
})();
