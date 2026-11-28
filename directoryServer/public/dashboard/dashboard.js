(() => {
    'use strict';

    const API = '../api/v1';
    const TOKEN_KEY = 'overteDashboardToken';
    const USER_KEY = 'overteDashboardUser';
    const ACCOUNT_KEY = 'overteDashboardAccountId';
    let token = sessionStorage.getItem(TOKEN_KEY) || '';
    let currentAdminId = sessionStorage.getItem(ACCOUNT_KEY) || '';
    let currentSection = 'overview';
    let editing = null;
    let cache = { accounts: [], domains: [], places: [] };

    const byId = (id) => document.getElementById(id);
    const dateText = (value) => {
        if (!value) return '—';
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? '—' : date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    };
    const numberText = (value) => Number(value || 0).toLocaleString();
    const idPath = (value) => encodeURIComponent(String(value));

    async function request(path, options = {}) {
        const headers = Object.assign({ 'Accept': 'application/json' }, options.headers || {});
        if (token) headers.Authorization = 'Bearer ' + token;
        if (options.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
        const response = await fetch(path, Object.assign({}, options, { headers }));
        let data;
        try { data = await response.json(); } catch (_) { throw new Error('The server returned an invalid response.'); }
        if (!response.ok || data.status === 'failure' || data.error) {
            throw new Error(data.error || data.message || ('Request failed (' + response.status + ').'));
        }
        return data.data || data;
    }

    function showMessage(message) {
        byId('globalMessage').textContent = message;
        byId('globalMessage').classList.remove('hidden');
    }

    function showLogin(message = '') {
        byId('loginView').classList.remove('hidden');
        byId('appView').classList.add('hidden');
        byId('loginMessage').textContent = message;
    }

    function showApp(username) {
        byId('loginView').classList.add('hidden');
        byId('appView').classList.remove('hidden');
        byId('signedInAs').textContent = 'Signed in as ' + username;
    }

    async function login(event) {
        event.preventDefault();
        const button = byId('loginForm').querySelector('button');
        button.disabled = true;
        byId('loginMessage').textContent = 'Signing in…';
        try {
            const body = new URLSearchParams({
                grant_type: 'password',
                scope: 'owner',
                username: byId('username').value.trim(),
                password: byId('password').value
            });
            const response = await fetch('../oauth/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
                body: body.toString()
            });
            const data = await response.json();
            if (!response.ok || data.error) throw new Error(data.error || 'Unable to sign in.');
            if (!Array.isArray(data.account_roles) || !data.account_roles.includes('admin')) {
                throw new Error('This account does not have administrator privileges.');
            }
            token = data.access_token;
            currentAdminId = data.account_id || '';
            sessionStorage.setItem(TOKEN_KEY, token);
            sessionStorage.setItem(USER_KEY, data.account_name || 'Administrator');
            sessionStorage.setItem(ACCOUNT_KEY, currentAdminId);
            await loadOverview();
            showApp(data.account_name || 'Administrator');
        } catch (error) {
            clearSession();
            showLogin(error.message);
        } finally {
            button.disabled = false;
        }
    }

    function clearSession() {
        token = '';
        currentAdminId = '';
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.removeItem(USER_KEY);
        sessionStorage.removeItem(ACCOUNT_KEY);
        sessionStorage.removeItem('overteAccountToken');
        sessionStorage.removeItem('overteAccountUser');
        sessionStorage.removeItem('overteAccountId');
        sessionStorage.removeItem('overteAccountRoles');
        cache = { accounts: [], domains: [], places: [] };
    }

    function logout() {
        clearSession();
        showLogin();
    }

    async function loadOverview() {
        const data = await request(API + '/admin/dashboard');
        const counts = data.counts || {};
        const server = data.server || {};
        byId('serverName').textContent = server.name || 'Overte';
        byId('serverMeta').textContent = 'Administration overview';
        byId('serverTime').textContent = 'Updated ' + new Date().toLocaleTimeString();
        byId('statAccounts').textContent = numberText(counts.accounts);
        byId('statOnline').textContent = numberText(counts.online_accounts) + ' online';
        byId('statDomains').textContent = numberText(counts.domains);
        byId('statActiveDomains').textContent = numberText(counts.active_domains) + ' active';
        byId('statPlaces').textContent = numberText(counts.places);
        byId('statUsers').textContent = numberText(counts.reported_users);
        byId('statTokens').textContent = numberText(counts.tokens);
        byId('statRequests').textContent = numberText(counts.pending_requests);
        const verified = Number(counts.verified_accounts || 0);
        const total = Number(counts.accounts || 0);
        const percentage = total ? Math.round((verified / total) * 100) : 0;
        byId('verifiedNumber').textContent = percentage + '%';
        byId('verifiedBar').style.width = percentage + '%';
        byId('verifiedCaption').textContent = numberText(verified) + ' of ' + numberText(total) + ' accounts verified or not requiring verification';
        byId('phpVersion').textContent = server.php_version || '—';
        const version = server.version || {};
        byId('serverVersion').textContent = [version.major, version.minor, version.patch].filter(v => v !== undefined).join('.') || '—';
        byId('utcTime').textContent = server.server_time ? new Date(server.server_time).toISOString().replace('T', ' ').replace('.000Z', ' UTC') : '—';
    }

    async function loadIceStatus() {
        const status = await request(API + '/admin/ice/status');
        const pill = byId('iceStatusPill');
        byId('iceConfiguredUrl').textContent = status.control_url || 'Not configured';
        byId('iceDirectoryId').textContent = status.directory_id || '—';
        byId('iceRegisteredUrl').textContent = status.registered_control_url || (status.legacy_record ? 'Existing registration (endpoint not recorded)' : '—');
        byId('iceDomainCount').textContent = numberText(status.domain_count);
        byId('iceNotice').textContent = status.message || (
            !status.configured ? 'ICE configuration is incomplete. Check the ICE URL, certificate and Directory ID in local.php.' :
            status.configuration_changed ? 'The configured ICE endpoint differs from the endpoint used for the saved registration. Switching servers is not available yet; do not enroll again until the old registration can be safely released.' :
            status.registered ? 'This Directory Server has a saved registration with the configured ICE server.' :
            'This Directory Server is not registered with the configured ICE server.'
        );
        pill.textContent = !status.configured ? 'Not configured' : (status.configuration_changed ? 'Endpoint changed' : (status.registered ? 'Registered' : 'Not registered'));
        pill.className = 'pill' + (status.registered && !status.configuration_changed ? ' good' : ' warn');
        byId('iceEnrollButton').disabled = !status.configured || status.registered;
        byId('iceRecoverButton').disabled = !status.configured;
        byId('iceSyncButton').disabled = !status.configured || !status.registered || status.configuration_changed || status.legacy_record;
        byId('iceDisconnectButton').disabled = !status.configured || !status.registered || status.configuration_changed || status.legacy_record;
        if (status.legacy_record) {
            byId('iceNotice').textContent = 'A previous registration token exists, but its ICE endpoint was not recorded. Recovering or switching requires care; the next ICE administration stage will handle this safely.';
            byId('iceSyncButton').disabled = true;
            byId('iceDisconnectButton').disabled = true;
        }
    }

    async function runIceAction(action, buttonId, successMessage, includeSecret = false) {
        const button = byId(buttonId);
        button.disabled = true;
        const original = button.textContent;
        button.textContent = 'Working…';
        try {
            const body = includeSecret ? { enrollment_secret: byId('iceEnrollmentSecret').value } : {};
            const result = await request(API + '/admin/ice/' + action, { method: 'POST', body: JSON.stringify(body) });
            byId('iceEnrollmentSecret').value = '';
            const affected = result.domain_count ?? result.released_domain_count;
            showMessage(successMessage + (affected === undefined ? '' : ' ' + numberText(affected) + ' domain(s).'));
            await loadIceStatus();
        } catch (error) {
            showMessage(error.message);
        } finally {
            if (includeSecret) byId('iceEnrollmentSecret').value = '';
            button.textContent = original;
            try { await loadIceStatus(); } catch (_) { button.disabled = false; }
        }
    }

    async function loadAccounts() {
        const data = await request(API + '/accounts?asAdmin=true&page=1&per_page=100');
        cache.accounts = data.accounts || [];
        renderAccounts();
        byId('accountsFooter').textContent = numberText(data.total_entries ?? cache.accounts.length) + ' accounts';
    }

    async function loadDomains() {
        const data = await request(API + '/admin/domains?page=0&per_page=100');
        cache.domains = data.domains || [];
        renderDomains();
        byId('domainsFooter').textContent = numberText(data.pagination?.total ?? cache.domains.length) + ' domains';
    }

    async function loadPlaces() {
        const data = await request(API + '/admin/places?page=1&per_page=100');
        cache.places = data.places || [];
        renderPlaces();
        byId('placesFooter').textContent = numberText(data.total_entries ?? cache.places.length) + ' places';
    }

    function cell(row, value) {
        const td = document.createElement('td');
        td.textContent = String(value ?? '');
        row.appendChild(td);
        return td;
    }

    function pill(parent, label, good = false, warn = false) {
        const span = document.createElement('span');
        span.className = 'pill' + (good ? ' good' : '') + (warn ? ' warn' : '');
        span.textContent = label;
        parent.appendChild(span);
    }

    function placeThumbnail(value, className = 'place-thumbnail') {
        const image = document.createElement('img');
        image.className = className;
        image.alt = '';
        image.loading = 'lazy';
        if (value && /^(https?:|\/|data:image\/)/i.test(String(value))) {
            image.src = String(value);
            image.addEventListener('error', () => { image.hidden = true; });
        } else {
            image.hidden = true;
        }
        return image;
    }

    function actionButton(parent, label, callback, danger = false) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = danger ? 'table-action danger' : 'table-action';
        button.textContent = label;
        button.addEventListener('click', callback);
        parent.appendChild(button);
    }

    function renderAccounts() {
        const body = byId('accountsBody');
        body.replaceChildren();
        const query = byId('accountSearch').value.trim().toLowerCase();
        const rows = cache.accounts.filter(item => [item.username, item.email].some(value => String(value || '').toLowerCase().includes(query)));
        if (!rows.length) { const tr = body.insertRow(); const td = tr.insertCell(); td.colSpan = 6; td.className = 'empty'; td.textContent = 'No matching accounts.'; return; }
        rows.forEach(item => {
            const tr = body.insertRow();
            cell(tr, item.username);
            cell(tr, item.email);
            const status = tr.insertCell();
            pill(status, item.location?.online ? 'Online' : (item.enabled ? 'Offline' : 'Unverified'), !!item.location?.online, !item.enabled);
            const role = tr.insertCell();
            pill(role, item.administrator ? 'Administrator' : 'User', !!item.administrator);
            cell(tr, dateText(item.when_account_created));
            const actions = tr.insertCell();
            actions.className = 'actions-cell';
            actionButton(actions, 'Edit', () => openEditor('account', item));
            actionButton(actions, 'Tokens', () => openTokens(item));
            if (item.accountId !== currentAdminId) actionButton(actions, 'Delete', () => deleteAccount(item), true);
        });
    }

    function renderDomains() {
        const body = byId('domainsBody');
        body.replaceChildren();
        const query = byId('domainSearch').value.trim().toLowerCase();
        const rows = cache.domains.filter(item => [item.name, item.network_address].some(value => String(value || '').toLowerCase().includes(query)));
        if (!rows.length) { const tr = body.insertRow(); const td = tr.insertCell(); td.colSpan = 7; td.className = 'empty'; td.textContent = 'No matching domains.'; return; }
        rows.forEach(item => {
            const tr = body.insertRow();
            const nameCell = tr.insertCell();
            const nameButton = document.createElement('button');
            nameButton.type = 'button';
            nameButton.className = 'domain-name-button';
            nameButton.textContent = item.name || 'Unnamed domain';
            nameButton.addEventListener('click', () => openDomainDetails(item));
            nameCell.appendChild(nameButton);
            cell(tr, item.network_address || '—');
            cell(tr, item.version || '—');
            cell(tr, numberText(item.num_users));
            cell(tr, item.visibility || 'open');
            cell(tr, dateText(item.when_domain_entry_created));
            const actions = tr.insertCell();
            actions.className = 'actions-cell';
            actionButton(actions, 'Edit', () => openEditor('domain', item));
            actionButton(actions, 'Delete', () => deleteDomain(item), true);
        });
    }

    function openDomainDetails(domain) {
        const content = byId('domainDetailsFields');
        content.replaceChildren();
        const rows = [
            ['Domain Name', domain.name || '—'],
            ['Users', numberText(domain.num_users)],
            ['ICE Server', domain.ice_server_address || '—'],
            ['Domain ID', domain.domainId || domain.id || '—'],
            ['Owner Account ID', domain.sponsor_account_id || '—'],
            ['Protocol', domain.protocol_version || '—'],
            ['Version', domain.version || '—']
        ];
        rows.forEach(([label, value]) => {
            const wrapper = document.createElement('div');
            wrapper.className = 'domain-detail-row';
            const term = document.createElement('dt');
            term.textContent = label;
            const description = document.createElement('dd');
            description.textContent = value;
            wrapper.append(term, description);
            content.appendChild(wrapper);
        });
        const keyDetails = document.createElement('details');
        keyDetails.className = 'domain-public-key';
        const summary = document.createElement('summary');
        summary.textContent = 'Public Key';
        const key = document.createElement('pre');
        key.textContent = domain.public_key || 'No public key registered';
        keyDetails.append(summary, key);
        content.appendChild(keyDetails);
        byId('domainDetailsTitle').textContent = domain.name || 'Domain details';
        byId('domainDetailsDialog').showModal();
    }

    function renderPlaces() {
        const body = byId('placesBody');
        body.replaceChildren();
        const query = byId('placeSearch').value.trim().toLowerCase();
        const rows = cache.places.filter(item => [item.name, item.domain?.name, item.user_name].some(value => String(value || '').toLowerCase().includes(query)));
        if (!rows.length) { const tr = body.insertRow(); const td = tr.insertCell(); td.colSpan = 6; td.className = 'empty'; td.textContent = 'No matching places.'; return; }
        rows.forEach(item => {
            const tr = body.insertRow();
            const thumb = tr.insertCell();
            thumb.appendChild(placeThumbnail(item.thumbnail));
            const name = tr.insertCell();
            const link = document.createElement('button');
            link.type = 'button';
            link.className = 'place-name-button';
            link.textContent = item.displayName || item.name || 'Unnamed place';
            link.addEventListener('click', () => openPlaceDetails(item));
            name.appendChild(link);
            cell(tr, item.maturity || 'unrated');
            cell(tr, item.domain?.name || '—');
            cell(tr, item.user_name || '—');
            const actions = tr.insertCell();
            actions.className = 'actions-cell';
            actionButton(actions, 'Delete', () => deletePlace(item), true);
        });
    }

    function openPlaceDetails(place) {
        const content = byId('placeDetailsFields');
        content.replaceChildren();
        const header = document.createElement('div');
        header.className = 'place-detail-header';
        header.appendChild(placeThumbnail(place.thumbnail, 'place-detail-thumbnail'));
        const title = document.createElement('div');
        title.className = 'place-detail-title';
        const name = document.createElement('h3');
        name.textContent = place.displayName || place.name || 'Unnamed place';
        const users = document.createElement('strong');
        users.textContent = numberText(place.current_attendance) + ' users';
        title.append(name, users);
        header.appendChild(title);
        content.appendChild(header);
        const rows = [
            ['Description', place.description || '—'],
            ['Tags', Array.isArray(place.tags) && place.tags.length ? place.tags.join(', ') : 'No tags found.'],
            ['Maturity', place.maturity || 'unrated'],
            ['Address', place.address || place.path || '—']
        ];
        rows.forEach(([label, value]) => {
            const wrapper = document.createElement('div');
            wrapper.className = 'place-detail-row';
            const term = document.createElement('dt');
            term.textContent = label;
            const description = document.createElement('dd');
            description.textContent = value;
            wrapper.append(term, description);
            content.appendChild(wrapper);
        });
        const domainDetails = document.createElement('details');
        domainDetails.className = 'place-domain-details';
        const summary = document.createElement('summary');
        summary.textContent = 'Domain';
        domainDetails.appendChild(summary);
        const domain = place.domain || {};
        [
            ['Domain ID', domain.domainId || domain.id || '—'],
            ['Domain Name', domain.name || '—'],
            ['Domain Network Address', [domain.network_address || '', domain.network_port || ''].filter(Boolean).join(':') || '—'],
            ['Domain ICE Server', domain.ice_server_address || '—'],
            ['Domain Last Checked In', domain.time_of_last_heartbeat || '—']
        ].forEach(([label, value]) => {
            const wrapper = document.createElement('div');
            wrapper.className = 'place-domain-row';
            const term = document.createElement('dt');
            term.textContent = label;
            const description = document.createElement('dd');
            description.textContent = value;
            wrapper.append(term, description);
            domainDetails.appendChild(wrapper);
        });
        content.appendChild(domainDetails);
        byId('placeDetailsTitle').textContent = place.displayName || place.name || 'Place details';
        byId('placeDetailsDialog').showModal();
    }

    function field(label, key, value, type = 'text', options = null, disabled = false, note = '') {
        return { label, key, value, type, options, disabled, note };
    }

    function editorFields(type, item) {
        if (type === 'create-domain') {
            return [
                field('Domain name', 'label', '', 'text', null, false, 'Use letters, numbers, dots, hyphens or underscores. Your admin account will sponsor this domain; an initial Place is created automatically.'),
                field('Network address (optional)', 'network_address', ''),
                field('Network port (optional)', 'network_port', '', 'number')
            ];
        }
        if (type === 'create-place') {
            return [
                field('Domain', 'domainId', cache.domains[0]?.id || '', 'select', cache.domains.map(domain => ({ value: domain.id, label: domain.name }))),
                field('Place name', 'name', ''),
                field('Display name', 'displayName', ''),
                field('Description', 'description', '', 'textarea'),
                field('Virtual address', 'address', '/0,0,0/0,0,0,1', 'text', null, false, 'Format: /x,y,z/x,y,z,w. The default places the bookmark at the domain origin.')
            ];
        }
        if (type === 'account') {
            const adminCount = cache.accounts.filter(account => account.administrator).length;
            const cannotChangeRole = item.accountId === currentAdminId || (item.administrator && adminCount <= 1);
            return [
                field('Email address', 'email', item.email || '', 'email'),
                field('New password (optional)', 'password', '', 'password'),
                field('Administrator privileges', 'administrator', !!item.administrator, 'checkbox', null, cannotChangeRole)
            ];
        }
        if (type === 'domain') {
            return [
                field('Domain name', 'name', item.name || ''),
                field('Description', 'description', item.description || '', 'textarea'),
                field('Visibility', 'visibility', item.visibility || 'open', 'select', ['open', 'friends', 'connections', 'group', 'private']),
                field('Maturity', 'maturity', item.maturity || 'unrated', 'select', ['unrated', 'everyone', 'teen', 'mature', 'adult']),
                field('Capacity', 'capacity', item.capacity || 0, 'number'),
                field('Restriction', 'restriction', item.restriction || 'open', 'select', ['open', 'hifi', 'acl'])
            ];
        }
        return [
            field('Place name', 'name', item.name || ''),
            field('Display name', 'displayName', item.displayName || item.name || ''),
            field('Description', 'description', item.description || '', 'textarea'),
            field('Visibility', 'visibility', item.visibility || 'open', 'select', ['open', 'friends', 'connections', 'private']),
            field('Maturity', 'maturity', item.maturity || 'unrated', 'select', ['unrated', 'everyone', 'teen', 'mature', 'adult']),
            field('Virtual path', 'path', item.path || '/0,0,0/0,0,0,1')
        ];
    }

    function buildEditorField(container, definition) {
        const wrapper = document.createElement('label');
        wrapper.className = 'editor-field' + (definition.type === 'checkbox' ? ' checkbox-field' : '');
        const caption = document.createElement('span');
        caption.textContent = definition.label;
        wrapper.appendChild(caption);
        let input;
        if (definition.type === 'textarea') {
            input = document.createElement('textarea');
            input.rows = 3;
            input.value = String(definition.value ?? '');
        } else if (definition.type === 'select') {
            input = document.createElement('select');
            definition.options.forEach(option => {
                const element = document.createElement('option');
                element.value = typeof option === 'object' ? option.value : option;
                element.textContent = typeof option === 'object' ? option.label : option;
                input.appendChild(element);
            });
            input.value = String(definition.value ?? '');
        } else {
            input = document.createElement('input');
            input.type = definition.type === 'checkbox' ? 'checkbox' : definition.type;
            if (definition.type === 'checkbox') input.checked = !!definition.value;
            else input.value = String(definition.value ?? '');
        }
        input.name = definition.key;
        input.dataset.field = definition.key;
        if (['email', 'name', 'label', 'address', 'domainId'].includes(definition.key)) input.required = true;
        if (definition.type === 'number') { input.min = '0'; if (definition.key === 'network_port') { input.min = '1'; input.max = '65535'; } }
        input.disabled = !!definition.disabled;
        wrapper.appendChild(input);
        if (definition.note) {
            const note = document.createElement('small');
            note.textContent = definition.note;
            wrapper.appendChild(note);
        }
        if (definition.disabled && definition.type === 'checkbox') {
            const note = document.createElement('small');
            note.textContent = 'This role cannot be changed here to avoid removing the last administrator or changing your own access.';
            wrapper.appendChild(note);
        }
        container.appendChild(wrapper);
    }

    function openEditor(type, item) {
        editing = { type, item };
        byId('recordTitle').textContent = type.startsWith('create-') ? (type === 'create-domain' ? 'Create domain' : 'Create place') : 'Edit ' + type;
        byId('recordError').textContent = '';
        const fields = byId('recordFields');
        fields.replaceChildren();
        editorFields(type, item || {}).forEach(definition => buildEditorField(fields, definition));
        byId('recordSave').classList.remove('hidden');
        byId('recordSave').disabled = false;
        byId('recordSave').textContent = type.startsWith('create-') ? 'Create' : 'Save changes';
        byId('recordCancelBottom').textContent = 'Cancel';
        byId('recordDialog').showModal();
    }

    function openCredentials(title, entries, note) {
        editing = null;
        byId('recordTitle').textContent = title;
        byId('recordError').textContent = '';
        const fields = byId('recordFields');
        fields.replaceChildren();
        if (note) {
            const description = document.createElement('p');
            description.className = 'credential-note';
            description.textContent = note;
            fields.appendChild(description);
        }
        entries.forEach(entry => {
            const wrapper = document.createElement('label');
            wrapper.className = 'editor-field';
            const caption = document.createElement('span');
            caption.textContent = entry.label;
            wrapper.appendChild(caption);
            const row = document.createElement('div');
            row.className = 'credential-row';
            const input = document.createElement('input');
            input.type = 'text';
            input.readOnly = true;
            input.value = String(entry.value ?? '');
            input.className = 'credential-value';
            row.appendChild(input);
            if (entry.copy !== false && input.value) {
                const copy = document.createElement('button');
                copy.type = 'button';
                copy.className = 'secondary-button';
                copy.textContent = 'Copy';
                copy.addEventListener('click', async () => {
                    try {
                        await navigator.clipboard.writeText(input.value);
                        copy.textContent = 'Copied';
                    } catch (_) {
                        input.select();
                        const copied = document.execCommand('copy');
                        copy.textContent = copied ? 'Copied' : 'Select and copy';
                    }
                });
                row.appendChild(copy);
            }
            wrapper.appendChild(row);
            fields.appendChild(wrapper);
        });
        byId('recordSave').classList.add('hidden');
        byId('recordCancelBottom').textContent = 'Close';
        if (!byId('recordDialog').open) byId('recordDialog').showModal();
    }

    async function createDomain(values) {
        const domainInput = { label: values.label };
        if (values.network_address) domainInput.network_address = values.network_address;
        if (values.network_port) domainInput.network_port = values.network_port;
        const result = await request(API + '/domains', { method: 'POST', body: JSON.stringify({ domain: domainInput }) });
        const domain = result.domain || {};
        const place = result.place || {};
        let placeKey = '';
        const placeId = place.id || place.placeId;
        if (placeId) {
            try {
                const placeResult = await request(API + '/places/' + idPath(placeId));
                placeKey = placeResult.place?.current_api_key || '';
            } catch (_) {
                // Creation already succeeded; do not report a false failure if key lookup fails.
            }
        }
        await activateSection('domains');
        await loadOverview();
        const entries = [
            { label: 'Domain name', value: domain.name || values.label, copy: false },
            { label: 'Domain ID', value: domain.id || domain.domainId || '', copy: false },
            { label: 'Domain API key', value: domain.api_key || '' },
            { label: 'Initial place', value: place.name || '', copy: false },
            { label: 'Initial place ID', value: placeId || '', copy: false }
        ];
        if (placeKey) entries.push({ label: 'Initial place activity API key', value: placeKey });
        openCredentials('Domain created', entries, placeKey ? 'Copy the domain API key now; it is only returned at creation. The domain server uses it to authenticate. The Place activity key is used by scripts that update this Place and can be retrieved later.' : 'The domain and initial Place were created. The domain API key is shown below. The Place activity key can be retrieved from the Place details.');
    }

    async function createPlace(values) {
        const result = await request(API + '/user/places', {
            method: 'POST',
            body: JSON.stringify({ place: {
                domainId: values.domainId,
                name: values.name,
                displayName: values.displayName || values.name,
                description: values.description || '',
                address: values.address
            } })
        });
        const place = result.place || {};
        await activateSection('places');
        await loadOverview();
        openCredentials('Place created', [
            { label: 'Place name', value: place.name || values.name, copy: false },
            { label: 'Place ID', value: place.id || place.placeId || '', copy: false },
            { label: 'Place activity API key', value: place.current_api_key || '' }
        ], 'Keep the activity API key somewhere safe. Scripts can use it to update this Place\'s current attendance and information.');
    }

    async function saveEditor(event) {
        event.preventDefault();
        if (!editing) return;
        const save = byId('recordSave');
        save.disabled = true;
        save.textContent = 'Saving…';
        byId('recordError').textContent = '';
        const { type, item } = editing;
        try {
            const inputs = Array.from(byId('recordFields').querySelectorAll('[data-field]'));
            const values = {};
            inputs.forEach(input => {
                if (input.disabled) return;
                values[input.dataset.field] = input.type === 'checkbox' ? input.checked : (input.type === 'number' ? Number(input.value) : input.value.trim());
            });
            if (type === 'create-domain') {
                if (values.network_port && (values.network_port < 1 || values.network_port > 65535)) throw new Error('Network port must be between 1 and 65535.');
                await createDomain(values);
                return;
            } else if (type === 'create-place') {
                await createPlace(values);
                return;
            } else if (type === 'account') {
                if (values.email !== item.email) {
                    await request(API + '/account/' + idPath(item.accountId) + '/field/email', { method: 'POST', body: JSON.stringify({ set: values.email }) });
                }
                if (values.password) {
                    await request(API + '/account/' + idPath(item.accountId) + '/field/password', { method: 'POST', body: JSON.stringify({ set: values.password }) });
                }
                if (Object.prototype.hasOwnProperty.call(values, 'administrator') && values.administrator !== item.administrator) {
                    const roles = values.administrator ? ['user', 'admin'] : ['user'];
                    await request(API + '/account/' + idPath(item.accountId) + '/field/roles', { method: 'POST', body: JSON.stringify({ set: roles }) });
                }
            } else {
                const base = type === 'domain' ? '/domains/' + idPath(item.id || item.domainId) + '/field/' : '/places/' + idPath(item.id || item.placeId) + '/field/';
                for (const [key, value] of Object.entries(values)) {
                    if (String(value) === String(item[key] ?? (key === 'capacity' ? 0 : ''))) continue;
                    await request(API + base + key, { method: 'POST', body: JSON.stringify({ set: value }) });
                }
            }
            byId('recordDialog').close();
            await activateSection(currentSection);
        } catch (error) {
            byId('recordError').textContent = error.message;
        } finally {
            save.disabled = false;
            save.textContent = 'Save changes';
        }
    }

    async function deleteAccount(item) {
        if (item.accountId === currentAdminId) return;
        const adminCount = cache.accounts.filter(account => account.administrator).length;
        if (item.administrator && adminCount <= 1) {
            showMessage('The last administrator account cannot be deleted from the dashboard.');
            return;
        }
        const warning = 'Permanently delete account "' + item.username + '"? This also removes its access tokens, sponsored domains and their places, owned places, pending requests, and relationship references.';
        if (!window.confirm(warning)) return;
        try {
            await request(API + '/account/' + idPath(item.accountId), { method: 'DELETE' });
            await activateSection('accounts');
            await loadOverview();
        } catch (error) { showMessage(error.message); }
    }

    async function deleteDomain(item) {
        const warning = 'Delete domain "' + item.name + '"? The existing API leaves its registered places in the directory, so those places will no longer have an associated domain.';
        if (!window.confirm(warning)) return;
        try {
            await request(API + '/domains/' + idPath(item.id || item.domainId), { method: 'DELETE' });
            await activateSection('domains');
            await loadOverview();
        } catch (error) { showMessage(error.message); }
    }

    async function deletePlace(item) {
        if (!window.confirm('Permanently delete place "' + item.name + '" and its place access token?')) return;
        try {
            await request(API + '/places/' + idPath(item.id || item.placeId), { method: 'DELETE' });
            await activateSection('places');
            await loadOverview();
        } catch (error) { showMessage(error.message); }
    }

    async function openTokens(account) {
        byId('recordTitle').textContent = 'Access tokens — ' + account.username;
        byId('recordError').textContent = '';
        const fields = byId('recordFields');
        fields.replaceChildren();
        const loading = document.createElement('p');
        loading.className = 'muted';
        loading.textContent = 'Loading tokens…';
        fields.appendChild(loading);
        byId('recordSave').classList.add('hidden');
        if (!byId('recordDialog').open) byId('recordDialog').showModal();
        try {
            const data = await request(API + '/account/' + idPath(account.accountId) + '/tokens?page=1&per_page=100');
            fields.replaceChildren();
            const tokens = data.tokens || [];
            if (tokens.length) {
                const revokeAll = document.createElement('div');
                revokeAll.className = 'token-row';
                const revokeAllDetails = document.createElement('div');
                const revokeAllTitle = document.createElement('strong');
                revokeAllTitle.textContent = 'Revoke every token';
                const revokeAllNote = document.createElement('small');
                revokeAllNote.textContent = account.accountId === currentAdminId
                    ? 'This includes your current dashboard session; you will be signed out.'
                    : 'Every client using this account will need to sign in or obtain a new token.';
                revokeAllDetails.append(revokeAllTitle, revokeAllNote);
                revokeAll.appendChild(revokeAllDetails);
                actionButton(revokeAll, 'Revoke all', async () => {
                    const isCurrentAccount = account.accountId === currentAdminId;
                    const warning = isCurrentAccount
                        ? 'Revoke ALL access tokens for your administrator account? This will also end your current dashboard session and sign you out.'
                        : 'Revoke ALL access tokens for "' + account.username + '"? Every client using this account will need a replacement token.';
                    if (!window.confirm(warning)) return;
                    try {
                        const result = await request(API + '/account/' + idPath(account.accountId) + '/tokens', { method: 'DELETE' });
                        if (isCurrentAccount) {
                            byId('recordDialog').close();
                            clearSession();
                            showLogin('All access tokens were revoked. Please sign in again.');
                        } else {
                            await openTokens(account);
                            await loadOverview();
                            byId('recordError').textContent = 'Revoked ' + numberText(result.revoked_count) + ' token(s).';
                        }
                    } catch (error) { byId('recordError').textContent = error.message; }
                }, true);
                fields.appendChild(revokeAll);
            }
            if (!tokens.length) {
                const empty = document.createElement('p');
                empty.className = 'muted';
                empty.textContent = 'This account has no access tokens.';
                fields.appendChild(empty);
            }
            tokens.forEach(item => {
                const row = document.createElement('div');
                row.className = 'token-row';
                const details = document.createElement('div');
                const scope = document.createElement('strong');
                scope.textContent = (item.scope || []).join(', ') || 'Unknown scope';
                const dates = document.createElement('small');
                dates.textContent = 'Created ' + dateText(item.creation_time) + ' · Expires ' + dateText(item.expiration_time);
                details.append(scope, dates);
                row.appendChild(details);
                actionButton(row, 'Revoke', async () => {
                    if (!window.confirm('Revoke this token? Any client using it will need a replacement token.')) return;
                    try {
                        await request(API + '/account/' + idPath(account.accountId) + '/tokens/' + idPath(item.tokenId), { method: 'DELETE' });
                        await openTokens(account);
                        await loadOverview();
                    } catch (error) { byId('recordError').textContent = error.message; }
                }, true);
                fields.appendChild(row);
            });
        } catch (error) {
            fields.replaceChildren();
            byId('recordError').textContent = error.message;
        }
    }

    async function activateSection(section) {
        currentSection = section;
        document.querySelectorAll('.nav-item').forEach(button => button.classList.toggle('active', button.dataset.section === section));
        document.querySelectorAll('.section-view').forEach(view => view.classList.toggle('hidden', view.id !== section + 'Section'));
        byId('pageTitle').textContent = section.charAt(0).toUpperCase() + section.slice(1);
        byId('globalMessage').classList.add('hidden');
        try {
            if (section === 'overview') await loadOverview();
            if (section === 'accounts') await loadAccounts();
            if (section === 'domains') await loadDomains();
            if (section === 'places') await loadPlaces();
            if (section === 'ice') await loadIceStatus();
        } catch (error) {
            if (/not logged in|unauthorized|administrator/i.test(error.message)) logout();
            else showMessage(error.message);
        }
    }

    byId('loginForm').addEventListener('submit', login);
    byId('logoutButton').addEventListener('click', logout);
    byId('refreshButton').addEventListener('click', () => activateSection(currentSection));
    document.querySelectorAll('.nav-item').forEach(button => button.addEventListener('click', () => activateSection(button.dataset.section)));
    byId('accountSearch').addEventListener('input', renderAccounts);
    byId('domainSearch').addEventListener('input', renderDomains);
    byId('placeSearch').addEventListener('input', renderPlaces);
    byId('iceEnrollButton').addEventListener('click', () => {
        if (!byId('iceEnrollmentSecret').value.trim()) { showMessage('Enter the ICE enrollment secret first.'); return; }
        if (window.confirm('Register this Directory Server with the configured ICE server?')) runIceAction('enroll', 'iceEnrollButton', 'ICE enrollment succeeded.', true);
    });
    byId('iceRecoverButton').addEventListener('click', () => {
        if (!byId('iceEnrollmentSecret').value.trim()) { showMessage('Enter the ICE enrollment secret first.'); return; }
        if (window.confirm('Recover the registration token? This invalidates the previous token on the configured ICE server.')) runIceAction('recover', 'iceRecoverButton', 'ICE registration token recovered.', true);
    });
    byId('iceSyncButton').addEventListener('click', () => runIceAction('sync', 'iceSyncButton', 'ICE domain list synchronized.'));
    byId('iceDisconnectButton').addEventListener('click', () => {
        if (window.confirm('Disconnect this Directory Server from the configured ICE server? The ICE server will revoke this registration token, release all its domain UUIDs, and remove its active peers. You must do this BEFORE changing ice_control_url.')) {
            runIceAction('disconnect', 'iceDisconnectButton', 'Directory Server disconnected from ICE.');
        }
    });
    byId('createDomainButton').addEventListener('click', () => openEditor('create-domain', {}));
    byId('createPlaceButton').addEventListener('click', async () => {
        try {
            if (!cache.domains.length) await loadDomains();
            if (!cache.domains.length) { showMessage('Create a domain before creating an additional place.'); return; }
            openEditor('create-place', {});
        } catch (error) {
            showMessage(error.message);
        }
    });
    byId('placeDetailsClose').addEventListener('click', () => byId('placeDetailsDialog').close());
    byId('placeDetailsCloseBottom').addEventListener('click', () => byId('placeDetailsDialog').close());
    byId('domainDetailsClose').addEventListener('click', () => byId('domainDetailsDialog').close());
    byId('domainDetailsCloseBottom').addEventListener('click', () => byId('domainDetailsDialog').close());
    byId('recordForm').addEventListener('submit', saveEditor);
    byId('recordCancel').addEventListener('click', () => byId('recordDialog').close());
    byId('recordCancelBottom').addEventListener('click', () => byId('recordDialog').close());
    byId('recordDialog').addEventListener('close', () => {
        editing = null;
        byId('recordSave').classList.remove('hidden');
        byId('recordCancelBottom').textContent = 'Close';
    });

    if (token && !currentAdminId) clearSession();
    if (token) {
        loadOverview().then(() => showApp(sessionStorage.getItem(USER_KEY) || 'Administrator')).catch(() => logout());
    } else {
        showLogin();
    }
})();
