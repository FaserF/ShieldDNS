let currentConfig = { upstreams: [], upstream_dot: [], prefer_encrypted: true, lists: [], allowlists: [], custom_blocked: [], custom_allowed: [] };
    let trafficChart = null;
    let typeChart = null;
    
    // UI Elements
    let authOverlay, setupView, loginView, listItemsContainer, allowlistItemsContainer, views;
    let upstreamsInput, dotUpstreamsInput, preferEncryptedCheck, customBlockedList, customAllowedList;
    let systemLogTerminal, certInfoContent, statsContainer, topBlockedContainer, topClientsContainer;
    let queryLogItems, fullQueryLogItems;
    let systemLogEventSource = null;
    let apiKeysListContainer, apiKeyModal, apiKeyForm, apiKeyResult, apiKeyValue, protectionStatusLabel, toggleProtectionBtn;
    let adminDomainInput, blockIpInput;

/**
 * Custom alternative to window.alert()
 */
async function showAlert(message, title = 'Notification') {
    return new Promise((resolve) => {
        const modal = document.getElementById('alert-modal');
        const titleEl = document.getElementById('alert-title');
        const messageEl = document.getElementById('alert-message');
        const okBtn = document.getElementById('alert-ok');

        titleEl.textContent = title;
        messageEl.textContent = message;
        modal.classList.remove('hidden');

        const cleanup = () => {
            modal.classList.add('hidden');
            okBtn.removeEventListener('click', handleOk);
            window.removeEventListener('keydown', handleKey);
            resolve();
        };

        const handleOk = () => cleanup();
        const handleKey = (e) => { if (e.key === 'Enter' || e.key === 'Escape') cleanup(); };

        okBtn.addEventListener('click', handleOk, { once: true });
        window.addEventListener('keydown', handleKey);
        okBtn.focus();
    });
}

/**
 * Custom alternative to window.confirm()
 */
async function showConfirm(message, title = 'Confirmation') {
    return new Promise((resolve) => {
        const modal = document.getElementById('confirm-modal');
        const titleEl = document.getElementById('confirm-title');
        const messageEl = document.getElementById('confirm-message');
        const yesBtn = document.getElementById('confirm-yes');
        const noBtn = document.getElementById('confirm-cancel');

        titleEl.textContent = title;
        messageEl.textContent = message;
        modal.classList.remove('hidden');

        const cleanup = (result) => {
            modal.classList.add('hidden');
            yesBtn.removeEventListener('click', handleYes);
            noBtn.removeEventListener('click', handleNo);
            window.removeEventListener('keydown', handleKey);
            resolve(result);
        };

        const handleYes = () => cleanup(true);
        const handleNo = () => cleanup(false);
        const handleKey = (e) => {
            if (e.key === 'Enter') cleanup(true);
            if (e.key === 'Escape') cleanup(false);
        };

        yesBtn.addEventListener('click', handleYes, { once: true });
        noBtn.addEventListener('click', handleNo, { once: true });
        window.addEventListener('keydown', handleKey);
        yesBtn.focus();
    });
}

document.addEventListener('DOMContentLoaded', () => {
    // Theme initialization
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.body.className = savedTheme;
    const themeToggleBtn = document.getElementById('theme-toggle');
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', () => {
            const isDark = document.body.classList.contains('dark');
            const newTheme = isDark ? 'light' : 'dark';
            document.body.className = newTheme;
            localStorage.setItem('theme', newTheme);
        });
    }

    const getEl = (id) => document.getElementById(id);
    // Initialize UI Elements
    authOverlay = getEl('auth-overlay');
    setupView = getEl('setup-view');
    loginView = getEl('login-view');
    listItemsContainer = getEl('list-items');
    allowlistItemsContainer = getEl('allowlist-items');
    views = document.querySelectorAll('.view');
    upstreamsInput = getEl('upstreams-input');
    dotUpstreamsInput = getEl('dot-upstreams-input');
    preferEncryptedCheck = getEl('prefer-encrypted-check');
    customBlockedList = getEl('custom-blocked-list');
    customAllowedList = getEl('custom-allowed-list');
    systemLogTerminal = getEl('system-log-terminal');
    certInfoContent = getEl('cert-info-content');
    topBlockedContainer = getEl('top-blocked-list');
    topClientsContainer = getEl('top-clients-list');
    queryLogItems = getEl('query-log-items');
    fullQueryLogItems = getEl('full-query-log-items');

    statsContainer = {
        total: getEl('stat-total'),
        blocked: getEl('stat-blocked'),
        ratio: getEl('stat-ratio'),
        cache: getEl('stat-cache'),
        latency: getEl('stat-latency'),
        clients: getEl('stat-clients')
    };

    apiKeysListContainer = getEl('api-keys-list');
    apiKeyModal = getEl('api-key-modal');
    apiKeyForm = getEl('api-key-form');
    apiKeyResult = getEl('api-key-result');
    apiKeyValue = getEl('api-key-value');
    protectionStatusLabel = getEl('protection-status-label');
    toggleProtectionBtn = getEl('toggle-protection-btn');
    adminDomainInput = getEl('admin-domain-input');
    blockIpInput = getEl('block-ip-input');


    getEl('cancel-api-key-btn')?.addEventListener('click', () => apiKeyModal.classList.add('hidden'));
    getEl('close-api-key-modal-btn')?.addEventListener('click', () => apiKeyModal.classList.add('hidden'));

    getEl('save-api-key-btn')?.addEventListener('click', async () => {
        const name = getEl('api-key-name').value;
        if (!name) { await showAlert('Please enter a name'); return; }
        
        const perms = [];
        if (getEl('perm-stats').checked) perms.push('read:stats');
        if (getEl('perm-logs').checked) perms.push('read:logs');
        if (getEl('perm-system').checked) perms.push('read:system');
        if (getEl('perm-filtering').checked) perms.push('write:filtering');

        try {
            const resp = await fetch('/api/tokens/create', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, permissions: perms })
            });
            const data = await resp.json();
            apiKeyValue.textContent = data.token;
            apiKeyForm.classList.add('hidden');
            apiKeyResult.classList.remove('hidden');
            fetchAPIKeys();
        } catch (e) {
            await showAlert('Failed to create API key');
        }
    });

    getEl('copy-api-key-btn')?.addEventListener('click', () => {
        navigator.clipboard.writeText(apiKeyValue.textContent);
        getEl('copy-api-key-btn').textContent = 'Copied!';
        setTimeout(() => getEl('copy-api-key-btn').textContent = 'Copy', 2000);
    });

    toggleProtectionBtn?.addEventListener('click', async () => {
        const newStatus = !currentConfig.filtering_enabled;
        try {
            await fetch('/api/filtering/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: newStatus })
            });
            currentConfig.filtering_enabled = newStatus;
            renderProtectionStatus();
        } catch (e) {
            await showAlert('Failed to toggle protection');
        }
    });

    let editingTokenId = null;

    window.editAPIKey = (id) => {
        const token = allTokens.find(t => t.id === id);
        if (!token) return;

        editingTokenId = id;
        document.getElementById('api-key-modal-title').textContent = 'Edit API Key';
        document.getElementById('api-key-name').value = token.name;
        document.getElementById('perm-stats').checked = token.permissions.includes('read:stats');
        document.getElementById('perm-logs').checked = token.permissions.includes('read:logs');
        document.getElementById('perm-system').checked = token.permissions.includes('read:system');
        document.getElementById('perm-filtering').checked = token.permissions.includes('write:filtering');
        
        getEl('save-api-key-btn').textContent = 'Update Key';
        apiKeyForm.classList.remove('hidden');
        apiKeyResult.classList.add('hidden');
        apiKeyModal.classList.remove('hidden');
    };

    getEl('create-api-key-btn')?.addEventListener('click', () => {
        editingTokenId = null;
        getEl('api-key-modal-title').textContent = 'Generate API Key';
        getEl('api-key-name').value = '';
        getEl('perm-stats').checked = true;
        getEl('perm-logs').checked = false;
        getEl('perm-system').checked = false;
        getEl('perm-filtering').checked = false;
        getEl('save-api-key-btn').textContent = 'Generate';
        apiKeyForm.classList.remove('hidden');
        apiKeyResult.classList.add('hidden');
        apiKeyModal.classList.remove('hidden');
    });

    getEl('save-api-key-btn')?.addEventListener('click', async () => {
        const name = getEl('api-key-name').value;
        if (!name) { await showAlert('Please enter a name'); return; }
        
        const perms = [];
        if (getEl('perm-stats').checked) perms.push('read:stats');
        if (getEl('perm-logs').checked) perms.push('read:logs');
        if (getEl('perm-system').checked) perms.push('read:system');
        if (getEl('perm-filtering').checked) perms.push('write:filtering');

        try {
            const endpoint = editingTokenId ? '/api/tokens/update' : '/api/tokens/create';
            const body = { name, permissions: perms };
            if (editingTokenId) body.id = editingTokenId;

            const resp = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            
            if (editingTokenId) {
                apiKeyModal.classList.add('hidden');
                fetchAPIKeys();
            } else {
                const data = await resp.json();
                apiKeyValue.textContent = data.token;
                apiKeyForm.classList.add('hidden');
                apiKeyResult.classList.remove('hidden');
                fetchAPIKeys();
            }
        } catch (e) {
            await showAlert('Failed to save API key');
        }
    });

    let allTokens = [];

    const navItems = document.querySelectorAll('.nav-item');

    // --- Enter Key Support ---
    document.getElementById('login-password')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') document.getElementById('login-confirm-btn').click();
    });
    document.getElementById('setup-confirm')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') document.getElementById('setup-finish-btn').click();
    });
    document.getElementById('setup-password')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') nextSetupStep(2);
    });

    // --- Authentication Logic ---

    const checkAuthStatus = async () => {
        try {
            const resp = await fetch('/api/auth-status');
            const data = await resp.json();

            if (data.need_setup) {
                authOverlay.classList.remove('hidden');
                setupView.classList.remove('hidden');
                loginView.classList.add('hidden');
            } else if (!data.logged_in) {
                authOverlay.classList.remove('hidden');
                loginView.classList.remove('hidden');
                setupView.classList.add('hidden');
            } else {
                authOverlay.classList.add('hidden');
                initializeApp();
            }
        } catch (e) {
            console.error('Failed to check auth status', e);
        }
    };

    window.nextSetupStep = (step) => {
        document.querySelectorAll('.setup-pane').forEach(p => p.classList.add('hidden'));
        document.querySelectorAll('.w-step').forEach(s => s.classList.remove('active'));
        
        document.getElementById(`setup-pane-${step}`).classList.remove('hidden');
        document.getElementById(`w-step-${step}`).classList.add('active');

        if (step === 3) {
            renderSetupPresets();
        }
    };

    const renderSetupPresets = async () => {
        const resp = await fetch('/api/presets');
        const presets = await resp.json();
        const container = document.getElementById('setup-presets');
        container.innerHTML = '';

        const grouped = {};
        presets.forEach(p => {
            const cat = p.category || 'Other';
            if (!grouped[cat]) grouped[cat] = [];
            grouped[cat].push(p);
        });

        Object.keys(grouped).forEach(cat => {
            const catHeader = document.createElement('div');
            catHeader.className = 'preset-category-header';
            catHeader.textContent = cat;
            catHeader.style.cssText = 'grid-column: 1 / -1; margin: 15px 0 10px 0; font-weight: 700; color: var(--accent); font-size: 0.9rem; text-transform: uppercase; border-bottom: 1px solid var(--border); padding-bottom: 5px; text-align: left;';
            container.appendChild(catHeader);

            grouped[cat].forEach((p, i) => {
                const item = document.createElement('div');
                item.className = 'preset-selection-item';
                item.innerHTML = `
                    <input type="checkbox" id="pre-${cat}-${i}" value="${p.url}" ${p.enabled ? 'checked' : ''}>
                    <label for="pre-${cat}-${i}">${p.name}</label>
                `;
                container.appendChild(item);
            });
        });
    };

    document.getElementById('setup-finish-btn')?.addEventListener('click', async () => {
        const password = document.getElementById('setup-password').value;
        const confirm = document.getElementById('setup-confirm').value;
        const upstreams = document.getElementById('setup-upstreams').value.split(',').map(s => s.trim()).filter(s => s);
        const dotUpstreams = document.getElementById('setup-dot-upstreams').value.split(',').map(s => s.trim()).filter(s => s);
        const preferEncrypted = document.getElementById('setup-prefer-encrypted').checked;
        
        const selectedPresets = [];
        document.querySelectorAll('#setup-presets input:checked').forEach(input => {
            const label = input.nextElementSibling.textContent;
            selectedPresets.push({ name: label, url: input.value, enabled: true });
        });

        if (password.length < 12) {
            await showAlert('Password too short!');
            nextSetupStep(1);
            return;
        }

        if (password !== confirm) {
            await showAlert('Passwords do not match!');
            nextSetupStep(1);
            return;
        }

        // 1. Create Account
        const setupResp = await fetch('/api/setup', {
            method: 'POST',
            body: JSON.stringify({ password })
        });

        if (!setupResp.ok) {
            await showAlert('Setup failed at account creation.');
            return;
        }

        // 2. Login to get session for config
        const loginResp = await fetch('/api/login', {
            method: 'POST',
            body: JSON.stringify({ password })
        });

        if (!loginResp.ok) {
            await showAlert('Login failed during setup.');
            return;
        }

        const allowResp = await fetch('/api/presets/allow');
        const allAllows = await allowResp.json();
        const defaultAllows = allAllows.filter(a => a.enabled);

        // 3. Save Config (Upstreams + Selected Lists)
        await fetch('/api/config', {
            method: 'POST',
            body: JSON.stringify({ 
                upstreams, 
                upstream_dot: dotUpstreams, 
                prefer_encrypted: preferEncrypted, 
                lists: selectedPresets,
                allowlists: defaultAllows
            })
        });

        await showAlert('Setup complete! Welcome to ShieldDNS.');
        location.reload();
    });

    document.getElementById('login-confirm-btn').addEventListener('click', async () => {
        const password = document.getElementById('login-password').value;
        const resp = await fetch('/api/login', {
            method: 'POST',
            body: JSON.stringify({ password })
        });

        if (resp.ok) {
            checkAuthStatus();
        } else {
            await showAlert('Invalid password.');
        }
    });

    const handleLogout = async () => {
        await fetch('/api/logout', { method: 'POST' });
        location.reload();
    };
    document.getElementById('logout-btn')?.addEventListener('click', handleLogout);
    document.getElementById('nav-logout-btn')?.addEventListener('click', handleLogout);

    document.getElementById('password-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const current = document.getElementById('current-password').value;
        const newPwd = document.getElementById('new-password').value;

        if (newPwd.length < 12) {
            await showAlert('New password must be at least 12 characters.');
            return;
        }

        const resp = await fetch('/api/change-password', {
            method: 'POST',
            body: JSON.stringify({ current, new: newPwd })
        });

        if (resp.ok) {
            await showAlert('Password changed successfully! Please login again.');
            location.reload();
        } else {
            const err = await resp.text();
            await showAlert('Failed to change password: ' + err);
        }
    });

    // --- Main Application Logic ---

    const initializeApp = () => {
        // Initialize dynamic hostname in dashboard
        const dotInput = document.getElementById('copy-dot');
        if (dotInput) dotInput.value = window.location.hostname;

        fetchStats();
        fetchConfig();
        fetchPresets();
        fetchQueries();
        fetchHistory();
        fetchAPIKeys();
        startSSE();
        setInterval(fetchStats, 10000);
        setInterval(fetchHistory, 60000); // Chart once a minute
    };

    const fetchHistory = async () => {
        try {
            const resp = await fetch('/api/history');
            if (resp.status === 401) return;
            const data = await resp.json();
            renderChart(data);
        } catch (e) {
            console.error('Failed to fetch history', e);
        }
    };

    const renderChart = (data) => {
        const ctx = document.getElementById('traffic-chart').getContext('2d');
        const labels = Array.from({ length: 24 }, (_, i) => {
            const h = (new Date().getHours() - 23 + i + 24) % 24;
            return `${h}:00`;
        });

        const totals = data.map(d => d.total);
        const blocked = data.map(d => d.blocked);

        if (trafficChart) {
            trafficChart.data.datasets[0].data = totals;
            trafficChart.data.datasets[1].data = blocked;
            trafficChart.update();
            return;
        }

        trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Total Queries',
                        data: totals,
                        borderColor: '#5c6bc0',
                        backgroundColor: 'rgba(92, 107, 192, 0.1)',
                        fill: true,
                        tension: 0.4
                    },
                    {
                        label: 'Blocked',
                        data: blocked,
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        fill: true,
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } },
                    x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
                }
            }
        });
    };

    window.debounce = (func, wait) => {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    };

    const fetchQueries = async () => {
        const searchInput = document.getElementById('query-search');
        const filterStatus = document.getElementById('query-filter-status');
        const search = searchInput ? searchInput.value : '';
        const status = filterStatus ? filterStatus.value : '';

        try {
            const resp = await fetch(`/api/queries?search=${encodeURIComponent(search)}&status=${status}`);
            if (resp.status === 401) return;
            const queries = await resp.json();
            renderQueries(queries);
        } catch (e) {
            console.error('Failed to fetch queries', e);
        }
    };

    const renderQueries = (queries) => {
        const dashContainer = document.getElementById('query-log-items');
        const fullContainer = document.getElementById('full-query-log-items');

        const populate = (container, data) => {
            if (!container) return;
            container.innerHTML = '';
            data.forEach(q => {
                const row = document.createElement('tr');
                const time = new Date(q.time).toLocaleTimeString();
                const actionBtn = q.status === 'Allowed' 
                    ? `<button class="btn btn-sm secondary" onclick="addCustomRule('blocked', '${q.domain}')">Block</button>`
                    : `<button class="btn btn-sm secondary" onclick="addCustomRule('allowed', '${q.domain}')">Allow</button>`;
                
                row.innerHTML = `
                    <td>${time}</td>
                    <td title="${q.client_ip}">${q.domain}</td>
                    <td>${q.type}</td>
                    <td><span class="status-badge ${q.status.toLowerCase()}">${q.status}</span></td>
                    <td>${actionBtn}</td>
                `;
                container.appendChild(row);
            });
        };

        populate(dashContainer, (queries || []).slice(0, 10));
        populate(fullContainer, queries || []);
    };

    const createQueryRow = (q) => {
        const row = document.createElement('tr');
        const time = new Date(q.time || Date.now()).toLocaleTimeString();
        const actionBtn = q.status === 'Allowed' 
            ? `<button class="btn btn-sm secondary" onclick="addCustomRule('blocked', '${q.domain}')">Block</button>`
            : `<button class="btn btn-sm secondary" onclick="addCustomRule('allowed', '${q.domain}')">Allow</button>`;

        row.innerHTML = `
            <td>${time}</td>
            <td title="${q.client_ip}">${q.domain}</td>
            <td>${q.type}</td>
            <td><span class="status-badge ${q.status.toLowerCase()}">${q.status}</span></td>
            <td>${actionBtn}</td>
        `;
        return row;
    };

    const startSSE = () => {
        const source = new EventSource('/api/events');
        source.onmessage = (event) => {
            const query = JSON.parse(event.data);
            if (query.type === 'ping') return;
            
            const row = createQueryRow(query);
            queryLogItems.prepend(row);
            if (queryLogItems.children.length > 15) {
                queryLogItems.lastElementChild.remove();
            }
        };
        source.onerror = () => {
            source.close();
            setTimeout(startSSE, 5000);
        };
    };

    const renderTypeChart = (queryTypes) => {
        const ctx = document.getElementById('type-chart')?.getContext('2d');
        if (!ctx) return;

        let labels = Object.keys(queryTypes);
        let data = Object.values(queryTypes);

        if (labels.length === 0) {
            labels = ['No Data'];
            data = [1];
        }

        const colorPalette = {
            'A': '#3b82f6',      // blue
            'AAAA': '#10b981',   // emerald
            'HTTPS': '#8b5cf6',  // purple
            'TXT': '#f59e0b',    // orange
            'SRV': '#ec4899',    // pink
            'PTR': '#06b6d4',    // cyan
            'MX': '#ef4444',     // red
            'ANY': '#64748b'     // slate
        };
        const bgColors = labels.map((l, i) => colorPalette[l] || `hsl(${(i * 137.5) % 360}, 70%, 50%)`);

        if (typeChart) {
            typeChart.data.labels = labels;
            typeChart.data.datasets[0].data = data;
            typeChart.data.datasets[0].backgroundColor = bgColors;
            typeChart.update();
            return;
        }

        typeChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: bgColors,
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#94a3b8', boxWidth: 10, font: { size: 10 } }
                    }
                }
            }
        });
    };

    const fetchPresets = async () => {
        try {
            const resp = await fetch('/api/presets');
            const presets = await resp.json();
            renderPresets(presets);
        } catch (e) {
            console.error('Failed to fetch presets', e);
        }
    };

    const renderPresets = (presets) => {
        const container = document.getElementById('preset-items');
        container.innerHTML = '';

        const grouped = {};
        presets.forEach(p => {
            const cat = p.category || 'Other';
            if (!grouped[cat]) grouped[cat] = [];
            grouped[cat].push(p);
        });

        Object.keys(grouped).forEach(cat => {
            const catHeader = document.createElement('div');
            catHeader.className = 'preset-category-group';
            catHeader.style.cssText = 'grid-column: 1 / -1; margin-top: 20px;';
            catHeader.innerHTML = `<h2 style="font-size: 1.1rem; color: var(--accent); margin-bottom: 10px; display: flex; align-items: center; justify-content: flex-start; text-align: left; gap: 8px;">
                <i class="fas fa-folder-open"></i> ${cat}
            </h2>`;
            container.appendChild(catHeader);

            grouped[cat].forEach(preset => {
                const card = document.createElement('div');
                card.className = 'preset-card';
                card.innerHTML = `
                    <div class="preset-info">
                        <h3>${preset.name}</h3>
                    </div>
                    <button class="btn btn-sm secondary" onclick="addPreset('${preset.name}', '${preset.url}')">Add</button>
                `;
                container.appendChild(card);
            });
        });
    };

    window.addPreset = async (name, url) => {
        if (currentConfig.lists.some(l => l.url === url)) {
            await showAlert('This list is already added.');
            return;
        }
        currentConfig.lists.push({ name, url, enabled: true });
        await saveConfig();
        renderConfig();
    };

    const fetchAllowlistPresets = async () => {
        try {
            const resp = await fetch('/api/presets/allow');
            if (!resp.ok) return;
            const presets = await resp.json();
            renderAllowlistPresets(presets);
        } catch (e) {
            console.error('Failed to fetch allowlist presets', e);
        }
    };

    const renderAllowlistPresets = (presets) => {
        const container = document.getElementById('preset-allow-items');
        if (!container) return;
        container.innerHTML = '';

        const grouped = {};
        presets.forEach(p => {
            const cat = p.category || 'Official';
            if (!grouped[cat]) grouped[cat] = [];
            grouped[cat].push(p);
        });

        Object.keys(grouped).forEach(cat => {
            const catHeader = document.createElement('div');
            catHeader.className = 'preset-category-group';
            catHeader.style.cssText = 'grid-column: 1 / -1; margin-top: 20px;';
            catHeader.innerHTML = `<h2 style="font-size: 1.1rem; color: var(--accent); margin-bottom: 10px; display: flex; align-items: center; justify-content: flex-start; text-align: left; gap: 8px;">
                <i class="fas fa-folder-open"></i> ${cat}
            </h2>`;
            container.appendChild(catHeader);

            grouped[cat].forEach(preset => {
                const isAdded = (currentConfig.allowlists || []).some(l => l.url === preset.url);
                const card = document.createElement('div');
                card.className = 'preset-card';
                card.innerHTML = `
                    <div class="preset-info">
                        <h3>${preset.name}</h3>
                    </div>
                    <button class="btn btn-sm ${isAdded ? 'secondary' : 'primary'}" ${isAdded ? 'disabled' : ''} onclick="addAllowPreset('${preset.name}', '${preset.url}')">${isAdded ? 'Added ✓' : 'Add'}</button>
                `;
                container.appendChild(card);
            });
        });
    };

    window.addAllowPreset = async (name, url) => {
        if (!currentConfig.allowlists) currentConfig.allowlists = [];
        if (currentConfig.allowlists.some(l => l.url === url)) {
            await showAlert('This allowlist is already added.');
            return;
        }
        currentConfig.allowlists.push({ name, url, enabled: true, category: 'Official' });
        await saveConfig();
        renderConfig();
        renderAllowlistPresets(await (await fetch('/api/presets/allow')).json());
    };

    const fetchAnalytics = async () => {
        try {
            const [blockedResp, clientsResp] = await Promise.all([
                fetch('/api/top-blocked'),
                fetch('/api/top-clients')
            ]);
            if (blockedResp.ok && topBlockedContainer) {
                const blocked = await blockedResp.json();
                topBlockedContainer.innerHTML = (blocked || []).map(b => `
                    <tr>
                        <td>${b.domain}</td>
                        <td class="text-right">${b.count || 0}</td>
                    </tr>
                `).join('') || '<tr><td colspan="2">No data available</td></tr>';
            }
            if (clientsResp.ok && topClientsContainer) {
                const clients = await clientsResp.json();
                topClientsContainer.innerHTML = (clients || []).map(c => `
                    <tr>
                        <td>${c.client_ip}</td>
                        <td class="text-right">${c.count || 0}</td>
                    </tr>
                `).join('') || '<tr><td colspan="2">No data available</td></tr>';
            }
        } catch (e) {
            console.error('Failed to fetch analytics', e);
        }
    };

    // Navigation logic
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            const targetView = item.dataset.view;
            if (!targetView) return;

            e.preventDefault();

            navItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            
            views.forEach(v => v.classList.add('hidden'));
            const viewEl = document.getElementById(targetView);
            if (viewEl) viewEl.classList.remove('hidden');

            if (targetView === 'lists') { fetchPresets(); fetchAllowlistPresets(); }
            if (targetView === 'queries') fetchQueries();
            if (targetView === 'analytics') fetchAnalytics();
            if (targetView === 'about') fetchStats();
            if (targetView === 'diagnostics') {
                fetchDiagnostics();
                window.diagnosticsInterval = setInterval(fetchDiagnostics, 5000);
            } else {
                clearInterval(window.diagnosticsInterval);
            }
            if (targetView === 'system-logs') startSystemLogStream();
            else stopSystemLogStream();
        });
    });

    const fetchDiagnostics = async () => {
        try {
            const resp = await fetch('/api/diagnostics');
            if (resp.status === 401) return;
            const data = await resp.json();

            const certInfo = document.getElementById('cert-info-content');
            if (certInfo) {
                if (!data.certificate || !data.certificate.valid) {
                    certInfo.innerHTML = '<p class="help">No valid SSL certificate information available.</p>';
                } else {
                    const cert = data.certificate;
                    const daysLeft = Math.floor((new Date(cert.not_after) - new Date()) / (1000 * 60 * 60 * 24));
                    certInfo.innerHTML = `
                        <div class="diag-item"><span>Issuer</span><span class="badge secondary">${cert.issuer}</span></div>
                        <div class="diag-item"><span>Valid Until</span><span class="badge ${daysLeft < 30 ? 'danger' : 'official'}">${new Date(cert.not_after).toLocaleDateString()} (${daysLeft} days)</span></div>
                    `;
                }
            }

            const latencyList = document.getElementById('upstream-latency-list');
            if (latencyList) {
                if (!data.upstream_health || data.upstream_health.length === 0) {
                    latencyList.innerHTML = '<tr><td colspan="3" class="help">No upstream servers configured.</td></tr>';
                } else {
                    latencyList.innerHTML = data.upstream_health.map(h => {
                        const isUp = h.status === 'up';
                        const latencyStr = isUp ? `${h.latency_ms} ms` : '-';
                        return `
                            <tr>
                                <td>${h.server}</td>
                                <td><span class="badge ${isUp ? 'official' : 'danger'}">${h.status.toUpperCase()}</span></td>
                                <td style="text-align:right">${latencyStr}</td>
                            </tr>
                        `;
                    }).join('');
                }
            }
        } catch (e) {
            console.error('Failed to fetch diagnostics', e);
        }
    };

    const fetchStats = async () => {
        try {
            const resp = await fetch('/api/stats');
            if (resp.status === 401) return; 
            const data = await resp.json();
            
            if (statsContainer && statsContainer.total) {
                statsContainer.total.textContent = data.total_queries.toLocaleString();
                statsContainer.blocked.textContent = data.blocked_queries.toLocaleString();
                const ratio = data.total_queries > 0 ? (data.blocked_queries / data.total_queries * 100).toFixed(1) : 0;
                statsContainer.ratio.textContent = `${ratio} %`;
                const cacheRatio = data.total_queries > 0 ? (data.cache_hits / data.total_queries * 100).toFixed(1) : 0;
                statsContainer.cache.textContent = `${cacheRatio} %`;
                statsContainer.latency.textContent = `${(data.average_latency || 0).toFixed(2)} ms`;
                statsContainer.clients.textContent = data.unique_clients || 0;
            }
            
            if (data.query_types) {
                renderTypeChart(data.query_types);
            }

            // Update version
            const versionEl = document.getElementById('app-version');
            if (versionEl && data.version) {
                versionEl.textContent = data.version;
            }

            // About view updates
            const shieldVer = document.getElementById('about-shielddns-ver');
            if (shieldVer) shieldVer.textContent = data.version;
            
            const coreVer = document.getElementById('about-coredns-ver');
            if (coreVer) coreVer.textContent = data.coredns_version || 'v1.14.2';
            
            const osVer = document.getElementById('about-os-ver');
            if (osVer) osVer.textContent = 'Alpine ' + (data.alpine_version || '3.23');
        } catch (e) {
            console.error('Failed to fetch stats', e);
        }
    };

    const fetchConfig = async () => {
        try {
            const resp = await fetch('/api/config');
            if (resp.status === 401) return;
            currentConfig = await resp.json();
            // Fallback for old configs
            if (currentConfig.upstream_dot === undefined) currentConfig.upstream_dot = [];
            if (currentConfig.prefer_encrypted === undefined) currentConfig.prefer_encrypted = false;
            if (currentConfig.filtering_enabled === undefined) currentConfig.filtering_enabled = true;
            
            renderConfig();
            renderProtectionStatus();
        } catch (e) {
            console.error('Failed to fetch config', e);
        }
    };

    const renderProtectionStatus = () => {
        const enabled = currentConfig.filtering_enabled;
        const card = document.querySelector('.protection-status-card');
        const icon = document.getElementById('status-icon');
        const title = document.getElementById('status-title');
        const desc = document.getElementById('status-desc');

        if (enabled) {
            card.classList.remove('disabled');
            card.classList.add('protected');
            title.textContent = 'ShieldDNS is Active';
            desc.textContent = 'Your requests are being filtered and secured.';
            toggleProtectionBtn.textContent = 'Disable Protection';
            toggleProtectionBtn.className = 'btn btn-primary';
        } else {
            card.classList.remove('protected');
            card.classList.add('disabled');
            title.textContent = 'Protection is Disabled';
            desc.textContent = 'Blocklists are currently inactive. Traffic is unfiltered.';
            toggleProtectionBtn.textContent = 'Enable Protection';
            toggleProtectionBtn.className = 'btn secondary';
        }
    };

    const fetchAPIKeys = async () => {
        try {
            const resp = await fetch('/api/tokens');
            const tokens = await resp.json();
            renderAPIKeys(tokens);
        } catch (e) {
            console.error('Failed to fetch API keys', e);
        }
    };

    const renderAPIKeys = (tokens) => {
        allTokens = tokens;
        apiKeysListContainer.innerHTML = '';
        tokens.forEach(k => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${k.name}</td>
                <td>${(k.permissions || []).map(p => `<span class="badge secondary">${p}</span>`).join(' ')}</td>
                <td>${new Date(k.created_at).toLocaleDateString()}</td>
                <td>${!k.last_used || k.last_used === '0001-01-01T00:00:00Z' ? 'Never' : new Date(k.last_used).toLocaleString()}</td>
                <td>
                    <button class="btn btn-sm secondary" onclick="editAPIKey('${k.id}')">Edit</button>
                    <button class="btn btn-sm danger" onclick="deleteAPIKey('${k.id}')">Delete</button>
                </td>
            `;
            apiKeysListContainer.appendChild(tr);
        });
    };

    window.deleteAPIKey = async (id) => {
        if (!(await showConfirm('Are you sure you want to delete this API key?'))) return;
        try {
            await fetch(`/api/tokens/delete?id=${id}`, { method: 'DELETE' });
            fetchAPIKeys();
        } catch (e) {
            await showAlert('Failed to delete key');
        }
    };

    const renderConfig = () => {
        upstreamsInput.value = currentConfig.upstreams.join(', ');
        dotUpstreamsInput.value = (currentConfig.upstream_dot || []).join(', ');
        preferEncryptedCheck.checked = currentConfig.prefer_encrypted;
        
        if (adminDomainInput) adminDomainInput.value = currentConfig.admin_domain || '';
        if (blockIpInput) blockIpInput.value = currentConfig.block_page_ip || '';
        
        const smartCheck = document.getElementById('smart-upstream-check');
        if (smartCheck) smartCheck.checked = currentConfig.use_fastest_upstream || false;
        
        const retentionInput = document.getElementById('retention-input');
        if (retentionInput) retentionInput.value = currentConfig.retention_days || 30;

        currentConfig.lists = currentConfig.lists || [];
        listItemsContainer.innerHTML = '';
        currentConfig.lists.forEach((list, index) => {
            const item = createListItem(list, index, 'block');
            listItemsContainer.appendChild(item);
        });

        currentConfig.allowlists = currentConfig.allowlists || [];
        allowlistItemsContainer.innerHTML = '';
        currentConfig.allowlists.forEach((list, index) => {
            const item = createListItem(list, index, 'allow');
            allowlistItemsContainer.appendChild(item);
        });

        // Render Custom Rules
        const renderCustomList = (container, rules, type) => {
            if (!container) return;
            container.innerHTML = (rules || []).map(r => `
                <div class="preset-selection-item">
                    <span>${r}</span>
                    <button class="btn danger-text" onclick="removeCustomRule('${type}', '${r}')"><i class="fas fa-trash"></i></button>
                </div>
            `).join('') || '<p class="help">No custom rules added yet.</p>';
        };
        renderCustomList(customBlockedList, currentConfig.custom_blocked, 'blocked');
        renderCustomList(customAllowedList, currentConfig.custom_allowed, 'allowed');
    };

    window.addCustomRule = async (type, domain) => {
        if (!domain) {
            const input = document.getElementById(type === 'blocked' ? 'custom-block-input' : 'custom-allow-input');
            domain = input.value.trim();
            if (!domain) return;
            input.value = '';
        }
        
        const field = type === 'blocked' ? 'custom_blocked' : 'custom_allowed';
        if (!currentConfig[field]) currentConfig[field] = [];
        if (currentConfig[field].includes(domain)) {
            await showAlert('This domain is already in the list.');
            return;
        }
        
        currentConfig[field].push(domain);
        await saveConfig();
        renderConfig();
    };

    window.removeCustomRule = (type, domain) => {
        const field = type === 'blocked' ? 'custom_blocked' : 'custom_allowed';
        currentConfig[field] = currentConfig[field].filter(d => d !== domain);
        saveConfig();
        renderConfig();
    };

    const createListItem = (list, index, type) => {
        const item = document.createElement('div');
        item.className = 'list-item';
        const isOfficial = list.url.startsWith('file:///') || list.url.includes('FaserF/ShieldDNS');
        item.innerHTML = `
            <div class="list-info">
                <h3>${list.name} ${isOfficial ? '<span class="badge official">Official</span>' : ''}</h3>
                ${list.category ? `<span class="badge secondary" style="font-size: 0.7rem;">${list.category}</span>` : ''}
                <p>${list.url}</p>
            </div>
            <div class="list-actions">
                <button class="btn secondary" onclick="toggleList(${index}, '${type}')">${list.enabled ? 'Disable' : 'Enable'}</button>
                ${isOfficial ? '' : `<button class="btn danger" onclick="removeList(${index}, '${type}')">Remove</button>`}
            </div>
        `;
        return item;
    };

    const saveConfig = async () => {
        const upstreams = upstreamsInput.value.split(',').map(s => s.trim()).filter(s => s);
        const dots = dotUpstreamsInput.value.split(',').map(s => s.trim()).filter(s => s);
        
        currentConfig.upstreams = upstreams;
        currentConfig.upstream_dot = dots;
        currentConfig.prefer_encrypted = preferEncryptedCheck.checked;
        currentConfig.admin_domain = adminDomainInput?.value.trim() || '';
        currentConfig.block_ip_input = blockIpInput?.value.trim() || '';

        await fetch('/api/config', {
            method: 'POST',
            body: JSON.stringify(currentConfig)
        });
        await showAlert('Configuration saved!');
    };

    document.getElementById('settings-form')?.addEventListener('submit', (e) => {
        e.preventDefault();
        saveConfig();
    });

    document.getElementById('refresh-btn')?.addEventListener('click', async () => {
        await fetch('/api/refresh', { method: 'POST' });
        await showAlert('Update started in background...');
    });

    document.getElementById('check-updates-btn')?.addEventListener('click', async () => {
        await fetch('/api/refresh', { method: 'POST' });
        await showAlert('Update check started in background...');
    });

    document.getElementById('backup-btn')?.addEventListener('click', () => {
        window.location.href = '/api/backup';
    });

    const restoreFileInput = document.getElementById('restore-file-input');
    if (restoreFileInput) {
        restoreFileInput.addEventListener('change', async (e) => {
            if (!e.target.files.length) return;
            const file = e.target.files[0];
            
            if (await showConfirm('Are you sure you want to restore this configuration? This will overwrite your current settings and restart the filtering engine.')) {
                const formData = new FormData();
                formData.append('config', file);
                
                try {
                    const resp = await fetch('/api/restore', {
                        method: 'POST',
                        body: formData
                    });
                    if (resp.ok) {
                        await showAlert('Configuration restored successfully.');
                        window.location.reload();
                    } else {
                        const errText = await resp.text();
                        await showAlert('Restore failed: ' + errText);
                    }
                } catch (err) {
                    await showAlert('Restore request failed: ' + err.message);
                }
            }
            e.target.value = '';
        });
    }

    document.getElementById('smart-upstream-check')?.addEventListener('change', (e) => {
        currentConfig.use_fastest_upstream = e.target.checked;
        saveConfig();
    });

    document.getElementById('retention-input')?.addEventListener('change', (e) => {
        currentConfig.retention_days = parseInt(e.target.value);
        saveConfig();
    });

    // Modal logic for adding lists
    const modal = document.getElementById('modal');
    document.getElementById('add-list-btn')?.addEventListener('click', () => {
        document.getElementById('modal-title').textContent = 'Add Blocklist';
        document.getElementById('list-type').value = 'block';
        modal.classList.remove('hidden');
    });
    document.getElementById('add-allowlist-btn')?.addEventListener('click', () => {
        document.getElementById('modal-title').textContent = 'Add Allowlist';
        document.getElementById('list-type').value = 'allow';
        modal.classList.remove('hidden');
    });
    document.getElementById('modal-cancel')?.addEventListener('click', () => modal.classList.add('hidden'));
    
    document.getElementById('modal-confirm')?.addEventListener('click', () => {
        const name = document.getElementById('list-name').value;
        const url = document.getElementById('list-url').value;
        const type = document.getElementById('list-type').value;
        const category = document.getElementById('list-category').value;
        if (name && url) {
            if (type === 'allow') {
                currentConfig.allowlists.push({ name, url, enabled: true, category });
            } else {
                currentConfig.lists.push({ name, url, enabled: true, category });
            }
            saveConfig();
            modal.classList.add('hidden');
            renderConfig();
        }
    });

    document.getElementById('search-btn')?.addEventListener('click', async () => {
        const domain = document.getElementById('domain-search').value.trim();
        if (!domain) return;

            const resp = await fetch(`/api/search?q=${domain}`);
            if (!resp.ok) {
                const text = await resp.text();
                console.warn('Search failed:', text);
                const result = document.getElementById('search-result');
                result.textContent = 'Protection status unavailable (blocklist still loading)';
                result.className = 'help';
                result.classList.remove('hidden');
                return;
            }
            const data = await resp.json();
        const result = document.getElementById('search-result');
        result.classList.remove('hidden', 'blocked', 'allowed');
        
        if (data.blocked) {
            let listInfo = '';
            if (data.lists && data.lists.length > 0) {
                listInfo = `<div class="blocked-sources">Blocked by: ${data.lists.map(l => `<span class="badge secondary">${l}</span>`).join(' ')}</div>`;
            }
            result.innerHTML = `<div>❌ ${domain} is CURRENTLY BLOCKED</div>${listInfo}`;
            result.classList.add('blocked');
        } else {
            result.textContent = `✅ ${domain} is NOT BLOCKED`;
            result.classList.add('allowed');
        }
    });

    // System Reset Logic
    const resetModal1 = document.getElementById('reset-modal-1');
    const resetModal2 = document.getElementById('reset-modal-2');
    const resetBtn = document.getElementById('reset-system-btn');
    const resetConfirm1 = document.getElementById('reset-confirm-1');
    const resetCancel1 = document.getElementById('reset-cancel-1');
    const resetConfirm2 = document.getElementById('reset-confirm-2');
    const resetCancel2 = document.getElementById('reset-cancel-2');
    const resetFinalInput = document.getElementById('reset-final-input');
    const restartOverlay = document.getElementById('restart-overlay');
    const resetTriggerBackup = document.getElementById('reset-trigger-backup');

    resetBtn?.addEventListener('click', () => {
        resetModal1.classList.remove('hidden');
    });

    resetCancel1?.addEventListener('click', () => {
        resetModal1.classList.add('hidden');
    });

    resetConfirm1?.addEventListener('click', () => {
        resetModal1.classList.add('hidden');
        resetModal2.classList.remove('hidden');
    });

    resetCancel2?.addEventListener('click', () => {
        resetModal2.classList.add('hidden');
        resetFinalInput.value = '';
        resetConfirm2.disabled = true;
    });

    resetFinalInput?.addEventListener('input', (e) => {
        resetConfirm2.disabled = e.target.value !== 'RESET';
    });

    resetTriggerBackup?.addEventListener('click', (e) => {
        e.preventDefault();
        window.location.href = '/api/backup';
    });

    resetConfirm2?.addEventListener('click', async () => {
        if (resetFinalInput.value !== 'RESET') return;

        resetModal2.classList.add('hidden');
        restartOverlay.classList.remove('hidden');

        try {
            const resp = await fetch('/api/reset', { method: 'POST' });
            if (resp.ok) {
                // Wait for the system to actually go down and come back
                let attempts = 0;
                const checkStatus = async () => {
                    attempts++;
                    try {
                        const statusResp = await fetch('/api/auth-status');
                        if (statusResp.ok) {
                            location.reload();
                        } else {
                            setTimeout(checkStatus, 2000);
                        }
                    } catch (e) {
                        if (attempts > 30) {
                            await showAlert('System is taking longer than expected to restart. Please refresh manually.');
                        } else {
                            setTimeout(checkStatus, 2000);
                        }
                    }
                };
                setTimeout(checkStatus, 3000);
            } else {
                throw new Error('Reset failed');
            }
        } catch (e) {
            restartOverlay.classList.add('hidden');
            await showAlert('System reset failed: ' + e.message);
        }
    });

    document.getElementById('reset-lists-btn')?.addEventListener('click', async () => {
        if (!(await showConfirm('Are you sure you want to restore all filter lists to factory defaults? Your custom lists will be removed.'))) return;
        try {
            const resp = await fetch('/api/config/reset-lists', { method: 'POST' });
            if (resp.ok) {
                await showAlert('Filter lists restored to defaults! Processing updates in background...');
                location.reload();
            }
        } catch (e) {
            await showAlert('Failed to reset lists');
        }
    });

    // Initial check
    checkAuthStatus();

    // Attach to window for global access
    window.saveConfig = saveConfig;
    window.renderConfig = renderConfig;
    window.fetchConfig = fetchConfig;
    window.fetchQueries = fetchQueries;
});

const startSystemLogStream = () => {
    if (systemLogEventSource) return;
    systemLogTerminal.textContent = '';
    systemLogEventSource = new EventSource('/api/system-logs');
    systemLogEventSource.onmessage = (e) => {
        const line = document.createElement('div');
        line.textContent = e.data;
        // Basic syntax coloring
        if (e.data.includes('[CoreDNS]')) line.style.color = '#5c6bc0';
        if (e.data.includes('[CoreDNS-ERR]')) line.style.color = '#ef4444';
        
        systemLogTerminal.appendChild(line);
        systemLogTerminal.scrollTop = systemLogTerminal.scrollHeight;
        
        // Limit lines in DOM
        if (systemLogTerminal.childNodes.length > 1000) {
            systemLogTerminal.removeChild(systemLogTerminal.firstChild);
        }
    };
    systemLogEventSource.onerror = () => {
        stopSystemLogStream();
        setTimeout(startSystemLogStream, 5000);
    };
};

const stopSystemLogStream = () => {
    if (systemLogEventSource) {
        systemLogEventSource.close();
        systemLogEventSource = null;
    }
};

window.clearSystemLogs = () => {
    systemLogTerminal.textContent = '';
};

const fetchDiagnostics = async () => {
    try {
        const resp = await fetch('/api/diagnostics');
        const data = await resp.json();
        
        const cert = data.certificate || {};
        certInfoContent.innerHTML = `
            <div class="diag-item"><span>Status</span><span class="badge ${cert.valid ? 'official' : 'danger'}">${cert.valid ? 'Valid' : 'Expired'}</span></div>
            <div class="diag-item"><span>Subject</span><span>${cert.subject || '-'}</span></div>
            <div class="diag-item"><span>Issuer</span><span>${cert.issuer || '-'}</span></div>
            <div class="diag-item"><span>Expires</span><span>${cert.not_after ? new Date(cert.not_after).toLocaleString() : '-'}</span></div>
            <div class="diag-item"><span>Not Before</span><span>${cert.not_before ? new Date(cert.not_before).toLocaleString() : '-'}</span></div>
            <div class="diag-item"><span>SANs</span><div style="text-align:right">${(cert.dns_names || []).join('<br>') || '-'}</div></div>
        `;

        const latencyTable = document.getElementById('upstream-latency-list');
        if (latencyTable) {
            const upstreams = data.upstream_health || [];
            if (upstreams.length === 0) {
                latencyTable.innerHTML = '<tr><td colspan="3" class="help">No upstreams configured.</td></tr>';
            } else {
                latencyTable.innerHTML = upstreams.map(h => {
                    const isUp = h.status === 'up';
                    const latStr = isUp ? `${h.latency_ms.toFixed(1)} ms` : '-';
                    return `
                        <tr>
                            <td>${h.server}</td>
                            <td><span class="badge ${isUp ? 'official' : 'danger'}">${isUp ? 'Healthy' : 'Down'}</span></td>
                            <td class="text-right">${latStr}</td>
                        </tr>
                    `;
                }).join('');
            }
        }
    } catch (e) {
        certInfoContent.innerHTML = '<p class="danger-text">Failed to load diagnostics information.</p>';
    }
};


window.toggleList = async (index, type) => {
    if (type === 'allow') {
        currentConfig.allowlists[index].enabled = !currentConfig.allowlists[index].enabled;
    } else {
        currentConfig.lists[index].enabled = !currentConfig.lists[index].enabled;
    }
    await saveConfig();
    renderConfig();
};

window.removeList = async (index, type) => {
    if (await showConfirm('Are you sure you want to remove this list?')) {
        if (type === 'allow') {
            currentConfig.allowlists.splice(index, 1);
        } else {
            currentConfig.lists.splice(index, 1);
        }
        await saveConfig();
        renderConfig();
    }
};

window.copyText = async (id) => {
    const input = document.getElementById(id);
    try {
        await navigator.clipboard.writeText(input.value);
        const btn = input.nextElementSibling;
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = originalText, 2000);
    } catch (err) {
        console.error('Failed to copy text: ', err);
    }
};

window.exportLogs = (format) => {
    window.location.href = `/api/export?format=${format}`;
};
