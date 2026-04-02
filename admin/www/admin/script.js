let currentConfig = { upstreams: [], upstream_dot: [], prefer_encrypted: true, lists: [], allowlists: [], custom_blocked: [], custom_allowed: [] };
    let trafficChart = null;
    let typeChart = null;
    let clientAliases = {};
    let clientChart = null;
    let blocklistMap = {};
    let allCountries = {};
    
    // UI Elements
    let authOverlay, setupView, loginView, listItemsContainer, allowlistItemsContainer, views;
    let upstreamsInput, dotUpstreamsInput, preferEncryptedCheck, signMobileConfigCheck, customBlockedList, customAllowedList;
    let systemLogTerminal, certInfoContent, statsContainer, topBlockedContainer, topClientsContainer;
    let queryLogItems, fullQueryLogItems, latencyList;
    let systemLogEventSource = null;
    let apiKeysListContainer, apiKeyModal, apiKeyForm, apiKeyResult, apiKeyValue, protectionStatusLabel, toggleProtectionBtn;
    let adminDomainInput, blockIpInput, tagsContainer;

// DOMContentLoaded will remain, but showAlert/showConfirm are gone
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

    // Mobile Sidebar Toggle
    const sidebar = document.querySelector('.sidebar');
    const sidebarOverlay = document.getElementById('sidebar-overlay');
    const sidebarToggle = document.getElementById('sidebar-toggle');

    const toggleSidebar = () => {
        sidebar.classList.toggle('open');
        sidebarOverlay.classList.toggle('open');
    };

    sidebarToggle?.addEventListener('click', toggleSidebar);
    sidebarOverlay?.addEventListener('click', toggleSidebar);

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
    signMobileConfigCheck = getEl('sign-mobileconfig-check');
    customBlockedList = getEl('custom-blocked-list');
    customAllowedList = getEl('custom-allowed-list');
    systemLogTerminal = getEl('system-log-terminal');
    certInfoContent = getEl('cert-info-content');
    topBlockedContainer = getEl('top-blocked-list');
    topClientsContainer = getEl('top-clients-list');
    queryLogItems = getEl('query-log-items');
    fullQueryLogItems = getEl('full-query-log-items');
    latencyList = getEl('upstream-latency-list');
    tagsContainer = getEl('blocked-countries-tags');

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

    getEl('copy-api-key-btn')?.addEventListener('click', () => {
        navigator.clipboard.writeText(apiKeyValue.textContent);
        getEl('copy-api-key-btn').textContent = 'Copied!';
        setTimeout(() => getEl('copy-api-key-btn').textContent = 'Copy', 2000);
    });

    getEl('close-list-details-btn')?.addEventListener('click', () => getEl('list-details-modal').classList.add('hidden'));
    getEl('close-list-details-btn-2')?.addEventListener('click', () => getEl('list-details-modal').classList.add('hidden'));

    const formatDate = (dateString) => {
        if (!dateString || dateString.startsWith('0001-01-01')) return 'Never';
        try {
            const date = new Date(dateString);
            if (isNaN(date.getTime())) return 'Never';
            return date.toLocaleString(undefined, {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        } catch (e) {
            return 'Never';
        }
    };

    window.openListDetailsModal = (list) => {
        console.log('Opening details for list:', list);
        const modal = getEl('list-details-modal');
        if (!modal) {
            console.error('List details modal not found in DOM');
            return;
        }

        getEl('modal-list-name').textContent = list.name || 'List Details';
        const urlEl = getEl('modal-list-url');
        const url = list.url || '';
        urlEl.textContent = url || 'No URL';
        urlEl.href = url.startsWith('file://') ? '#' : (url || '#');
        
        getEl('modal-list-entries').textContent = (list.entries || 0).toLocaleString();
        getEl('modal-list-updated').textContent = formatDate(list.updated_at);
        
        modal.classList.remove('hidden');
    };

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
            if (e.message.includes('Unexpected token') || e.message.includes('JSON')) {
                 // Likely getting 'Setup required' plain text
                 checkAuthStatus();
            }
            await showAlert('Failed to save API key');
        }
    });

    let allTokens = [];

    const navItems = document.querySelectorAll('.nav-item');

    document.getElementById('login-password')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') document.getElementById('login-confirm-btn').click();
    });
    document.getElementById('setup-confirm')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') document.getElementById('setup-finish-btn').click();
    });
    document.getElementById('setup-password')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') nextSetupStep(2);
    });


    const checkAuthStatus = async () => {
        try {
            const resp = await fetch('/api/auth-status');
            if (resp.status === 403) {
                // Backend says setup required
                authOverlay.classList.remove('hidden');
                setupView.classList.remove('hidden');
                loginView.classList.add('hidden');
                return;
            }
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


    const initializeApp = () => {
        // Initialize dynamic connection guide in dashboard
        const currentDomain = window.location.hostname;
        const setGuide = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.value = val;
        };
        setGuide('guide-dot-host', currentDomain);
        setGuide('guide-dot-url', `tls://${currentDomain}`);
        setGuide('guide-doh-url', `https://${currentDomain}/dns-query`);
        setGuide('guide-doq-url', `quic://${currentDomain}`);

        fetchStats();
        fetchConfig();
        fetchPresets();
        fetchQueries();
        fetchHistory();
        fetchAPIKeys();
        fetchCountries();
        startSSE();
        setInterval(fetchStats, 10000);
        setInterval(fetchHistory, 60000); // Chart once a minute
    };

    const fetchHistory = async () => {
        try {
            const resp = await fetch('/api/history');
            if (resp.status === 403) {
                const text = await resp.text();
                if (text.includes('Setup required') || text.includes('SETUP_REQUIRED')) {
                    checkAuthStatus();
                    return;
                }
            }
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



    const fetchQueries = async () => {
        const searchInput = document.getElementById('query-search');
        const filterStatus = document.getElementById('query-filter-status');
        const search = searchInput ? searchInput.value : '';
        const status = filterStatus ? filterStatus.value : '';

        try {
            const resp = await fetch(`/api/queries?search=${encodeURIComponent(search)}&status=${status}`);
            if (resp.status === 403) {
                const text = await resp.text();
                if (text.includes('Setup required') || text.includes('SETUP_REQUIRED')) {
                    checkAuthStatus();
                    return;
                }
            }
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
                
                const clientDisplay = q.client_alias ? `${q.client_alias} (${q.client_ip})` : q.client_ip;
                
                row.innerHTML = `
                    <td>${time}</td>
                    <td><span class="domain-link" onclick="showDomainDetails('${q.domain}')" title="${q.domain}">${q.domain}</span></td>
                    <td><span class="ip-link" onclick="showIPDetails('${q.client_ip}')" title="${q.client_ip}">${clientDisplay}</span></td>
                    <td class="hide-mobile">${q.type}</td>
                    <td><span class="status-badge ${q.status.toLowerCase()}">${q.status}</span></td>
                    <td class="hide-mobile">${actionBtn}</td>
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

        const clientDisplay = q.client_alias ? `${q.client_alias} (${q.client_ip})` : q.client_ip;

        row.innerHTML = `
            <td>${time}</td>
            <td><span class="domain-link" onclick="showDomainDetails('${q.domain}')" title="${q.domain}">${q.domain}</span></td>
            <td><span class="ip-link" onclick="showIPDetails('${q.client_ip}')" title="${q.client_ip}">${clientDisplay}</span></td>
            <td class="hide-mobile">${q.type}</td>
            <td><span class="status-badge ${q.status.toLowerCase()}">${q.status}</span></td>
            <td class="hide-mobile">${actionBtn}</td>
        `;
        return row;
    };

    const startSSE = () => {
        const source = new EventSource('/api/events');
        source.onmessage = (event) => {
            const query = JSON.parse(event.data);
            if (query.type === 'ping') return;
            
            const row = createQueryRow(query);
            
            // Update Dashboard Live Log
            if (queryLogItems) {
                queryLogItems.prepend(row);
                if (queryLogItems.children.length > 15) {
                    queryLogItems.lastElementChild.remove();
                }
            }

            // Update Full Query Log
            if (fullQueryLogItems) {
                const fullRow = row.cloneNode(true);
                fullQueryLogItems.prepend(fullRow);
                if (fullQueryLogItems.children.length > 500) {
                    fullQueryLogItems.lastElementChild.remove();
                }
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

        const bgColors = labels.map((l, i) => DNS_TYPE_COLORS[l] || `hsl(${(i * 137.5) % 360}, 70%, 50%)`);

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
                        <td><span class="domain-link" onclick="showDomainDetails('${b.domain}')">${b.domain}</span></td>
                        <td class="text-right">${b.count || 0}</td>
                    </tr>
                `).join('') || '<tr><td colspan="2">No data available</td></tr>';
            }
            if (clientsResp.ok && topClientsContainer) {
                const clients = await clientsResp.json();
                topClientsContainer.innerHTML = (clients || []).map(c => {
                    const display = c.client_alias ? `${c.client_alias} (${c.client_ip})` : c.client_ip;
                    return `
                        <tr>
                            <td><span class="ip-link" onclick="showIPDetails('${c.client_ip}')">${display}</span></td>
                            <td class="text-right">${c.count || 0}</td>
                        </tr>
                    `;
                }).join('') || '<tr><td colspan="2">No data available</td></tr>';
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

            if (targetView === 'queries') fetchQueries();
            else if (targetView === 'analytics') fetchAnalytics();
            else if (targetView === 'system-logs') startSystemLogStream();
            else if (targetView === 'diagnostics') {
                fetchDiagnostics();
                startDiagTimer();
            }
            else if (targetView === 'lists') { fetchPresets(); fetchAllowlistPresets(); }
            else if (targetView === 'settings') fetchConfig();
            else if (targetView === 'about') fetchStats();
            
            if (targetView !== 'diagnostics') stopDiagTimer();
            if (targetView !== 'system-logs') stopSystemLogStream();

            // Auto-close sidebar on mobile after selection
            if (sidebar.classList.contains('open')) {
                toggleSidebar();
            }
        });
    });

    let diagnosticsInterval;
    const startDiagTimer = () => {
        stopDiagTimer(); // Clear any existing timer
        const interval = (currentConfig.diagnostics_refresh_interval || 600) * 1000;
        diagnosticsInterval = setInterval(fetchDiagnostics, interval);
    };

    const stopDiagTimer = () => {
        if (diagnosticsInterval) {
            clearInterval(diagnosticsInterval);
            diagnosticsInterval = null;
        }
    };

    const formatUptime = (seconds) => {
        const d = Math.floor(seconds / (3600 * 24));
        const h = Math.floor((seconds % (3600 * 24)) / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = Math.floor(seconds % 60);

        let uptimeString = '';
        if (d > 0) uptimeString += `${d}d `;
        if (h > 0) uptimeString += `${h}h `;
        if (m > 0) uptimeString += `${m}m `;
        uptimeString += `${s}s`;
        return uptimeString.trim();
    };

    const fetchDiagnostics = async () => {
        try {
            const resp = await fetch('/api/diagnostics');
            if (resp.status === 401) return;
            const data = await resp.json();

            const selectionMethod = document.getElementById('upstream-selection-method');
            if (selectionMethod) {
                selectionMethod.textContent = `(${data.selection_mode || 'Manual'})`;
            }

            const certInfo = document.getElementById('cert-info-content');
            if (certInfo) {
                if (!data.certificate || !data.certificate.valid) {
                    certInfo.innerHTML = '<p class="help">No valid SSL certificate information available.</p>';
                } else {
                    const cert = data.certificate;
                    const daysLeft = Math.floor((new Date(cert.not_after) - new Date()) / (1000 * 60 * 60 * 24));
                    certInfo.innerHTML = `
                        <div class="diag-item"><span>Status</span><span class="badge ${cert.valid ? 'official' : 'danger'}">${cert.valid ? 'Valid' : 'Expired'}</span></div>
                        <div class="diag-item"><span>Subject</span><span title="${cert.subject || ''}">${cert.subject || '-'}</span></div>
                        <div class="diag-item"><span>Issuer</span><span title="${cert.issuer || ''}">${cert.issuer || '-'}</span></div>
                        <div class="diag-item"><span>Expires</span><span>${new Date(cert.not_after).toLocaleString()} (${daysLeft} days left)</span></div>
                        <div class="diag-item"><span>SANs</span><span style="white-space: normal; word-break: break-all;">${(cert.dns_names || []).join(', ') || '-'}</span></div>
                    `;
                }
            }

            if (latencyList) {
                if (!data.upstream_health || data.upstream_health.length === 0) {
                    latencyList.innerHTML = '<tr><td colspan="3" class="help">No upstream servers configured.</td></tr>';
                } else {
                    latencyList.innerHTML = data.upstream_health.map(h => {
                        const isUp = h.status === 'up';
                        const latencyStr = isUp ? `${h.latency_ms.toFixed(1)} ms` : '-';
                        const preferredBadge = h.is_preferred ? '<span class="badge" style="background: var(--accent); color: white; margin-left:8px;">Primary</span>' : '';
                        return `
                            <tr>
                                <td>${h.server}${preferredBadge}</td>
                                <td><span class="badge ${isUp ? 'official' : 'danger'}">${isUp ? 'Healthy' : 'Down'}</span></td>
                                <td style="text-align:right">${latencyStr}</td>
                            </tr>
                        `;
                    }).join('');
                }
            }

            // System Resources
            if (data.system) {
                const sys = data.system;
                const cpuLoad = document.getElementById('diag-cpu-load');
                if (cpuLoad && sys.cpu_load) {
                    cpuLoad.textContent = sys.cpu_load.join(', ');
                }
                const cpuModel = document.getElementById('diag-cpu-model');
                if (cpuModel && sys.cpu_model) {
                    cpuModel.textContent = `${sys.cpu_model} (${sys.cpu_cores || 1} cores)`;
                }
                
                const ramUsage = document.getElementById('diag-ram-usage');
                const ramBar = document.getElementById('diag-ram-bar');
                if (ramUsage && sys.ram_total_mb) {
                    ramUsage.textContent = `${sys.ram_used_mb}MB / ${sys.ram_total_mb}MB (${sys.ram_percent}%)`;
                    if (ramBar) ramBar.style.width = `${sys.ram_percent}%`;
                }

                const diskUsage = document.getElementById('diag-disk-usage');
                const diskBar = document.getElementById('diag-disk-bar');
                if (diskUsage && sys.disk_total_gb) {
                    diskUsage.textContent = `${sys.disk_used_gb}GB / ${sys.disk_total_gb}GB (${sys.disk_percent}%)`;
                    if (diskBar) diskBar.style.width = `${sys.disk_percent}%`;
                }

                const uptime = document.getElementById('diag-uptime');
                if (uptime && sys.uptime_seconds) {
                    uptime.textContent = formatUptime(sys.uptime_seconds);
                }
            }
        } catch (e) {
            console.error('Failed to fetch diagnostics', e);
        }
    };

    const fetchStats = async () => {
        try {
            const resp = await fetch('/api/stats');
            if (resp.status === 403) {
                const text = await resp.text();
                if (text.includes('Setup required') || text.includes('SETUP_REQUIRED')) {
                    checkAuthStatus();
                    return;
                }
            }
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
            const updateBadge = (el, current, latest) => {
                if (!el) return;
                const normalize = (v) => {
                    if (!v) return '';
                    let n = v.toLowerCase().trim();
                    if (n.startsWith('v')) n = n.substring(1);
                    // Split by space, comma, tab, or hyphen (if hyphen is followed by arch info)
                    // e.g. "1.14.2 linux/arm64" or "1.14.2-linux-arm64"
                    let parts = n.split(/[ \t,]/);
                    let vPart = parts[0];
                    if (vPart.includes('-')) {
                        // Check if the part after hyphen looks like a version or metadata
                        let subParts = vPart.split('-');
                        // If the first subpart is numeric-ish, it's likely the version
                        vPart = subParts[0];
                    }
                    return vPart.trim();
                };

                const currentNorm = normalize(current);
                const latestNorm = normalize(latest);

                // Use the normalized version for display if the original is too long/complex
                let displayVersion = current;
                if (current.includes(' ') || current.includes(',') || current.length > 15) {
                    displayVersion = normalize(current);
                    if (!displayVersion.startsWith('v')) displayVersion = 'v' + displayVersion;
                }

                let html = `<span title="${current}">${displayVersion}</span>`;
                if (latest && latestNorm !== currentNorm) {
                    html += ` <span class="badge warning" style="margin-left:8px; background:#f59e0b; color:white;">UPDATE</span>`;
                } else if (latest) {
                    html += ` <span class="badge official" style="margin-left:8px;">LATEST</span>`;
                }
                el.innerHTML = html;
            };

            updateBadge(document.getElementById('about-shielddns-ver'), data.version, data.latest_version);
            updateBadge(document.getElementById('about-coredns-ver'), data.coredns_version || 'v1.14.2', data.latest_coredns_version);
            updateBadge(document.getElementById('about-os-ver'), (data.alpine_version || '3.23'), data.latest_alpine_version);
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

    const fetchCountries = async () => {
        try {
            const resp = await fetch('/api/countries');
            if (resp.ok) {
                allCountries = await resp.json();
                initCountryPicker();
                renderConfig();
            }
        } catch (e) {
            console.error('Failed to fetch countries', e);
        }
    };

    const initCountryPicker = () => {
        const searchInput = document.getElementById('country-search');
        const dropdown = document.getElementById('country-dropdown');
        if (!searchInput || !dropdown) return;

        searchInput.addEventListener('input', () => {
            const query = searchInput.value.toLowerCase();
            if (!query) {
                dropdown.classList.add('hidden');
                return;
            }

            const filtered = Object.entries(allCountries)
                .filter(([code, name]) => name.toLowerCase().includes(query) || code.toLowerCase().includes(query))
                .slice(0, 10);

            if (filtered.length > 0) {
                dropdown.innerHTML = filtered.map(([code, name]) => `
                    <div class="dropdown-item" onclick="selectCountry('${code}')">
                        <img src="https://flagcdn.com/w20/${code.toLowerCase()}.png" style="vertical-align: middle; margin-right: 8px; border-radius: 2px;">
                        ${name} (${code})
                    </div>
                `).join('');
                dropdown.classList.remove('hidden');
            } else {
                dropdown.classList.add('hidden');
            }
        });

        document.addEventListener('click', (e) => {
            if (!searchInput.contains(e.target) && !dropdown.contains(e.target)) {
                dropdown.classList.add('hidden');
            }
        });
    };

    window.selectCountry = async (code) => {
        if (!currentConfig.blocked_countries) currentConfig.blocked_countries = [];
        if (!currentConfig.blocked_countries.includes(code)) {
            currentConfig.blocked_countries.push(code);
            await saveConfig();
            renderConfig();
        }
        document.getElementById('country-search').value = '';
        document.getElementById('country-dropdown').classList.add('hidden');
    };

    window.removeCountry = async (code) => {
        currentConfig.blocked_countries = (currentConfig.blocked_countries || []).filter(c => c !== code);
        await saveConfig();
        renderConfig();
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
        if (signMobileConfigCheck) signMobileConfigCheck.checked = currentConfig.sign_mobileconfig;
        
        if (adminDomainInput) adminDomainInput.value = currentConfig.admin_domain || '';
        if (blockIpInput) blockIpInput.value = currentConfig.block_page_ip || '';
        
        const smartCheck = document.getElementById('smart-upstream-check');
        if (smartCheck) smartCheck.checked = currentConfig.use_fastest_upstream || false;
        
        const retentionInput = document.getElementById('retention-input');
        if (retentionInput) retentionInput.value = currentConfig.retention_days || 30;

        const latencyIntervalInput = document.getElementById('latency-interval-input');
        if (latencyIntervalInput) latencyIntervalInput.value = currentConfig.latency_test_interval || 10;

        const smartPolicyInput = document.getElementById('smart-selection-policy-input');
        if (smartPolicyInput) smartPolicyInput.value = currentConfig.smart_selection_policy || 'fastest';

        const diagRefreshInput = document.getElementById('diagnostics-interval-input');
        if (diagRefreshInput) diagRefreshInput.value = currentConfig.diagnostics_refresh_interval || 600;

        const serveStaleCheck = document.getElementById('serve-stale-check');
        if (serveStaleCheck) serveStaleCheck.checked = currentConfig.serve_stale;

        if (document.getElementById('dnssec-check')) document.getElementById('dnssec-check').checked = currentConfig.dnssec_enabled;
        if (document.getElementById('sign-mobileconfig-check')) document.getElementById('sign-mobileconfig-check').checked = currentConfig.sign_mobileconfig;
        if (document.getElementById('debug-mode-check')) document.getElementById('debug-mode-check').checked = currentConfig.debug_mode;

        currentConfig.lists = currentConfig.lists || [];
        listItemsContainer.innerHTML = '';
        currentConfig.lists.forEach((list, index) => {
            const item = createListItem(list, index, 'block');
            listItemsContainer.appendChild(item);
        });

        // Add delegated listener for blocklists
        if (!listItemsContainer.getAttribute('data-has-listener')) {
            listItemsContainer.addEventListener('click', (e) => {
                const item = e.target.closest('.list-item');
                if (!item) return;
                
                // Don't trigger if a button or link was clicked
                if (e.target.tagName === 'BUTTON' || e.target.tagName === 'A' || e.target.closest('button') || e.target.closest('a')) {
                    return;
                }

                const index = parseInt(item.getAttribute('data-index'));
                const list = currentConfig.lists[index];
                if (list) window.openListDetailsModal(list);
            });
            listItemsContainer.setAttribute('data-has-listener', 'true');
        }

        currentConfig.allowlists = currentConfig.allowlists || [];
        allowlistItemsContainer.innerHTML = '';
        currentConfig.allowlists.forEach((list, index) => {
            const item = createListItem(list, index, 'allow');
            allowlistItemsContainer.appendChild(item);
        });

        // Add delegated listener for allowlists
        if (!allowlistItemsContainer.getAttribute('data-has-listener')) {
            allowlistItemsContainer.addEventListener('click', (e) => {
                const item = e.target.closest('.list-item');
                if (!item) return;

                // Don't trigger if a button or link was clicked
                if (e.target.tagName === 'BUTTON' || e.target.tagName === 'A' || e.target.closest('button') || e.target.closest('a')) {
                    return;
                }

                const index = parseInt(item.getAttribute('data-index'));
                const list = currentConfig.allowlists[index];
                if (list) window.openListDetailsModal(list);
            });
            allowlistItemsContainer.setAttribute('data-has-listener', 'true');
        }

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

        // Render Custom Mappings
        const mappingsList = document.getElementById('custom-mappings-list');
        if (mappingsList) {
            const mappings = currentConfig.custom_mappings || {};
            const keys = Object.keys(mappings);
            mappingsList.innerHTML = keys.map(domain => `
                <div class="preset-selection-item">
                    <span style="flex:1">${domain}</span>
                    <span class="badge secondary" style="font-family:monospace; margin-right: 15px;">${mappings[domain]}</span>
                    <button class="btn danger-text" onclick="removeCustomMapping('${domain}')"><i class="fas fa-trash"></i></button>
                </div>
            `).join('') || '<p class="help">No custom mappings added yet.</p>';
        }


        // Render Blocked Countries Tags
        if (tagsContainer) {
            tagsContainer.innerHTML = (currentConfig.blocked_countries || []).map(code => {
                const name = allCountries[code] || code;
                return `
                    <div class="tag">
                        <img src="https://flagcdn.com/w20/${code.toLowerCase()}.png" style="vertical-align: middle; border-radius: 2px;">
                        <span>${name}</span>
                        <span class="remove-tag" onclick="removeCountry('${code}')">&times;</span>
                    </div>
                `;
            }).join('');
        }

        renderLastLogin();
    };

    const renderLastLogin = () => {
        const lastLoginEl = document.getElementById('dashboard-last-login');
        if (!lastLoginEl || !currentConfig.last_login) {
            if (lastLoginEl) lastLoginEl.style.display = 'none';
            return;
        }

        const date = new Date(currentConfig.last_login);
        if (isNaN(date.getTime()) || date.getFullYear() < 2000) {
            lastLoginEl.style.display = 'none';
            return;
        }

        lastLoginEl.style.display = 'block';
        lastLoginEl.textContent = `Your last login was at ${date.toLocaleString()}`;
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

    window.removeCustomRule = async (type, domain) => {
        const field = type === 'blocked' ? 'custom_blocked' : 'custom_allowed';
        currentConfig[field] = currentConfig[field].filter(d => d !== domain);
        await saveConfig();
        renderConfig();
    };

    window.addCustomMapping = async () => {
        const domainInput = document.getElementById('custom-map-domain');
        const ipInput = document.getElementById('custom-map-ip');
        const domain = domainInput.value.trim();
        const ip = ipInput.value.trim();

        if (!domain || !ip) {
            await showAlert('Both domain and IP address are required.');
            return;
        }

        try {
            const resp = await fetch('/api/rules/add', {
                method: 'POST',
                body: JSON.stringify({ domain, type: 'mapping', ip })
            });

            if (resp.ok) {
                domainInput.value = '';
                ipInput.value = '';
                fetchConfig(); // Refresh full config to get updated mappings
            } else {
                const err = await resp.text();
                await showAlert('Failed to add mapping: ' + err);
            }
        } catch (e) {
            await showAlert('Connection error.');
        }
    };

    window.removeCustomMapping = async (domain) => {
        if (!(await showConfirm(`Are you sure you want to remove the mapping for ${domain}?`))) return;
        
        try {
            const resp = await fetch('/api/rules/remove', {
                method: 'POST',
                body: JSON.stringify({ domain })
            });

            if (resp.ok) {
                fetchConfig();
            } else {
                await showAlert('Failed to remove mapping.');
            }
        } catch (e) {
            await showAlert('Connection error.');
        }
    };

    const createListItem = (list, index, type) => {
        const item = document.createElement('div');
        item.className = 'list-item';
        item.setAttribute('data-index', index);
        item.setAttribute('data-type', type);
        const isOfficial = (list.url && list.url.startsWith('file:///')) || (list.url && list.url.includes('FaserF/ShieldDNS'));
        item.innerHTML = `
            <div class="list-info">
                <h3>${list.name} ${isOfficial ? '<span class="badge official">Official</span>' : ''}</h3>
                ${list.category ? `<span class="badge secondary" style="font-size: 0.7rem;">${list.category}</span>` : ''}
                <p style="word-break: break-all; opacity: 0.7; font-size: 0.85rem; margin-top: 5px;">${list.url}</p>
            </div>
            <div class="list-actions">
                <button class="btn btn-sm secondary" onclick="event.stopPropagation(); toggleList(${index}, '${type}')">${list.enabled ? 'Disable' : 'Enable'}</button>
                ${isOfficial ? '' : `<button class="btn btn-sm danger" onclick="event.stopPropagation(); removeList(${index}, '${type}')"><i class="fas fa-trash"></i></button>`}
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
        currentConfig.sign_mobileconfig = signMobileConfigCheck?.checked || false;
        currentConfig.admin_domain = adminDomainInput?.value.trim() || '';
        currentConfig.block_page_ip = blockIpInput?.value.trim() || '';

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

    document.getElementById('apply-recommended-btn')?.addEventListener('click', async () => {
        if (await showConfirm('This will add a set of recommended, non-redundant blocklists and allowlists for privacy and performance. Continue?')) {
            await applyRecommendedFilters();
        }
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

    document.getElementById('latency-interval-input')?.addEventListener('change', (e) => {
        currentConfig.latency_test_interval = parseInt(e.target.value);
        saveConfig();
    });

    document.getElementById('smart-selection-policy-input')?.addEventListener('change', (e) => {
        currentConfig.smart_selection_policy = e.target.value;
        saveConfig();
    });

    document.getElementById('diagnostics-interval-input')?.addEventListener('change', (e) => {
        currentConfig.diagnostics_refresh_interval = parseInt(e.target.value);
        saveConfig();
        if (document.querySelector('.nav-item.active[data-view="diagnostics"]')) {
            startDiagTimer();
        }
    });

    document.getElementById('serve-stale-check')?.addEventListener('change', (e) => {
        currentConfig.serve_stale = e.target.checked;
        saveConfig();
    });

    document.getElementById('dnssec-check')?.addEventListener('change', (e) => {
        currentConfig.dnssec_enabled = e.target.checked;
        saveConfig();
    });

    document.getElementById('sign-mobileconfig-check')?.addEventListener('change', (e) => {
        currentConfig.sign_mobileconfig = e.target.checked;
        saveConfig();
    });

    document.getElementById('debug-mode-check')?.addEventListener('change', (e) => {
        currentConfig.debug_mode = e.target.checked;
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
    
    const fetchClientAliases = async () => {
        try {
            const resp = await fetch('/api/client/alias');
            if (resp.ok) clientAliases = await resp.json();
        } catch (e) {}
    };
    fetchClientAliases();

    // Domain Detail Modal Listeners
    const domainModal = document.getElementById('domain-info-modal');
    document.getElementById('domain-info-close-btn')?.addEventListener('click', () => domainModal.classList.add('hidden'));
    document.getElementById('domain-info-done-btn')?.addEventListener('click', () => domainModal.classList.add('hidden'));
    document.getElementById('domain-info-view-logs-btn')?.addEventListener('click', () => {
        const domain = document.getElementById('domain-info-subtitle').textContent;
        domainModal.classList.add('hidden');
        const queryNavItem = document.querySelector('.nav-item[data-view="queries"]');
        if (queryNavItem) queryNavItem.click();
        const searchInput = document.getElementById('query-search');
        if (searchInput) {
            searchInput.value = domain;
            fetchQueries();
        }
    });

    document.getElementById('modal-domain-block-btn')?.addEventListener('click', async () => {
        const domain = document.getElementById('domain-info-subtitle').textContent;
        const currentStatus = document.getElementById('domain-status-badge').textContent;
        const isCurrentlyBlocked = currentStatus.includes('Blocked');
        
        const action = isCurrentlyBlocked ? 'allowed' : 'blocked';
        await addCustomRule(action, domain);
        // Refresh modal status after rule change
        showDomainDetails(domain);
    });

    // IP Detail Modal Listeners
    const ipModal = document.getElementById('ip-info-modal');
    document.getElementById('ip-info-close-btn')?.addEventListener('click', () => ipModal.classList.add('hidden'));
    document.getElementById('ip-info-done-btn')?.addEventListener('click', () => ipModal.classList.add('hidden'));
    document.getElementById('ip-info-view-all-btn')?.addEventListener('click', () => {
        const title = document.getElementById('ip-info-title').textContent;
        const ip = document.getElementById('ip-info-subtitle').textContent;
        ipModal.classList.add('hidden');
        
        // Switch to queries view
        const queryNavItem = document.querySelector('.nav-item[data-view="queries"]');
        if (queryNavItem) queryNavItem.click();
        
        // Apply filter
        const searchInput = document.getElementById('query-search');
        if (searchInput) {
            searchInput.value = ip;
            fetchQueries();
        }
    });

    const editAliasBtn = document.getElementById('edit-alias-btn');
    const aliasEditBox = document.getElementById('alias-edit-box');
    const aliasInput = document.getElementById('client-alias-input');
    const saveAliasBtn = document.getElementById('save-alias-btn');

    editAliasBtn?.addEventListener('click', () => {
        aliasEditBox.classList.toggle('hidden');
        if (!aliasEditBox.classList.contains('hidden')) {
            const ip = document.getElementById('ip-info-subtitle').textContent;
            aliasInput.value = clientAliases[ip] || '';
            aliasInput.focus();
        }
    });

    saveAliasBtn?.addEventListener('click', async () => {
        const ip = document.getElementById('ip-info-subtitle').textContent;
        const alias = aliasInput.value.trim();
        
        try {
            const resp = await fetch('/api/client/alias', {
                method: 'POST',
                body: JSON.stringify({ ip, alias })
            });
            if (resp.ok) {
                clientAliases[ip] = alias;
                document.getElementById('ip-info-title').textContent = alias || 'Client Details';
                aliasEditBox.classList.add('hidden');
                // Refresh top clients list if visible to show new alias
                if (document.querySelector('.nav-item.active[data-view="dashboard"]')) {
                    fetchStats();
                }
            }
        } catch (e) {
            console.error('Failed to save alias', e);
        }
    });

    window.showIPDetails = async (ip) => {
        if (!ip || ip === 'Unknown') return;
        
        const modal = document.getElementById('ip-info-modal');
        const title = document.getElementById('ip-info-title');
        const subtitle = document.getElementById('ip-info-subtitle');
        const aliasBox = document.getElementById('alias-edit-box');
        
        title.textContent = clientAliases[ip] || 'Client Details';
        subtitle.textContent = ip;
        aliasBox.classList.add('hidden');
        modal.classList.remove('hidden');

        // Reset fields
        document.getElementById('ip-info-total').textContent = '...';
        document.getElementById('ip-info-blocked').textContent = '...';
        document.getElementById('ip-info-blocked-bar').style.width = '0%';
        document.getElementById('ip-info-hostname').textContent = '...';
        document.getElementById('ip-info-type-tag').textContent = '...';
        document.getElementById('ip-info-type-tag').className = 'badge';
        document.getElementById('ip-info-manufacturer').textContent = '-';
        document.getElementById('ip-info-mac').textContent = '-';
        document.getElementById('ip-info-country').textContent = '-';
        document.getElementById('ip-info-city').textContent = '-';
        document.getElementById('ip-info-flag').innerHTML = '';
        document.getElementById('ip-info-top-domains').innerHTML = '<tr><td colspan="2" class="help">Loading...</td></tr>';
        document.getElementById('ip-info-top-blocked').innerHTML = '<tr><td colspan="2" class="help">Loading...</td></tr>';
        document.getElementById('ip-info-history').innerHTML = '<tr><td colspan="3" class="help">Loading...</td></tr>';

        // Initialize/Clear Chart
        if (clientChart) {
            clientChart.destroy();
            clientChart = null;
        }

        try {
            // Fetch IP Info (Geo, Hostname, MAC)
            fetch(`/api/ip-info?ip=${ip}`).then(r => r.json()).then(data => {
                const typeTag = document.getElementById('ip-info-type-tag');
                typeTag.textContent = data.is_private ? 'Local Network' : 'Public IP';
                typeTag.classList.remove('local', 'public');
                typeTag.classList.add(data.is_private ? 'local' : 'public');
                
                document.getElementById('ip-info-hostname').textContent = data.hostname || (data.is_private ? 'Local Device' : 'Cloud/Public');
                
                let provider = data.isp || (data.is_private ? 'Unknown' : 'Public Provider');
                let manufacturer = data.manufacturer || (data.is_private ? 'Unknown' : provider);
                
                let deviceText = manufacturer;
                if (data.os) {
                    deviceText = `${data.os} (${manufacturer})`;
                }
                
                document.getElementById('ip-info-manufacturer').textContent = deviceText;
                document.getElementById('ip-info-manufacturer').title = data.user_agent || '';
                
                // If it's a public IP and we have a specific ISP, show it in hostname or as a separate info
                if (!data.is_private && data.isp) {
                    // Update hostname to include ISP if generic
                    if (!data.hostname) {
                        document.getElementById('ip-info-hostname').textContent = data.isp;
                    }
                }

                if (data.is_private) {
                    document.getElementById('ip-info-mac').textContent = data.mac || 'MAC Not Available';
                    document.getElementById('ip-info-country').textContent = 'Local';
                    document.getElementById('ip-info-city').textContent = 'N/A';
                    document.getElementById('ip-info-flag').innerHTML = '🏠';
                } else {
                    document.getElementById('ip-info-mac').textContent = 'N/A';
                    document.getElementById('ip-info-country').textContent = data.country || 'Unknown';
                    document.getElementById('ip-info-city').textContent = data.city || 'Unknown';
                    if (data.country_code) {
                        document.getElementById('ip-info-flag').innerHTML = `<img src="https://flagcdn.com/w20/${data.country_code.toLowerCase()}.png" style="vertical-align: middle; border-radius: 2px;">`;
                    } else {
                        document.getElementById('ip-info-flag').innerHTML = '🌐';
                    }
                }
            });

            // Fetch Enhanced Stats (includes Timeline)
            fetch(`/api/client/stats?ip=${ip}`).then(r => r.json()).then(data => {
                document.getElementById('ip-info-total').textContent = data.total.toLocaleString();
                document.getElementById('ip-info-blocked').textContent = data.blocked.toLocaleString();
                
                const ratio = data.total > 0 ? (data.blocked / data.total) * 100 : 0;
                document.getElementById('ip-info-blocked-bar').style.width = ratio + '%';

                // Render Sparkline Timeline
                const ctx = document.getElementById('ip-info-chart').getContext('2d');
                clientChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: Array(24).fill(''),
                        datasets: [{
                            data: data.timeline.map(h => h.total),
                            borderColor: '#5c6bc0',
                            backgroundColor: 'rgba(92, 107, 192, 0.1)',
                            fill: true,
                            tension: 0.4,
                            pointRadius: 0,
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false }, tooltip: { enabled: false } },
                        scales: {
                            x: { display: false },
                            y: { display: false, beginAtZero: true }
                        }
                    }
                });
            });

            // Fetch Top Domains (Allowed)
            fetch(`/api/client/top-domains?ip=${ip}`).then(r => r.json()).then(domains => {
                const container = document.getElementById('ip-info-top-domains');
                container.innerHTML = (domains || []).map(d => `
                    <tr>
                        <td class="truncate" style="max-width: 154px;"><span class="domain-link" onclick="showDomainDetails('${d.domain}')">${d.domain}</span></td>
                        <td style="text-align:right">${d.count}</td>
                    </tr>
                `).join('') || '<tr><td colspan="2" class="help">No data</td></tr>';
            });

            // Fetch Top Blocked Domains
            fetch(`/api/client/top-blocked?ip=${ip}`).then(r => r.json()).then(domains => {
                const container = document.getElementById('ip-info-top-blocked');
                container.innerHTML = (domains || []).map(d => `
                    <tr>
                        <td class="truncate" style="max-width: 154px; color: var(--danger);"><span class="domain-link" onclick="showDomainDetails('${d.domain}')">${d.domain}</span></td>
                        <td style="text-align:right">${d.count}</td>
                    </tr>
                `).join('') || '<tr><td colspan="2" class="help">No blocked domains</td></tr>';
            });

            // Fetch Recent History
            fetch(`/api/queries?client_ip=${ip}&limit=20`).then(r => r.json()).then(queries => {
                const container = document.getElementById('ip-info-history');
                container.innerHTML = (queries || []).map(q => {
                    const time = new Date(q.time).toLocaleTimeString();
                    return `
                        <tr>
                            <td>${time}</td>
                            <td class="truncate" style="max-width: 150px;"><span class="domain-link" onclick="showDomainDetails('${q.domain}')" title="${q.domain}">${q.domain}</span></td>
                            <td><span class="status-badge ${q.status.toLowerCase()}">${q.status}</span></td>
                        </tr>
                    `;
                }).join('') || '<tr><td colspan="3" class="help">No recent activity</td></tr>';
            });

        } catch (e) {
            console.error('Failed to fetch client details', e);
        }
    };

    window.showDomainDetails = async (domain) => {
        if (!domain) return;
        
        const modal = document.getElementById('domain-info-modal');
        const subtitle = document.getElementById('domain-info-subtitle');
        const statusBadge = document.getElementById('domain-status-badge');
        const blockBtn = document.getElementById('modal-domain-block-btn');
        
        subtitle.textContent = domain;
        modal.classList.remove('hidden');

        // Reset fields
        document.getElementById('domain-info-total').textContent = '...';
        document.getElementById('domain-info-blocked').textContent = '...';
        document.getElementById('domain-info-clients').textContent = '...';
        document.getElementById('domain-info-ratio').textContent = '...';
        document.getElementById('domain-info-clients-list').innerHTML = '<tr><td colspan="2" class="help">Loading...</td></tr>';
        document.getElementById('domain-info-history').innerHTML = '<tr><td colspan="3" class="help">Loading...</td></tr>';

        try {
            // Check if blocked
            const searchResp = await fetch(`/api/search?q=${domain}`);
            const searchData = await searchResp.json();
            
            if (searchData.blocked) {
                statusBadge.textContent = 'Blocked';
                statusBadge.className = 'badge danger';
                blockBtn.textContent = 'Unblock Domain';
                blockBtn.className = 'btn btn-sm success';
            } else {
                statusBadge.textContent = 'Allowed';
                statusBadge.className = 'badge success';
                blockBtn.textContent = 'Block Domain';
                blockBtn.className = 'btn btn-sm danger';
            }

            // Fetch Domain Stats
            fetch(`/api/domain/stats?domain=${domain}`).then(r => r.json()).then(data => {
                document.getElementById('domain-info-total').textContent = (data.total || 0).toLocaleString();
                document.getElementById('domain-info-blocked').textContent = (data.blocked || 0).toLocaleString();
                document.getElementById('domain-info-clients').textContent = (data.clients_count || 0).toLocaleString();
                const ratio = data.total > 0 ? ((data.blocked / data.total) * 100).toFixed(1) : '0';
                document.getElementById('domain-info-ratio').textContent = `${ratio}%`;
            });

            // Fetch Top Clients
            fetch(`/api/domain/clients?domain=${domain}`).then(r => r.json()).then(clients => {
                const container = document.getElementById('domain-info-clients-list');
                container.innerHTML = (clients || []).map(c => `
                    <tr>
                        <td><span class="ip-link" onclick="showIPDetails('${c.ip}')">${clientAliases[c.ip] || c.ip}</span></td>
                        <td style="text-align:right">${c.count}</td>
                    </tr>
                `).join('') || '<tr><td colspan="2" class="help">No queries recorded.</td></tr>';
            });

            // Fetch History
            fetch(`/api/queries?search=${domain}&limit=15`).then(r => r.json()).then(queries => {
                const container = document.getElementById('domain-info-history');
                container.innerHTML = (queries || []).map(q => {
                    const time = new Date(q.time).toLocaleTimeString();
                    return `
                        <tr>
                            <td>${time}</td>
                            <td><span class="ip-link" onclick="showIPDetails('${q.client_ip}')">${clientAliases[q.client_ip] || q.client_ip}</span></td>
                            <td><span class="status-badge ${q.status.toLowerCase()}">${q.status}</span></td>
                        </tr>
                    `;
                }).join('') || '<tr><td colspan="3" class="help">No recent activity.</td></tr>';
            });

        } catch (e) {
            console.error('Failed to fetch domain details', e);
        }
    };

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

window.applyRecommendedFilters = async () => {
    const recommendedBlock = [
        { name: 'OISD Basic', url: 'https://big.oisd.nl/basic', category: 'Privacy' },
        { name: 'Steven Black Unified', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', category: 'Ads/Malware' },
        { name: 'HaGeZi Multi Light', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt', category: 'Ads/Trackers (DE Focus)' },
        { name: 'AdGuard DNS Filter', url: 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt', category: 'Ads' }
    ];

    const recommendedAllow = [
        { name: 'Apple Services', url: 'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/apple.txt', category: 'Services' },
        { name: 'Microsoft Services', url: 'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/microsoft.txt', category: 'Services' },
        { name: 'Google Services', url: 'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/google.txt', category: 'Services' },
        { name: 'WhatsApp', url: 'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whatsapp.txt', category: 'Messaging' },
        { name: 'Facebook Services', url: 'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/facebook.txt', category: 'Social' }
    ];

    let addedCount = 0;
    
    recommendedBlock.forEach(rec => {
        if (!currentConfig.lists.some(l => l.url === rec.url)) {
            currentConfig.lists.push({ ...rec, enabled: true });
            addedCount++;
        }
    });

    recommendedAllow.forEach(rec => {
        if (!currentConfig.allowlists.some(l => l.url === rec.url)) {
            currentConfig.allowlists.push({ ...rec, enabled: true });
            addedCount++;
        }
    });

    if (addedCount > 0) {
        await saveConfig();
        renderConfig();
        await showAlert(`Successfully added ${addedCount} recommended lists!`);
    } else {
        await showAlert('All recommended lists are already in your configuration.');
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
