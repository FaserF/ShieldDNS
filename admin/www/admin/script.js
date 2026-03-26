let currentConfig = { upstreams: [], upstream_dot: [], prefer_encrypted: true, lists: [], allowlists: [], custom_blocked: [], custom_allowed: [] };
    let trafficChart = null;
    let typeChart = null;
    
    // UI Elements
    let authOverlay, setupView, loginView, listItemsContainer, allowlistItemsContainer, views;
    let upstreamsInput, dotUpstreamsInput, preferEncryptedCheck, customBlockedList, customAllowedList;
    let systemLogTerminal, certInfoContent, statsContainer, topBlockedContainer, topClientsContainer;
    let queryLogItems, fullQueryLogItems;
    let systemLogEventSource = null;

document.addEventListener('DOMContentLoaded', () => {
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
        cache: getEl('stat-cache')
    };

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
        presets.forEach((p, i) => {
            const item = document.createElement('div');
            item.className = 'preset-selection-item';
            item.innerHTML = `
                <input type="checkbox" id="pre-${i}" value="${p.url}" checked>
                <label for="pre-${i}">${p.name}</label>
            `;
            container.appendChild(item);
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
            alert('Password too short!');
            nextSetupStep(1);
            return;
        }

        if (password !== confirm) {
            alert('Passwords do not match!');
            nextSetupStep(1);
            return;
        }

        // 1. Create Account
        const setupResp = await fetch('/api/setup', {
            method: 'POST',
            body: JSON.stringify({ password })
        });

        if (!setupResp.ok) {
            alert('Setup failed at account creation.');
            return;
        }

        // 2. Login to get session for config
        const loginResp = await fetch('/api/login', {
            method: 'POST',
            body: JSON.stringify({ password })
        });

        if (!loginResp.ok) {
            alert('Login failed during setup.');
            return;
        }

        // 3. Save Config (Upstreams + Selected Lists)
        await fetch('/api/config', {
            method: 'POST',
            body: JSON.stringify({ 
                upstreams, 
                upstream_dot: dotUpstreams, 
                prefer_encrypted: preferEncrypted, 
                lists: selectedPresets,
                allowlists: [
                    { name: "ShieldDNS Official Allowlist", url: "https://raw.githubusercontent.com/FaserF/ShieldDNS/main/official/allowlists/default.txt", enabled: true }
                ]
            })
        });

        alert('Setup complete! Welcome to ShieldDNS.');
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
            alert('Invalid password.');
        }
    });

    document.getElementById('logout-btn')?.addEventListener('click', async () => {
        await fetch('/api/logout', { method: 'POST' });
        location.reload();
    });

    document.getElementById('password-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const current = document.getElementById('current-password').value;
        const newPwd = document.getElementById('new-password').value;

        if (newPwd.length < 12) {
            alert('New password must be at least 12 characters.');
            return;
        }

        const resp = await fetch('/api/change-password', {
            method: 'POST',
            body: JSON.stringify({ current, new: newPwd })
        });

        if (resp.ok) {
            alert('Password changed successfully! Please login again.');
            location.reload();
        } else {
            const err = await resp.text();
            alert('Failed to change password: ' + err);
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
                row.innerHTML = `
                    <td>${time}</td>
                    <td title="${q.client_ip}">${q.domain}</td>
                    <td>${q.type}</td>
                    <td><span class="status-badge ${q.status.toLowerCase()}">${q.status}</span></td>
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
        row.innerHTML = `
            <td>${time}</td>
            <td title="${q.client_ip}">${q.domain}</td>
            <td>${q.type}</td>
            <td><span class="status-badge ${q.status.toLowerCase()}">${q.status}</span></td>
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

        const labels = Object.keys(queryTypes);
        const data = Object.values(queryTypes);

        if (typeChart) {
            typeChart.data.labels = labels;
            typeChart.data.datasets[0].data = data;
            typeChart.update();
            return;
        }

        typeChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: ['#5c6bc0', '#ef4444', '#10b981', '#f59e0b', '#6366f1', '#ec4899', '#8b5cf6'],
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
        presets.forEach(preset => {
            const card = document.createElement('div');
            card.className = 'preset-card';
            card.innerHTML = `
                <div class="preset-info">
                    <h3>${preset.name}</h3>
                </div>
                <button class="btn secondary" onclick="addPreset('${preset.name}', '${preset.url}')">Add</button>
            `;
            container.appendChild(card);
        });
    };

    window.addPreset = (name, url) => {
        if (currentConfig.lists.some(l => l.url === url)) {
            alert('This list is already added.');
            return;
        }
        currentConfig.lists.push({ name, url, enabled: true });
        saveConfig();
        renderConfig();
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
            e.preventDefault();
            const targetView = item.dataset.view;
            if (!targetView) return;

            navItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            
            views.forEach(v => v.classList.add('hidden'));
            const viewEl = document.getElementById(targetView);
            if (viewEl) viewEl.classList.remove('hidden');

            if (targetView === 'queries') fetchQueries();
            if (targetView === 'analytics') fetchAnalytics();
            if (targetView === 'about') fetchStats();
            if (targetView === 'diagnostics') fetchDiagnostics();
            if (targetView === 'system-logs') startSystemLogStream();
            else stopSystemLogStream();
        });
    });

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
            
            renderConfig();
        } catch (e) {
            console.error('Failed to fetch config', e);
        }
    };

    const renderConfig = () => {
        upstreamsInput.value = currentConfig.upstreams.join(', ');
        dotUpstreamsInput.value = (currentConfig.upstream_dot || []).join(', ');
        preferEncryptedCheck.checked = currentConfig.prefer_encrypted;
        
        const smartCheck = document.getElementById('smart-upstream-check');
        if (smartCheck) smartCheck.checked = currentConfig.use_fastest_upstream || false;
        
        const retentionInput = document.getElementById('retention-input');
        if (retentionInput) retentionInput.value = currentConfig.retention_days || 30;

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

    window.addCustomRule = (type) => {
        const input = document.getElementById(type === 'blocked' ? 'custom-block-input' : 'custom-allow-input');
        const domain = input.value.trim();
        if (!domain) return;
        
        const field = type === 'blocked' ? 'custom_blocked' : 'custom_allowed';
        if (!currentConfig[field]) currentConfig[field] = [];
        if (currentConfig[field].includes(domain)) {
            alert('This domain is already in the list.');
            return;
        }
        
        currentConfig[field].push(domain);
        input.value = '';
        saveConfig();
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

        await fetch('/api/config', {
            method: 'POST',
            body: JSON.stringify(currentConfig)
        });
        alert('Configuration saved!');
    };

    document.getElementById('settings-form')?.addEventListener('submit', (e) => {
        e.preventDefault();
        saveConfig();
    });

    document.getElementById('refresh-btn')?.addEventListener('click', async () => {
        await fetch('/api/refresh', { method: 'POST' });
        alert('Update started in background...');
    });

    document.getElementById('backup-btn')?.addEventListener('click', () => {
        window.location.href = '/api/backup';
    });

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
        if (name && url) {
            if (type === 'allow') {
                currentConfig.allowlists.push({ name, url, enabled: true });
            } else {
                currentConfig.lists.push({ name, url, enabled: true });
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
        
        certInfoContent.innerHTML = `
            <div class="diag-item"><span>Status</span><span class="badge ${data.is_expired ? 'danger' : 'official'}">${data.is_expired ? 'Expired' : 'Valid'}</span></div>
            <div class="diag-item"><span>Subject</span><span>${data.subject}</span></div>
            <div class="diag-item"><span>Issuer</span><span>${data.issuer}</span></div>
            <div class="diag-item"><span>Expires</span><span>${new Date(data.expires).toLocaleString()}</span></div>
            <div class="diag-item"><span>Not Before</span><span>${new Date(data.not_before).toLocaleString()}</span></div>
            <div class="diag-item"><span>SANs</span><div style="text-align:right">${data.dns_names.join('<br>')}</div></div>
        `;
    } catch (e) {
        certInfoContent.innerHTML = '<p class="danger-text">Failed to load certificate information.</p>';
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
    if (confirm('Are you sure you want to remove this list?')) {
        if (type === 'white') {
            currentConfig.whitelists.splice(index, 1);
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
