document.addEventListener('DOMContentLoaded', () => {
    const navItems = document.querySelectorAll('.nav-item');
    const views = document.querySelectorAll('.view');
    const statsContainer = {
        total: document.getElementById('stat-total'),
        blocked: document.getElementById('stat-blocked'),
        ratio: document.getElementById('stat-ratio')
    };
    const upstreamsInput = document.getElementById('upstreams-input');
    const listItemsContainer = document.getElementById('list-items');

    const authOverlay = document.getElementById('auth-overlay');
    const setupView = document.getElementById('setup-view');
    const loginView = document.getElementById('login-view');

    let currentConfig = { upstreams: [], lists: [] };
    let trafficChart = null;

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
        const upstreams = document.getElementById('setup-upstreams').value.split(',').map(s => s.trim());
        
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
            body: JSON.stringify({ upstreams, lists: selectedPresets })
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
        fetchStats();
        fetchConfig();
        fetchPresets();
        fetchQueries();
        fetchHistory();
        setInterval(fetchStats, 10000);
        setInterval(fetchQueries, 5000);
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

    const fetchQueries = async () => {
        try {
            const resp = await fetch('/api/queries');
            if (resp.status === 401) return;
            const queries = await resp.json();
            renderQueries(queries);
        } catch (e) {
            console.error('Failed to fetch queries', e);
        }
    };

    const renderQueries = (queries) => {
        const container = document.getElementById('query-log-items');
        container.innerHTML = '';
        queries.forEach(q => {
            const row = document.createElement('tr');
            const time = new Date(q.time).toLocaleTimeString();
            row.innerHTML = `
                <td>${time}</td>
                <td>${q.domain}</td>
                <td>${q.type}</td>
                <td><span class="status-badge ${q.status.toLowerCase()}">${q.status}</span></td>
            `;
            container.appendChild(row);
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

    // Navigation logic
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const viewId = item.getAttribute('data-view');
            
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            views.forEach(v => {
                v.classList.toggle('hidden', v.id !== viewId);
            });
        });
    });

    const fetchStats = async () => {
        try {
            const resp = await fetch('/api/stats');
            if (resp.status === 401) return; // Not authorized yet
            const data = await resp.json();
            statsContainer.total.textContent = data.total_queries.toLocaleString();
            statsContainer.blocked.textContent = data.blocked_queries.toLocaleString();
            const ratio = data.total_queries > 0 ? (data.blocked_queries / data.total_queries * 100).toFixed(1) : 0;
            statsContainer.ratio.textContent = `${ratio} %`;
            
            // Update version
            const versionEl = document.getElementById('app-version');
            if (versionEl && data.version) {
                versionEl.textContent = data.version;
            }
        } catch (e) {
            console.error('Failed to fetch stats', e);
        }
    };

    const fetchConfig = async () => {
        try {
            const resp = await fetch('/api/config');
            if (resp.status === 401) return;
            currentConfig = await resp.json();
            renderConfig();
        } catch (e) {
            console.error('Failed to fetch config', e);
        }
    };

    const renderConfig = () => {
        upstreamsInput.value = currentConfig.upstreams.join(', ');
        listItemsContainer.innerHTML = '';
        currentConfig.lists.forEach((list, index) => {
            const item = document.createElement('div');
            item.className = 'list-item';
            item.innerHTML = `
                <div class="list-info">
                    <h3>${list.name}</h3>
                    <p>${list.url}</p>
                </div>
                <div class="list-actions">
                    <button class="btn secondary" onclick="toggleList(${index})">${list.enabled ? 'Disable' : 'Enable'}</button>
                    <button class="btn danger" onclick="removeList(${index})">Remove</button>
                </div>
            `;
            listItemsContainer.appendChild(item);
        });
    };

    const saveConfig = async () => {
        const upstreams = upstreamsInput.value.split(',').map(s => s.trim()).filter(s => s);
        currentConfig.upstreams = upstreams;

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

    // Modal logic for adding lists
    const modal = document.getElementById('modal');
    document.getElementById('add-list-btn')?.addEventListener('click', () => modal.classList.remove('hidden'));
    document.getElementById('modal-cancel')?.addEventListener('click', () => modal.classList.add('hidden'));
    
    document.getElementById('modal-confirm')?.addEventListener('click', () => {
        const name = document.getElementById('list-name').value;
        const url = document.getElementById('list-url').value;
        if (name && url) {
            currentConfig.lists.push({ name, url, enabled: true });
            saveConfig();
            modal.classList.add('hidden');
            renderConfig();
        }
    });

    document.getElementById('search-btn')?.addEventListener('click', async () => {
        const domain = document.getElementById('domain-search').value.trim();
        if (!domain) return;

        const resp = await fetch(`/api/search?q=${domain}`);
        const data = await resp.json();
        const result = document.getElementById('search-result');
        result.classList.remove('hidden', 'blocked', 'allowed');
        
        if (data.blocked) {
            result.textContent = `❌ ${domain} is CURRENTLY BLOCKED`;
            result.classList.add('blocked');
        } else {
            result.textContent = `✅ ${domain} is NOT BLOCKED`;
            result.classList.add('allowed');
        }
    });

    // Initial check
    checkAuthStatus();
});

window.toggleList = async (index) => {
    // Implementation needed
};
window.removeList = async (index) => {
    // Implementation needed
};

window.copyText = (id) => {
    const input = document.getElementById(id);
    input.select();
    document.execCommand('copy');
    const btn = input.nextElementSibling;
    const originalText = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = originalText, 2000);
};

// Auto-fill copy inputs based on current location
document.addEventListener('DOMContentLoaded', () => {
    const host = window.location.hostname;
    document.getElementById('copy-dot').value = host;
    document.getElementById('copy-doh').value = `https://${host}/dns-query`;
});
