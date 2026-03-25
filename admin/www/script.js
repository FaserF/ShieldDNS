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

    document.getElementById('setup-confirm-btn').addEventListener('click', async () => {
        const password = document.getElementById('setup-password').value;
        const confirm = document.getElementById('setup-confirm').value;

        if (password.length < 12) {
            alert('Password must be at least 12 characters.');
            return;
        }
        if (password !== confirm) {
            alert('Passwords do not match.');
            return;
        }

        const resp = await fetch('/api/setup', {
            method: 'POST',
            body: JSON.stringify({ password })
        });

        if (resp.ok) {
            alert('Setup successful! Please login.');
            checkAuthStatus();
        } else {
            alert('Setup failed.');
        }
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
        setInterval(fetchStats, 10000);
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

    // Initial check
    checkAuthStatus();
});

window.toggleList = async (index) => {
    // Implementation needed
};
window.removeList = async (index) => {
    // Implementation needed
};
