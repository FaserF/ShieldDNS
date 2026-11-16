/**
 * Global Simple vs. Advanced UI Mode Controller
 * Persists user preference in localStorage and toggles body classes for adaptive complexity.
 */

const MODE_STORAGE_KEY = 'shielddns_ui_mode';

export function getUIMode() {
    try {
        return localStorage.getItem(MODE_STORAGE_KEY) === 'advanced' ? 'advanced' : 'simple';
    } catch {
        return 'simple';
    }
}

export function applyUIMode(mode) {
    const normalized = mode === 'advanced' ? 'advanced' : 'simple';
    document.body.classList.remove('mode-simple', 'mode-advanced');
    document.body.classList.add(`mode-${normalized}`);

    const btn = document.getElementById('ui-mode-toggle');
    if (btn) {
        const isAdv = normalized === 'advanced';
        btn.innerHTML = isAdv ?
            '<i class="fas fa-sliders-h"></i> <span>Advanced Mode</span>' :
            '<i class="fas fa-magic"></i> <span>Simple Mode</span>';
        btn.title = isAdv ?
            'Switch to Simple Mode (hides technical parameters)' :
            'Switch to Advanced Mode (unlocks full DNS/cluster/regex controls)';
        btn.classList.toggle('active', isAdv);
    }
}

export function setUIMode(mode) {
    const normalized = mode === 'advanced' ? 'advanced' : 'simple';
    try {
        localStorage.setItem(MODE_STORAGE_KEY, normalized);
    } catch {
        // Ignore storage errors in private browsing
    }
    applyUIMode(normalized);
}

export function toggleUIMode() {
    const next = getUIMode() === 'advanced' ? 'simple' : 'advanced';
    setUIMode(next);
    return next;
}

export function initUIMode() {
    applyUIMode(getUIMode());
    const btn = document.getElementById('ui-mode-toggle');
    if (btn) {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            toggleUIMode();
        });
    }
}
