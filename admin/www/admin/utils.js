/**
 * ShieldDNS Admin UI Utilities
 */

// UI Alert Modal
async function showAlert(message, title = 'Notification') {
    return new Promise((resolve) => {
        const modal = document.getElementById('alert-modal');
        const titleEl = document.getElementById('alert-title');
        const messageEl = document.getElementById('alert-message');
        const okBtn = document.getElementById('alert-ok');

        if (!modal || !titleEl || !messageEl || !okBtn) {
            alert(message);
            resolve();
            return;
        }

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

// UI Confirmation Modal
async function showConfirm(message, title = 'Confirmation') {
    return new Promise((resolve) => {
        const modal = document.getElementById('confirm-modal');
        const titleEl = document.getElementById('confirm-title');
        const messageEl = document.getElementById('confirm-message');
        const yesBtn = document.getElementById('confirm-yes');
        const noBtn = document.getElementById('confirm-cancel');

        if (!modal || !titleEl || !messageEl || !yesBtn || !noBtn) {
            resolve(confirm(message));
            return;
        }

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

// Debounce helper
function debounce(func, wait) {
    let timeout;
    return (...args) => {
        clearTimeout(timeout);
        timeout = setTimeout(() => func(...args), wait);
    };
}

// Copy text to clipboard helper
async function copyText(id) {
    const input = document.getElementById(id);
    if (!input) return;
    const textToCopy = input.value !== undefined ? input.value : input.textContent;
    let success = false;

    if (navigator.clipboard && window.isSecureContext) {
        try {
            await navigator.clipboard.writeText(textToCopy);
            success = true;
        } catch (err) {
            console.warn('navigator.clipboard failed, attempting fallback...', err);
        }
    }

    if (!success) {
        try {
            const textarea = document.createElement('textarea');
            textarea.value = textToCopy;
            textarea.style.position = 'fixed';
            textarea.style.top = '0';
            textarea.style.left = '0';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.focus();
            textarea.select();
            success = document.execCommand('copy');
            document.body.removeChild(textarea);
        } catch (err) {
            console.error('Failed to copy text: ', err);
        }
    }

    if (success) {
        const btn = input.nextElementSibling;
        if (btn && btn.tagName === 'BUTTON') {
            const originalText = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(() => btn.textContent = originalText, 2000);
        }
    }
}

// Export logs helper
function exportLogs(format) {
    window.location.href = `/api/export?format=${format}`;
}

// Color Palette for charts
const DNS_TYPE_COLORS = {
    'A': '#3b82f6',      // blue
    'AAAA': '#10b981',   // emerald
    'HTTPS': '#8b5cf6',  // purple
    'TXT': '#f59e0b',    // orange
    'SRV': '#ec4899',    // pink
    'PTR': '#06b6d4',    // cyan
    'MX': '#ef4444',     // red
    'ANY': '#64748b'     // slate
};

// Global exports for window scope
window.showAlert = showAlert;
window.showConfirm = showConfirm;
window.debounce = debounce;
window.copyText = copyText;
window.exportLogs = exportLogs;
window.DNS_TYPE_COLORS = DNS_TYPE_COLORS;
