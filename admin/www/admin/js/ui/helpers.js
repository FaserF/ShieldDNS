/**
 * UI Helpers - Formatting, Modals, and DOM manipulation helpers
 */

export const formatDate = (dateString) => {
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

export const formatUptime = (seconds) => {
    const d = Math.floor(seconds / (3600 * 24));
    const h = Math.floor((seconds % (3600 * 24)) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    
    if (d > 0) return `${d}d ${h}h ${m}m ${s}s`;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    return `${m}m ${s}s`;
};

export const showAlert = (msg) => {
    return new Promise(resolve => {
        const modal = document.getElementById('alert-modal');
        const msgEl = document.getElementById('alert-message');
        const okBtn = document.getElementById('alert-ok');
        if (modal && msgEl && okBtn) {
            msgEl.textContent = msg;
            modal.classList.remove('hidden');
            okBtn.onclick = () => {
                modal.classList.add('hidden');
                resolve();
            };
        } else {
            alert(msg);
            resolve();
        }
    });
};

export const showConfirm = (msg) => {
    return new Promise(resolve => {
        const modal = document.getElementById('confirm-modal');
        const msgEl = document.getElementById('confirm-message');
        const okBtn = document.getElementById('confirm-yes');
        const cancelBtn = document.getElementById('confirm-no');
        if (modal && msgEl && okBtn && cancelBtn) {
            msgEl.textContent = msg;
            modal.classList.remove('hidden');
            okBtn.onclick = () => {
                modal.classList.add('hidden');
                resolve(true);
            };
            cancelBtn.onclick = () => {
                modal.classList.add('hidden');
                resolve(false);
            };
        } else {
            resolve(confirm(msg));
        }
    });
};

export const createGradient = (ctx, color) => {
    const gradient = ctx.createLinearGradient(0, 0, 0, 400);
    gradient.addColorStop(0, color.replace('1)', '0.4)'));
    gradient.addColorStop(1, color.replace('1)', '0)'));
    return gradient;
};
