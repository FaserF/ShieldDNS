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

/**
 * Enhanced UI Feedback
 */

export const setBtnLoading = (btn, isLoading, customText = null) => {
    if (!btn) return;
    if (isLoading) {
        btn.setAttribute('data-original-html', btn.innerHTML);
        btn.disabled = true;
        const text = customText || 'Processing...';
        btn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${text}`;
    } else {
        const original = btn.getAttribute('data-original-html');
        if (original) btn.innerHTML = original;
        btn.disabled = false;
        btn.removeAttribute('data-original-html');
    }
};

export const showToast = (message, type = 'success') => {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = `
            position: fixed;
            bottom: 30px;
            right: 30px;
            z-index: 9999;
            display: flex;
            flex-direction: column;
            gap: 12px;
            pointer-events: none;
        `;
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    const colors = {
        success: 'var(--success)',
        error: 'var(--danger)',
        info: 'var(--accent)'
    };
    const icons = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        info: 'fa-info-circle'
    };

    toast.style.cssText = `
        background: rgba(15, 23, 42, 0.95);
        backdrop-filter: blur(8px);
        color: white;
        padding: 14px 24px;
        border-radius: 12px;
        border-left: 4px solid ${colors[type] || colors.info};
        box-shadow: 0 10px 25px rgba(0,0,0,0.3);
        display: flex;
        align-items: center;
        gap: 12px;
        font-size: 0.9rem;
        font-weight: 500;
        transform: translateX(120%);
        transition: transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        pointer-events: auto;
    `;
    
    toast.innerHTML = `
        <i class="fas ${icons[type]} " style="color: ${colors[type]}"></i>
        <span>${message}</span>
    `;

    container.appendChild(toast);
    
    // Trigger animation
    setTimeout(() => toast.style.transform = 'translateX(0)', 10);
    
    const remove = () => {
        toast.style.transform = 'translateX(120%)';
        setTimeout(() => toast.remove(), 400);
    };

    setTimeout(remove, 4000);
    toast.onclick = remove;
};
