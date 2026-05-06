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

export const showAlert = (msg, title = 'Notification') => {
    return new Promise(resolve => {
        const modal = document.getElementById('alert-modal');
        const titleEl = document.getElementById('alert-title');
        const msgEl = document.getElementById('alert-message');
        const okBtn = document.getElementById('alert-ok');
        
        if (modal && msgEl && okBtn) {
            if (titleEl) titleEl.textContent = title;
            msgEl.textContent = msg;
            modal.classList.remove('hidden');
            
            const close = () => {
                modal.classList.add('hidden');
                window.removeEventListener('keydown', escListener);
                resolve();
            };
            
            const escListener = (e) => { if (e.key === 'Escape') close(); };
            window.addEventListener('keydown', escListener);
            okBtn.onclick = close;
        } else {
            alert(msg);
            resolve();
        }
    });
};

export const showConfirm = (msg, title = 'Confirmation', isDanger = false) => {
    return new Promise(resolve => {
        const modal = document.getElementById('confirm-modal');
        const titleEl = document.getElementById('confirm-title');
        const msgEl = document.getElementById('confirm-message');
        const okBtn = document.getElementById('confirm-yes');
        const cancelBtn = document.getElementById('confirm-cancel');
        
        if (modal && msgEl && okBtn && cancelBtn) {
            if (titleEl) titleEl.textContent = title;
            msgEl.textContent = msg;
            
            // Apply danger styling if requested
            if (isDanger) {
                modal.classList.add('danger');
                okBtn.classList.remove('primary');
                okBtn.classList.add('danger');
            } else {
                modal.classList.remove('danger');
                okBtn.classList.remove('danger');
                okBtn.classList.add('primary');
            }

            modal.classList.remove('hidden');
            
            const handle = (result) => {
                modal.classList.add('hidden');
                window.removeEventListener('keydown', escListener);
                resolve(result);
            };
            
            const escListener = (e) => { if (e.key === 'Escape') handle(false); };
            window.addEventListener('keydown', escListener);
            
            okBtn.onclick = () => handle(true);
            cancelBtn.onclick = () => handle(false);
            modal.onclick = (e) => { if (e.target === modal) handle(false); };
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

const btnOriginalNodes = new WeakMap();

export const setBtnLoading = (btn, isLoading, customText = null) => {
    if (!btn) return;
    if (isLoading) {
        if (!btnOriginalNodes.has(btn)) {
            // Save original nodes instead of innerHTML to prevent XSS warnings
            btnOriginalNodes.set(btn, Array.from(btn.childNodes));
        }
        btn.disabled = true;
        btn.textContent = '';
        
        const icon = document.createElement('i');
        icon.className = 'fas fa-spinner fa-spin';
        
        const textNode = document.createTextNode(' ' + (customText || 'Processing...'));
        
        btn.appendChild(icon);
        btn.appendChild(textNode);
    } else {
        const nodes = btnOriginalNodes.get(btn);
        if (nodes) {
            btn.textContent = '';
            nodes.forEach(n => btn.appendChild(n));
            btnOriginalNodes.delete(btn);
        }
        btn.disabled = false;
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
        <span>${escapeHTML(message)}</span>
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

/**
 * Animates a numeric value from its current state to a target value
 * Optimized for high-refresh-rate displays
 */
export const countTo = (element, targetValue, duration = 800, suffix = '', precision = 0) => {
    if (!element) return;
    
    // Parse current value or default to 0
    let startValue = parseFloat(element.textContent.replace(/[^0-9.-]+/g, "")) || 0;
    
    // Don't animate if the value hasn't changed enough
    if (Math.abs(startValue - targetValue) < 0.1) {
        element.textContent = targetValue.toLocaleString() + suffix;
        return;
    }

    const startTime = performance.now();
    
    const update = (now) => {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Ease out quadratic
        const ease = 1 - (1 - progress) * (1 - progress);
        
        const current = startValue + (targetValue - startValue) * ease;
        
        // Use integer or fixed precision depending on input
        if (precision === 0 && Number.isInteger(targetValue)) {
            element.textContent = Math.round(current).toLocaleString() + suffix;
        } else {
            element.textContent = current.toFixed(precision).toLocaleString() + suffix;
        }
        
        if (progress < 1) {
            requestAnimationFrame(update);
        } else {
            element.textContent = targetValue.toLocaleString(undefined, {
                minimumFractionDigits: precision,
                maximumFractionDigits: precision
            }) + suffix;
        }
    };
    
    requestAnimationFrame(update);
};

/**
 * Escapes HTML special characters to prevent XSS
 * @param {string} str - The string to escape
 * @returns {string} - The escaped string
 */
export const escapeHTML = (str) => {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
};

/**
 * Checks if a query matches the current UI filters (search and status)
 * @param {Object} query - The query object from the backend
 * @returns {boolean} - True if the query should be displayed
 */
export const matchesFilters = (query) => {
    const searchInput = document.getElementById('query-search');
    const statusSelect = document.getElementById('query-filter-status');
    
    if (!searchInput || !statusSelect) return true;
    
    const search = searchInput.value.trim().toLowerCase();
    const status = statusSelect.value;
    
    // Check search (domain or IP)
    if (search) {
        const matchesDomain = (query.domain || '').toLowerCase().includes(search);
        const matchesIp = (query.client_ip || '').toLowerCase().includes(search);
        if (!matchesDomain && !matchesIp) return false;
    }
    
    // Check status
    if (status) {
        const queryStatus = query.status || '';
        if (status === 'Blocked' && !queryStatus.includes('Blocked')) return false;
        if (status === 'Allowed' && queryStatus !== 'Allowed') return false;
    }
    
    // Check time range
    const fromTime = document.getElementById('query-time-from')?.value;
    const toTime = document.getElementById('query-time-to')?.value;
    
    if (fromTime || toTime) {
        const queryTime = new Date(query.time);
        if (fromTime && queryTime < new Date(fromTime)) return false;
        if (toTime && queryTime > new Date(toTime)) return false;
    }
    
    return true;
};
