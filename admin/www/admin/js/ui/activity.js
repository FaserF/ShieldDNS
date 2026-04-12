/**
 * System Activity Overlay - Provides live feedback during long-running tasks
 */
import { getEl } from '../core/state.js';

let logSource = null;
let isOverlayVisible = false;

export const showActivityOverlay = (title, description) => {
    const modal = getEl('activity-modal');
    const titleEl = getEl('activity-title');
    const descEl = getEl('activity-desc');
    const logContainer = getEl('activity-log-stream');
    const closeBtn = getEl('activity-close-btn');

    if (!modal || !titleEl || !descEl || !logContainer) return;

    titleEl.textContent = title;
    descEl.textContent = description;
    logContainer.innerHTML = '';
    modal.classList.remove('hidden');
    if (closeBtn) closeBtn.classList.add('hidden'); // Hide close button initially
    isOverlayVisible = true;

    // Connect to system logs SSE if not already connected
    startLogStream(logContainer);
};

export const hideActivityOverlay = (success = true) => {
    const modal = getEl('activity-modal');
    const descEl = getEl('activity-desc');
    const closeBtn = getEl('activity-close-btn');

    if (!modal) return;

    if (success) {
        if (descEl) descEl.innerHTML = '<span class="success-text"><i class="fas fa-check-circle"></i> Operation completed successfully!</span>';
        setTimeout(() => {
            if (isOverlayVisible) {
                modal.classList.add('hidden');
                isOverlayVisible = false;
                stopLogStream();
            }
        }, 3000);
    } else {
        if (descEl) descEl.innerHTML = '<span class="danger-text"><i class="fas fa-exclamation-triangle"></i> Operation failed. Check logs below.</span>';
        if (closeBtn) {
            closeBtn.classList.remove('hidden');
            closeBtn.onclick = () => {
                modal.classList.add('hidden');
                isOverlayVisible = false;
                stopLogStream();
            };
        }
    }
};

const startLogStream = (container) => {
    if (logSource) return;

    logSource = new EventSource('/api/system-logs');
    let pendingLines = [];
    let rafScheduled = false;

    const flushPendingLines = () => {
        rafScheduled = false;
        if (!container || pendingLines.length === 0) return;

        const fragment = document.createDocumentFragment();
        for (const { msg, isError, isWarn } of pendingLines) {
            const line = document.createElement('div');
            line.className = 'log-line';
            if (isError) line.classList.add('error');
            if (isWarn) line.classList.add('warn');
            line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
            fragment.appendChild(line);
        }
        pendingLines = [];
        container.appendChild(fragment);
        container.scrollTop = container.scrollHeight;

        // Keep only last 100 lines
        while (container.childNodes.length > 100) {
            container.removeChild(container.firstChild);
        }
    };

    logSource.onmessage = (event) => {
        if (!container) return;
        
        const filter = getEl('activity-log-filter')?.value || 'ALL';
        const msg = event.data;
        const isError = msg.includes('[ERROR]');
        const isWarn = msg.includes('[WARN]');

        if (filter === 'ERROR' && !isError) return;
        if (filter === 'WARN' && !isError && !isWarn) return;

        pendingLines.push({ msg, isError, isWarn });

        if (!rafScheduled) {
            rafScheduled = true;
            requestAnimationFrame(flushPendingLines);
        }
    };

    logSource.onerror = () => {
        stopLogStream();
    };
};

const stopLogStream = () => {
    if (logSource) {
        logSource.close();
        logSource = null;
    }
};
