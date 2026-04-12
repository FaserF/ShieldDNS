/**
 * VirtualScroller Class - Handles high-performance rendering of large lists
 * Optimized for high-refresh-rate displays (120Hz, 144Hz, etc.)
 */
export class VirtualScroller {
    constructor(containerId, rowHeight, renderRow) {
        this.tbody = document.getElementById(containerId);
        if (!this.tbody) return;
        
        this.container = this.tbody.parentElement?.parentElement; // .card-body.overflow-x or similar
        if (!this.container) return;

        this.rowHeight = rowHeight;
        this.renderRow = renderRow;
        this.data = [];
        this.buffer = 5;
        this._rafId = null;
        this._lastStartIndex = -1;
        this._lastEndIndex = -1;

        // Make tbody block to support height and positioning
        this.tbody.style.position = 'relative';

        // Use passive listener + rAF debounce for smooth scrolling on high-refresh-rate displays
        this.container.addEventListener('scroll', () => this._scheduleRender(), { passive: true });
    }

    _scheduleRender() {
        if (this._rafId) return; // Already scheduled, skip
        this._rafId = requestAnimationFrame(() => {
            this._rafId = null;
            this.render();
        });
    }

    setData(data) {
        this.data = data || [];
        this.tbody.style.height = `${this.data.length * this.rowHeight}px`;
        this._lastStartIndex = -1; // Force re-render
        this.render();
    }

    prepend(item) {
        this.data.unshift(item);
        if (this.data.length > 2000) this.data.pop();
        this.tbody.style.height = `${this.data.length * this.rowHeight}px`;
        this._lastStartIndex = -1; // Force re-render
        this.render();
    }

    render() {
        const scrollTop = this.container.scrollTop;
        const containerHeight = this.container.clientHeight;
        
        const startIndex = Math.max(0, Math.floor(scrollTop / this.rowHeight) - this.buffer);
        const endIndex = Math.min(this.data.length, Math.floor((scrollTop + containerHeight) / this.rowHeight) + this.buffer);

        // Skip DOM updates if the visible range hasn't changed
        if (startIndex === this._lastStartIndex && endIndex === this._lastEndIndex) return;
        this._lastStartIndex = startIndex;
        this._lastEndIndex = endIndex;

        const fragment = document.createDocumentFragment();
        for (let i = startIndex; i < endIndex; i++) {
            const item = this.data[i];
            if (!item) continue;
            const row = this.renderRow(item);
            row.classList.add('virtual-row');
            row.style.transform = `translateY(${i * this.rowHeight}px)`;
            fragment.appendChild(row);
        }
        this.tbody.innerHTML = '';
        this.tbody.appendChild(fragment);
    }
}
