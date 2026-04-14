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

        // Standard table layout flow

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
        this._lastStartIndex = -1; // Force re-render
        this.render();
    }

    prepend(item) {
        this.data.unshift(item);
        if (this.data.length > 2000) this.data.pop();
        this._lastStartIndex = -1; // Force re-render
        this.render();
    }

    render() {
        const scrollTop = this.container.scrollTop;
        const containerHeight = this.container.clientHeight;
        
        const startIndex = Math.max(0, Math.floor(scrollTop / this.rowHeight) - this.buffer);
        const endIndex = Math.min(this.data.length, Math.floor((scrollTop + containerHeight) / this.rowHeight) + this.buffer);

        if (startIndex === this._lastStartIndex && endIndex === this._lastEndIndex) return;
        this._lastStartIndex = startIndex;
        this._lastEndIndex = endIndex;

        const fragment = document.createDocumentFragment();
        
        // Add top spacer to push visible rows into position
        if (startIndex > 0) {
            const topSpacer = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 10; // Over-provision to cover all possible table widths
            td.style.height = `${startIndex * this.rowHeight}px`;
            td.style.padding = '0';
            td.style.border = 'none';
            topSpacer.appendChild(td);
            fragment.appendChild(topSpacer);
        }

        for (let i = startIndex; i < endIndex; i++) {
            const item = this.data[i];
            if (!item) continue;
            const row = this.renderRow(item);
            fragment.appendChild(row);
        }

        // Add bottom spacer to maintain scrollbar height
        if (endIndex < this.data.length) {
            const bottomSpacer = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 10;
            td.style.height = `${(this.data.length - endIndex) * this.rowHeight}px`;
            td.style.padding = '0';
            td.style.border = 'none';
            bottomSpacer.appendChild(td);
            fragment.appendChild(bottomSpacer);
        }

        this.tbody.innerHTML = '';
        this.tbody.appendChild(fragment);
    }
}
