/**
 * VirtualScroller Class - Handles high-performance rendering of large lists
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

        // Make tbody block to support height and positioning
        this.tbody.style.position = 'relative';

        this.container.addEventListener('scroll', () => this.render());
    }

    setData(data) {
        this.data = data || [];
        this.tbody.style.height = `${this.data.length * this.rowHeight}px`;
        this.render();
    }

    prepend(item) {
        this.data.unshift(item);
        if (this.data.length > 2000) this.data.pop();
        this.tbody.style.height = `${this.data.length * this.rowHeight}px`;
        this.render();
    }

    render() {
        const scrollTop = this.container.scrollTop;
        const containerHeight = this.container.clientHeight;
        
        const startIndex = Math.max(0, Math.floor(scrollTop / this.rowHeight) - this.buffer);
        const endIndex = Math.min(this.data.length, Math.floor((scrollTop + containerHeight) / this.rowHeight) + this.buffer);

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
