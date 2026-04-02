/**
 * ShieldDNS Mobile Layout Enforcement Test
 * 
 * This script provides programmatic verification that the UI is 
 * responsive and does not exhibit horizontal scrolling at narrow 
 * viewport widths (e.g., 320px, 375px).
 */

(function() {
    function verifyMobileLayout() {
        const results = [];
        let passed = true;
        
        const clientWidth = document.documentElement.clientWidth;
        const scrollWidth = document.documentElement.scrollWidth;
        
        console.log(`--- Mobile Layout Check (Viewport Width: ${clientWidth}px) ---`);
        
        // 1. Check Global Overflow
        if (scrollWidth > clientWidth) {
            results.push(`❌ Global Overflow: ScrollWidth (${scrollWidth}px) > ClientWidth (${clientWidth}px). 
               This indicates a horizontal scrollbar is visible.`);
            passed = false;
        } else {
            results.push(`✅ Global Overflow: OK (No horizontal scrollbar).`);
        }
        
        // 2. Identify Overflowing Elements
        const allElements = document.querySelectorAll('*');
        allElements.forEach(el => {
            const rect = el.getBoundingClientRect();
            // We ignore elements that are meant to be hidden or are part of known scrollable areas (like .overflow-x)
            const isScrollContainer = el.classList.contains('overflow-x') || el.classList.contains('log-terminal');
            
            if (!isScrollContainer && rect.right > clientWidth + 1) { // 1px buffer for rounding
                const description = el.id ? `#${el.id}` : (el.className ? `.${el.className.split(' ').join('.')}` : el.tagName.toLowerCase());
                results.push(`⚠️ Element Overflow: ${description} (Right: ${Math.round(rect.right)}px > ${clientWidth}px)`);
                passed = false;
            }
        });
        
        // 3. Check for Grid/Flex child integrity
        const containers = document.querySelectorAll('.analytics-grid, .stats-grid, .presets-grid, .connection-guide-grid');
        containers.forEach(container => {
            const computedStyle = window.getComputedStyle(container);
            if (computedStyle.display === 'grid') {
                const columns = computedStyle.gridTemplateColumns.split(' ');
                columns.forEach(col => {
                    if (parseInt(col) > clientWidth) {
                        results.push(`❌ Grid Column Overflow in ${container.className}: A column is wider than the viewport.`);
                        passed = false;
                    }
                });
            }
        });
        
        // 4. Touch Targets
        const interactive = document.querySelectorAll('button, a.nav-item, input[type="checkbox"]');
        let touchIssues = 0;
        interactive.forEach(el => {
            const rect = el.getBoundingClientRect();
            if (rect.width < 32 || rect.height < 32) { // 32px is the bare minimum, 44px is ideal
                touchIssues++;
            }
        });
        if (touchIssues > 0) {
            results.push(`⚠️ Touch Targets: ${touchIssues} elements are smaller than 32x32px and may be hard to tap on mobile.`);
        }

        // Final Report
        results.forEach(r => {
            if (r.startsWith('✅')) console.log(`%c${r}`, 'color: #10b981; font-weight: bold;');
            else if (r.startsWith('❌')) console.warn(`%c${r}`, 'color: #ef4444; font-weight: bold;');
            else console.log(`%c${r}`, 'color: #f59e0b;');
        });
        
        if (passed) {
            console.log("%c✓ MOBILE UI VALIDATED", 'background: #10b981; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold;');
        } else {
            console.error("%c✗ MOBILE UI ISSUES DETECTED", 'background: #ef4444; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold;');
        }
        
        return passed;
    }

    // Export to window
    if (typeof window !== 'undefined') {
        window.verifyMobileLayout = verifyMobileLayout;
        console.log("Mobile layout testing loaded. Run `verifyMobileLayout()` to check responsiveness.");
    }
})();
