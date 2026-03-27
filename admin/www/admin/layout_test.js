/**
 * ShieldDNS Layout Spacing Test
 * 
 * This script verifies that all interactive buttons on the dashboard 
 * have adequate spacing (margins or gaps) to prevent a cramped UI.
 */

function verifyButtonSpacing() {
    const buttons = document.querySelectorAll('.btn');
    const results = [];
    let passed = true;

    buttons.forEach((btn, index) => {
        const style = window.getComputedStyle(btn);
        const parentStyle = window.getComputedStyle(btn.parentElement);
        
        const marginRight = parseInt(style.marginRight || 0);
        const gap = parseInt(parentStyle.columnGap || parentStyle.gap || 0);
        const isFlex = parentStyle.display === 'flex';

        const name = btn.id || btn.textContent.trim() || `Button ${index}`;
        
        // Requirement: At least 8px spacing if flexed or has margin
        const spacing = isFlex ? Math.max(marginRight, gap) : marginRight;
        
        if (spacing < 8 && !btn.matches(':last-child')) {
            results.push(`❌ ${name}: Spacing too small (${spacing}px). Expected >= 8px.`);
            passed = false;
        } else {
            results.push(`✅ ${name}: Spacing OK (${spacing}px).`);
        }
    });

    console.log("--- Dashboard Layout Verification Results ---");
    results.forEach(r => console.log(r));
    return passed;
}

// Run the verification
if (typeof window !== 'undefined') {
    window.verifyLayout = verifyButtonSpacing;
}
