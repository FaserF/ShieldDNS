/**
 * ShieldDNS Layout & Mobile Verification Suite
 * 
 * Run `window.verifyFullLayout()` in the browser console to 
 * perform a complete check of spacing and responsiveness.
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
        
        const spacing = isFlex ? Math.max(marginRight, gap) : marginRight;
        
        if (spacing < 8 && !btn.matches(':last-child')) {
            results.push(`❌ ${name}: Spacing too small (${spacing}px). Expected >= 8px.`);
            passed = false;
        } else {
            results.push(`✅ ${name}: Spacing OK.`);
        }
    });

    console.log("--- Button Spacing Verification ---");
    results.forEach(r => console.log(r));
    return passed;
}

function verifyFullLayout() {
    console.clear();
    console.log("%c--- STARTING SHIELDDNS UI VERIFICATION ---", 'font-size: 1.2rem; font-weight: bold; color: var(--accent);');
    
    const spacingPassed = verifyButtonSpacing();
    
    let mobilePassed = true;
    if (typeof window.verifyMobileLayout === 'function') {
        mobilePassed = window.verifyMobileLayout();
    } else {
        console.warn("verifyMobileLayout not found. Make sure mobile_test.js is loaded.");
    }

    if (spacingPassed && mobilePassed) {
        console.log("%c✅ ALL UI TESTS PASSED", 'font-size: 1.5rem; color: #10b981; font-weight: bold; border-top: 2px solid #10b981; padding-top: 10px;');
        return true;
    } else {
        console.error("%c❌ UI VERIFICATION FAILED", 'font-size: 1.5rem; color: #ef4444; font-weight: bold; border-top: 2px solid #ef4444; padding-top: 10px;');
        return false;
    }
}

// Run the verification
if (typeof window !== 'undefined') {
    window.verifyLayout = verifyButtonSpacing;
    window.verifyFullLayout = verifyFullLayout;
    console.log("UI Test Suite loaded. Run `verifyFullLayout()` for a complete check.");
}
