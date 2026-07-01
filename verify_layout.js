const { chromium } = require('playwright');

async function testPage(url, pageName) {
    console.log(`\n========== Testing ${pageName} ==========`);
    const browser = await chromium.launch();
    const page = await browser.newPage();
    const viewports = [
        { width: 320, height: 568, name: 'iPhone SE' },
        { width: 1200, height: 800, name: 'Desktop' }
    ];

    console.log(`Navigating to ${pageName}...`);
    
    let consoleError = null;
    page.on('pageerror', exception => {
        consoleError = exception.message;
    });
    page.on('console', msg => {
        if (msg.type() === 'error') {
            console.error(`PAGE ERROR: ${msg.text()}`);
        } else {
            console.log(`PAGE LOG: ${msg.text()}`);
        }
    });

    try {
        // Mock Auth Status to bypass login in tests
        await page.route('**/api/auth-status', async route => {
            await route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ logged_in: true, need_setup: false })
            });
        });

        await page.goto(url, { waitUntil: 'load', timeout: 60000 });
    } catch (err) {
        console.error(`❌ Failed to load ${pageName}:`, err.message);
        await browser.close();
        return false;
    }

    if (consoleError) {
        console.error(`❌ ${pageName} failed with console error during load:`, consoleError);
        await browser.close();
        return false;
    }

    // --- Design Integrity Checks ---
    console.log("Running Design Integrity Checks...");
    const designIssues = await page.evaluate(() => {
        const issues = [];
        
        // 1. Check for standard inputs with solid white backgrounds
        const inputs = Array.from(document.querySelectorAll('input:not([type="checkbox"]):not([type="radio"]):not([type="hidden"])'));
        inputs.forEach(input => {
            const style = window.getComputedStyle(input);
            const bg = style.backgroundColor;
            if (bg === 'rgb(255, 255, 255)' || bg === 'rgba(255, 255, 255, 1)' || bg === 'white') {
                issues.push(`Input ${input.id || input.name || input.type} has a solid white background.`);
            }
            if (parseInt(style.borderRadius) < 4) {
                issues.push(`Input ${input.id || input.name} has insufficient border-radius.`);
            }
        });

        // 2. Check for "X" buttons that don't use Icons
        const tagRemovers = Array.from(document.querySelectorAll('.tag-remove'));
        tagRemovers.forEach(btn => {
            if (!btn.querySelector('i.fas') && btn.textContent === '×') {
                issues.push(`Tag remover button looks like a standard unstyled '×' character.`);
            }
        });

        // 3. Check for select dropdown styling bugs (like undefined CSS variables in inline styles)
        const selects = Array.from(document.querySelectorAll('select'));
        selects.forEach(sel => {
            if (sel.getAttribute('style') && (sel.getAttribute('style').includes('bg-card') || sel.getAttribute('style').includes('var(--text)'))) {
                issues.push(`Select ${sel.id || ''} uses undefined CSS variables in its inline style.`);
            }
        });

        // 4. Check for layout stretch bug on regular checkboxes using .checkbox-group (should not use space-between)
        const checkboxGroups = Array.from(document.querySelectorAll('.checkbox-group'));
        checkboxGroups.forEach(group => {
            const style = window.getComputedStyle(group);
            const hasSwitch = group.querySelector('.switch') !== null || group.querySelector('.checkbox-text') !== null;
            if (!hasSwitch && style.justifyContent === 'space-between') {
                issues.push(`Checkbox group ${group.id || ''} has a regular checkbox but uses space-between layout, stretching the label.`);
            }
        });

        // 5. Check for broken HTML markup leaks/literal escaping artifacts like ';"> in element texts
        const bodyText = document.body.innerHTML;
        if (bodyText.includes('\';">') || bodyText.includes('\';&quot;&gt;')) {
            issues.push(`Found escaping bug / literal ';"> character sequence in the page body.`);
        }

        return issues;
    });

    if (designIssues.length > 0) {
        console.error(`❌ Design Integrity Issues found in ${pageName}:`);
        designIssues.forEach(i => console.error(`   - ${i}`));
        await browser.close();
        return false;
    }
    console.log("✅ Design Integrity Checks passed.");

    // --- Functional Interaction Checks (Bugs Prevention) ---
    if (url.includes('/admin/')) {
        console.log("Running Functional Interaction Checks...");
        const interactionIssues = await page.evaluate(async () => {
            const issues = [];
            
            // Wait for app to be ready (max 2s)
            for (let i = 0; i < 20; i++) {
                if (window.editAPIKey) break;
                await new Promise(r => setTimeout(r, 100));
            }

            // Bug 1: Buttons in settings-form missing type="button"
            const settingsForm = document.getElementById('settings-form');
            if (settingsForm) {
                const buttons = Array.from(settingsForm.querySelectorAll('button:not([type="submit"])'));
                buttons.forEach(btn => {
                    if (btn.type !== 'button') {
                        issues.push(`Button "${btn.innerText.trim()}" (id: ${btn.id}) in settings-form is missing type="button". This causes unintended form submissions.`);
                    }
                });
            }

            // Bug 2: API Key Edit/Delete triggering form submit
            // We can mock the submit event and see if it's triggered
            let submitTriggered = false;
            if (settingsForm) {
                settingsForm.addEventListener('submit', (e) => {
                    submitTriggered = true;
                    e.preventDefault();
                    e.stopPropagation();
                }, true);

                // Simulate an API key in the list if empty (mocking render)
                const list = document.getElementById('api-keys-list');
                if (list) {
                    list.innerHTML = `
                        <tr>
                            <td>Test Key</td>
                            <td>read:stats</td>
                            <td>2026-05-07</td>
                            <td>Never</td>
                            <td>
                                <div style="display:flex; gap:8px;">
                                    <button type="button" id="test-edit-btn" class="btn btn-sm secondary"><i class="fas fa-edit"></i></button>
                                </div>
                            </td>
                        </tr>
                    `;
                    const editBtn = document.getElementById('test-edit-btn');
                    if (editBtn) {
                        // Mock state for functional check
                        if (window.state) {
                            window.state.allTokens = [{ id: 'test-id', name: 'Test Key', permissions: ['read:stats'] }];
                        }
                        
                        editBtn.onclick = () => window.editAPIKey('test-id');
                        editBtn.click();
                        
                        if (submitTriggered) {
                            issues.push("Clicking API Key Edit triggered a form submission! (Bug regression)");
                        }
                        
                        const modal = document.getElementById('api-key-modal');
                        if (!modal || modal.classList.contains('hidden')) {
                            issues.push("Clicking API Key Edit failed to open the management modal!");
                        }
                    }
                }
            }

            return issues;
        });

        if (interactionIssues.length > 0) {
            console.error(`❌ Functional Interaction Issues found:`);
            interactionIssues.forEach(i => console.error(`   - ${i}`));
            await browser.close();
            return false;
        }
        console.log("✅ Functional Interaction Checks passed.");
    }

    let failed = false;
    const issues = [];

    for (const vp of viewports) {
        console.log(`Checking viewport: ${vp.width}x${vp.height} (${vp.name})`);
        await page.setViewportSize({ width: vp.width, height: vp.height });
        await new Promise(r => setTimeout(r, 500));

        const overflow = await page.evaluate(() => {
            const scrollWidth = document.documentElement.scrollWidth;
            const clientWidth = document.documentElement.clientWidth;
            return { hasOverflow: scrollWidth > clientWidth, scrollWidth, clientWidth };
        });

        if (overflow.hasOverflow) {
            console.error(`  ❌ Horizontal overflow at ${vp.width}px.`);
            issues.push({ viewport: `${vp.width}x${vp.height}`, name: vp.name, overflow: overflow.scrollWidth - overflow.clientWidth });
            failed = true;
        } else {
            console.log(`  ✅ No overflow at ${vp.width}px.`);
        }
    }

    await browser.close();
    return !failed;
}

(async () => {
    const results = [];
    results.push(await testPage('http://localhost:8080/', 'Landing Page'));
    results.push(await testPage('http://localhost:8080/admin/', 'Admin Dashboard'));

    if (results.every(r => r)) {
        console.log('\n✅ All pages pass design & layout & functional verification!');
        process.exit(0);
    } else {
        console.error('\n❌ Verification failed for one or more pages!');
        process.exit(1);
    }
})();
