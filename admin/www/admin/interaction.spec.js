/* jshint node: true */
const { test, expect } = require('@playwright/test');

/**
 * ShieldDNS Interaction & Smoke Test
 * Ensures that interactive elements (buttons, links) are properly wired up 
 * and don't result in "dead" clicks.
 */

test.describe('ShieldDNS UI Interaction Audit', () => {

  test.beforeEach(async ({ page }) => {
    // Assuming the dev server is running on 8080
    await page.goto('http://localhost:8080');
    // Wait for app to initialize
    await page.waitForSelector('#total-queries');
  });

  test('All modal footer buttons should have listeners or actions', async ({ page }) => {
    // We check specifically for buttons that should close modals
    const modalButtons = await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('.modal button'));
      return buttons.map(btn => ({
        id: btn.id,
        text: btn.innerText.trim(),
        hasListener: !!btn.onclick || btn.getAttribute('onclick') !== null,
        parentModal: btn.closest('.modal').id
      }));
    });

    // For buttons without inline onclick, we verify they work by clicking them
    // Note: We only test buttons that are meant to close the modal here as a smoke test
    const closeButtons = [
      'ip-info-done-btn',
      'domain-info-done-btn',
      'blocked-clients-close-btn',
      'close-list-details-btn',
      'modal-cancel',
      'close-api-key-modal-btn',
      'cancel-api-key-btn',
      'reset-cancel-1',
      'reset-cancel-2',
      'alert-ok',
      'confirm-cancel'
    ];

    for (const id of closeButtons) {
      const btn = page.locator(`#${id}`);
      if (await btn.count() > 0) {
        // First make the modal visible so we can test the close action
        const parentId = await btn.evaluate(el => el.closest('.modal').id);
        await page.evaluate((modalId) => {
          document.getElementById(modalId).classList.remove('hidden');
        }, parentId);

        await expect(page.locator(`#${parentId}`)).toBeVisible();
        
        // Click and verify it's hidden
        await btn.click();
        await expect(page.locator(`#${parentId}`)).toBeHidden();
        console.log(`✅ Button #${id} correctly closes modal #${parentId}`);
      }
    }
  });

  test('No "dead" buttons in settings sections', async ({ page }) => {
    // Check for buttons in settings that might be missing listeners
    const actionButtons = page.locator('.settings-section button, .card button');
    const count = await actionButtons.count();
    
    for (let i = 0; i < count; i++) {
      const btn = actionButtons.nth(i);
      const id = await btn.getAttribute('id');
      const text = await btn.innerText();
      
      // If it's not a known functional button, we check if it has at least some pointer events
      const cursor = await btn.evaluate(el => window.getComputedStyle(el).cursor);
      expect(cursor).toBe('pointer');
    }
  });

  test('Verify that all critical navigation links are active', async ({ page }) => {
    const navLinks = page.locator('nav a, .sidebar a');
    const count = await navLinks.count();
    
    for (let i = 0; i < count; i++) {
      const link = navLinks.nth(i);
      const href = await link.getAttribute('href');
      // Should not be empty or just '#'
      expect(href).not.toBe('');
      if (href === '#') {
        // If it's a hash-link, it must have an onclick or be handled by navigation.js
        const hasHandler = await link.evaluate(el => !!el.onclick || el.classList.contains('nav-link'));
        expect(hasHandler).toBe(true);
      }
    }
  });

  test('Diagnostics should not display "0" as CPU model', async ({ page }) => {
    // Open diagnostics view
    await page.locator('.nav-item[data-view="diagnostics"]').click();
    const cpuModel = page.locator('#diag-cpu-model');
    // Wait for data to load
    await page.waitForTimeout(500);
    const text = await cpuModel.innerText();
    expect(text).not.toBe('0');
  });

});
