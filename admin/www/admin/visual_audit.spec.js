const { test, expect } = require('@playwright/test');

test('ShieldDNS UI Design Audit', async ({ page }) => {
  // Navigate to the app (assuming it's running locally for testing or we use the file path)
  // For this environment, we'll check the CSS properties of elements
  await page.goto('http://localhost:8080'); // Adjust to actual local dev URL

  // Helper to check if an element is using the ShieldDNS design variables
  const checkBrandedStyle = async (selector, property, expectedVar) => {
    const value = await page.evaluate(({sel, prop}) => {
      const el = document.querySelector(sel);
      if (!el) return null;
      return window.getComputedStyle(el).getPropertyValue(prop);
    }, {sel: selector, prop: property});
    return value;
  };

  // 1. Check Buttons have proper background
  const buttons = page.locator('button.btn.primary');
  for (const btn of await buttons.all()) {
    const bg = await btn.evaluate(el => window.getComputedStyle(el).backgroundColor);
    // ShieldDNS primary uses an accent color, e.g., hsla(var(--hue), 70%, 65%, 1)
    // We check if it's not the default browser grey
    expect(bg).not.toBe('rgb(239, 239, 239)'); 
  }

  // 2. Check Inputs have dark background (ShieldDNS style)
  const inputs = page.locator('input[type="text"], input[type="password"]');
  for (const input of await inputs.all()) {
    const bg = await input.evaluate(el => window.getComputedStyle(el).backgroundColor);
    // Should be dark/transparent, not white (rgb(255, 255, 255))
    expect(bg).not.toBe('rgb(255, 255, 255)');
  }

  // 3. Check Selects have dark background
  const selects = page.locator('select');
  for (const select of await selects.all()) {
    const bg = await select.evaluate(el => window.getComputedStyle(el).backgroundColor);
    expect(bg).not.toBe('rgb(255, 255, 255)');
  }

  // 4. Check that no stray inline-styled "Unknown" labels exist
  const infoEmpties = page.locator('.info-empty');
  if (await infoEmpties.count() > 0) {
    const fontStyle = await infoEmpties.first().evaluate(el => window.getComputedStyle(el).fontStyle);
    expect(fontStyle).toBe('italic');
  }

  // 5. Structural Audit: Ensure sections are not nested (layout stability)
  const nestedSections = await page.evaluate(() => {
    const sections = Array.from(document.querySelectorAll('section'));
    return sections.filter(s => s.parentElement.closest('section')).map(s => s.id);
  });
  expect(nestedSections, `Found nested sections: ${nestedSections.join(', ')}`).toHaveLength(0);
});
