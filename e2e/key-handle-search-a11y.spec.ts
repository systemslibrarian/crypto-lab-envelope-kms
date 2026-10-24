import { expect, test } from '@playwright/test';
import { reportCollected, scan } from './gate';

test('bounded key-handle search states are accessible and reflow at narrow width', async ({
  page,
}, testInfo) => {
  test.setTimeout(120000);
  await page.setViewportSize({ width: 380, height: 800 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  await page.locator('#deeper-summary').click();
  await expect(page.locator('#state-search-heading')).toBeVisible();
  await scan(page, 'key-handle search: initial bounded model');

  await page.locator('#state-search-run').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#state-search-outcome')).toHaveAttribute('data-outcome', 'protected');
  await expect(page.locator('#state-search-run')).toBeFocused();
  await scan(page, 'key-handle search: fixed-template completed graph');

  await page.locator('#state-search-cap').selectOption('1');
  await page.locator('#state-search-run').click();
  await expect(page.locator('#state-search-outcome')).toHaveAttribute('data-outcome', 'incomplete');
  await scan(page, 'key-handle search: operational cutoff');

  await page.locator('#state-search-cap').selectOption('50000');
  await page.locator('#state-search-policy').selectOption('per-handle-templates');
  await page.locator('#state-search-run').click();
  await expect(page.locator('#state-search-outcome')).toHaveAttribute('data-outcome', 'exposed');
  await scan(page, 'key-handle search: known-key import witness');
  await page
    .locator('#key-handle-state-search')
    .screenshot({ path: testInfo.outputPath('known-import-mobile.png') });

  await page.locator('#state-search-scenario').selectOption('same-value-handles');
  await page.locator('#state-search-run').click();
  await expect(page.locator('#state-search-alias-proof')).toBeVisible();
  await scan(page, 'key-handle search: same-value handles witness');

  const bounds = await page.locator('#key-handle-state-search').evaluate((element) => ({
    width: element.clientWidth,
    scroll: element.scrollWidth,
  }));
  expect(bounds.scroll, 'state-search content must reflow without clipping').toBeLessThanOrEqual(
    bounds.width + 1,
  );

  await page.setViewportSize({ width: 1280, height: 900 });
  await scan(page, 'key-handle search: same-value handles desktop');
  await page
    .locator('#key-handle-state-search')
    .screenshot({ path: testInfo.outputPath('same-value-desktop.png') });
  reportCollected();
});
