import { expect, test } from '@playwright/test';
import { scan, reportCollected } from './gate';

test('key-handle result states are accessible at narrow width with reduced motion', async ({
  page,
}, testInfo) => {
  test.setTimeout(120000);
  await page.setViewportSize({ width: 380, height: 800 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(
    true,
  );
  await page.locator('#deeper-summary').click();
  await expect(page.locator('#key-handles-heading')).toBeVisible();
  await scan(page, 'key handles: fixed role arrival');
  await page.locator('#handle-attack').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#handle-outcome')).toHaveAttribute('data-outcome', 'blocked-role');
  await expect(page.locator('#handle-attack')).toBeFocused();
  await scan(page, 'key handles: fixed role refusal');
  await page.locator('#handle-legitimate').click();
  await expect(page.locator('#handle-outcome')).toHaveAttribute('data-outcome', 'protected-handle');
  await scan(page, 'key handles: protected handle');
  await page.locator('#handle-policy').selectOption('mutable-usages');
  await page.locator('#handle-attack').click();
  await expect(page.locator('#handle-outcome')).toHaveAttribute('data-outcome', 'exposed');
  await page.locator('#handle-wire-details summary').click();
  await page.locator('.handle-model-details summary').click();
  await expect(page.locator('#handle-escaped-key')).toBeVisible();
  await scan(page, 'key handles: exposed key, challenge bytes and limitation');
  await page
    .locator('#key-handles-lab')
    .screenshot({ path: testInfo.outputPath('exposure-mobile.png') });
  await page.setViewportSize({ width: 1280, height: 900 });
  await scan(page, 'key handles: exposed key on desktop');
  await page
    .locator('#key-handles-lab')
    .screenshot({ path: testInfo.outputPath('exposure-desktop.png') });
  await page.setViewportSize({ width: 380, height: 800 });
  const bounds = await page.locator('#key-handles-lab').evaluate((element) => ({
    width: element.clientWidth,
    scroll: element.scrollWidth,
  }));
  expect(bounds.scroll, 'key-handle content must reflow without clipping').toBeLessThanOrEqual(
    bounds.width + 1,
  );
  await page.locator('#handle-target').selectOption('nonextractable');
  await page.locator('#handle-attack').click();
  await expect(page.locator('#handle-outcome')).toHaveAttribute('data-outcome', 'blocked-target');
  await scan(page, 'key handles: nonextractable target');
  reportCollected();
});
