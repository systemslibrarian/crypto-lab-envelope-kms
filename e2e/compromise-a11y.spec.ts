import { test, expect } from '@playwright/test';
import { scan, reportCollected } from './gate';

test('compromise result states remain accessible at narrow width', async ({ page }) => {
  test.setTimeout(120000);
  await page.setViewportSize({ width: 380, height: 800 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  const lab = page.locator('#compromise-lab');
  for (const mode of ['isolated', 'shared']) {
    await lab.locator('select').selectOption(mode);
    await lab.locator('#compromise-run').click();
    await expect(lab.locator('#compromise-run')).toBeEnabled();
    await expect(lab).not.toContainText('failed to run');
    await scan(page, 'compromise ' + mode);
  }
  reportCollected();
});
