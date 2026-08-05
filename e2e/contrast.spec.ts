import { expect, test, type Page } from '@playwright/test';
import { formatFailures, measure, settle } from '../contrast/measure.mjs';

/**
 * The half of the contrast question axe cannot answer.
 *
 * This page paints its hero inside two radial gradients and a linear gradient,
 * so axe declines to compute a ratio for anything sitting on them and files the
 * result as `incomplete` — 199 nodes of it. `incomplete` never reaches an
 * assertion on `results.violations`, so those surfaces were entirely ungated,
 * and two of them were genuinely below AA: `.cl-hero-sub` at 3.23:1 in light
 * theme (it carried `opacity: 0.85` on top of an already-dim colour) and
 * `.cl-hero-why-label` at 4.18:1.
 *
 * contrast/measure.mjs resolves them from rendered pixels, so a gradient, a
 * pseudo-element overlay or a translucent panel is measured as the reader sees
 * it. See that file for the method.
 */

async function load(page: Page): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  await expect
    .poll(() => page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches))
    .toBe(true);
  await expect(page.locator('.cl-hero-title')).toHaveText('Envelope KMS');
  await settle(page);
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
  });
  await settle(page);
}

async function seal(page: Page): Promise<void> {
  await page.locator('#plaintext-input').fill('Contrast gate payload');
  await page.locator('#context-input').fill('tenant=zeta');
  await page.locator('#seal-btn').click();
  await expect(page.locator('.wrap-step')).toHaveCount(4);
  await settle(page);
}

/**
 * Two states are enough to cover every surface: first paint carries the hero,
 * primer, controls and diagrams, and the sealed state adds the wrap replay and
 * the envelope inspector — including `.wrap-hex.zeroized`, the struck-through
 * DEK, which was the one below-AA surface that only exists after an action.
 */
const STATES: Record<string, (page: Page) => Promise<void>> = {
  'first paint': async () => {},
  'sealed envelope': seal,
};

for (const theme of ['dark', 'light'] as const) {
  for (const [name, drive] of Object.entries(STATES)) {
    test(`every text surface meets WCAG AA in ${theme} theme: ${name}`, async ({ page }) => {
      // Screenshotting the full page twice and reading it back through a canvas
      // is not fast; the work is the gate, not an accident of a slow machine.
      test.setTimeout(90_000);
      await load(page);
      if (theme === 'light') {
        await page.locator('#cl-theme-toggle').click();
        await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
        await settle(page);
      }
      await drive(page);

      const rows = await measure(page);
      // A run that measured almost nothing would pass vacuously.
      expect(rows.length, 'text surfaces measured').toBeGreaterThan(150);
      expect(formatFailures(rows), `sub-AA text in ${theme} / ${name}`).toEqual([]);
    });
  }
}
