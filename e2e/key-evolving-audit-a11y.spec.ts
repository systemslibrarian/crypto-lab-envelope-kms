import { expect, test, type Page } from '@playwright/test';
import { reportCollected, scan, watchPageErrors } from './gate';

async function screenshotExpandedViewport(page: Page, path: string): Promise<void> {
  await page.locator('#kea-wire-details').scrollIntoViewIfNeeded();
  await page.screenshot({ path });
}

test('key-evolving audit states are accessible and reflow at narrow width', async ({
  page,
}, testInfo) => {
  test.setTimeout(240_000);
  await page.setViewportSize({ width: 380, height: 800 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const errors = watchPageErrors(page);
  await page.goto('.');
  await expect(page.locator('#key-evolving-audit-heading')).toBeVisible();
  await expect(page.locator('#key-evolving-audit-lab')).toHaveAttribute('data-state', 'ready');
  await expect(page.locator('#kea-rewrite-prior')).toBeDisabled();
  await expect(page.locator('#kea-property-results [data-property]')).toHaveCount(4);
  await scan(page, 'key-evolving audit: initial separate results');

  await page.locator('#kea-build').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#key-evolving-audit-lab')).toHaveAttribute('data-state', 'built');
  await expect(page.locator('#kea-build')).toBeFocused();
  await expect(page.locator('#kea-rewrite-prior')).toBeEnabled();
  await scan(page, 'key-evolving audit: two authenticators built and compromise exposed');

  await page.locator('#kea-rewrite-prior').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#kea-rewrite-prior')).toBeFocused();
  await expect(
    page.locator('[data-attack="prior-rewrite"] [data-scheme="STATIC"]'),
  ).toHaveAttribute('data-verdict', 'accepted');
  await expect(
    page.locator('[data-attack="prior-rewrite"] [data-scheme="FORWARD_SECURE"]'),
  ).toHaveAttribute('data-verdict', 'rejected');
  await scan(page, 'key-evolving audit: pre-compromise rewrite comparison');

  await page.locator('#kea-forge-suffix').click();
  await expect(
    page.locator('[data-attack="suffix-forgery"] [data-scheme="FORWARD_SECURE"]'),
  ).toHaveAttribute('data-verdict', 'accepted');
  await expect(page.locator('[data-property="forward-integrity"]')).toHaveAttribute(
    'data-verdict',
    'split-boundary',
  );
  await scan(page, 'key-evolving audit: compromised suffix remains forgeable');

  await page.locator('#kea-truncate').click();
  await expect(page.locator('[data-property="completeness"]')).toHaveAttribute(
    'data-verdict',
    'unknown',
  );
  await expect(page.locator('[data-property="freshness"]')).toHaveAttribute(
    'data-verdict',
    'unknown',
  );
  await scan(page, 'key-evolving audit: valid prefix with unknown completeness and freshness');

  await page.locator('#kea-completeness-input').selectOption('trusted-close');
  await expect(page.locator('#key-evolving-audit-lab')).toHaveAttribute('data-retired', 'true');
  await expect(page.locator('#kea-status')).toContainText('Previous results retired');
  await expect(page.locator('#kea-rewrite-prior')).toBeDisabled();
  await page.locator('#kea-freshness-input').selectOption('trusted-heartbeat');
  await scan(page, 'key-evolving audit: changed trust inputs retire old evidence');

  await page.locator('#kea-build').click();
  await page.locator('#kea-truncate').click();
  await expect(page.locator('[data-property="completeness"]')).toHaveAttribute(
    'data-verdict',
    'missing-close',
  );
  await expect(page.locator('[data-property="freshness"]')).toHaveAttribute(
    'data-verdict',
    'missed-heartbeat',
  );
  await scan(page, 'key-evolving audit: trusted CLOSE and heartbeat detect the missing suffix');

  await page.locator('#kea-construction-details > summary').click();
  await page.locator('#kea-wire-details > summary').click();
  await expect(page.locator('#kea-static-initial-state')).toBeVisible();
  await expect(page.locator('#kea-records > li')).toHaveCount(6);
  await scan(page, 'key-evolving audit: construction and complete wire evidence expanded');

  const narrowBounds = await page.locator('#key-evolving-audit-lab').evaluate((element) => ({
    width: element.clientWidth,
    scroll: element.scrollWidth,
  }));
  expect(
    narrowBounds.scroll,
    'key-evolving audit evidence must reflow without viewport clipping',
  ).toBeLessThanOrEqual(narrowBounds.width + 1);
  await screenshotExpandedViewport(page, testInfo.outputPath('key-evolving-audit-mobile.png'));

  await page.setViewportSize({ width: 1280, height: 900 });
  await scan(page, 'key-evolving audit: expanded evidence on desktop');
  await screenshotExpandedViewport(page, testInfo.outputPath('key-evolving-audit-desktop.png'));

  await page.locator('#themeToggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await scan(page, 'key-evolving audit: expanded evidence in light theme');
  await screenshotExpandedViewport(page, testInfo.outputPath('key-evolving-audit-light.png'));

  await page.locator('#kea-reset').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#kea-reset')).toBeFocused();
  await expect(page.locator('#key-evolving-audit-lab')).toHaveAttribute('data-state', 'ready');
  await expect(page.locator('#key-evolving-audit-lab')).toHaveAttribute('data-retired', 'false');
  await expect(page.locator('#kea-compromise-period')).toHaveValue('3');
  await expect(page.locator('#kea-completeness-input')).toHaveValue('none');
  await expect(page.locator('#kea-freshness-input')).toHaveValue('none');
  await expect(page.locator('#kea-attack-evidence')).toBeEmpty();
  await scan(page, 'key-evolving audit: local reset');

  expect(errors, errors.join('\n')).toEqual([]);
  reportCollected();
});
