import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { settle } from '../contrast/measure.mjs';

/**
 * WCAG regression gate. Deploys are already gated on the RFC 3394/5649 KAT
 * vectors; this gates them on accessibility the same way.
 *
 * Three things this gate learned the hard way:
 *
 * 1. It used to inject `transition: none; animation: none; opacity: 1` before
 *    scanning. That is not motion neutralisation, it is blindness: a suite that
 *    forces `opacity: 1` on everything can never see an opacity-driven contrast
 *    defect (there was one, in .cl-hero-sub), and it leaves `scroll-behavior:
 *    smooth` alive so scrolled-to elements never stop moving. We emulate
 *    `prefers-reduced-motion: reduce` instead — which the page already honours
 *    with its own `animation: none` rules — and assert the emulation actually
 *    took, because `test.use({ reducedMotion })` silently does nothing on
 *    Playwright 1.61.1. Then we wait for `document.getAnimations()` to be quiet
 *    for several consecutive frames rather than exiting through a gap between
 *    two waves.
 *
 * 2. It only ever scanned the untouched first paint. Every result panel — the
 *    wrap replay, the cross-tenant refusal, the broken hash chain, the five
 *    security property verdicts — had never been scanned at all. Those panels
 *    are where this lab does its teaching, so they are where a violation costs
 *    the most. Each is now driven and scanned.
 *
 * 3. `results.violations` is not the whole oracle. axe files two defect classes
 *    under `incomplete`, which no assertion was reading: `aria-prohibited-attr`
 *    (an `aria-label` on a role-less element, where ARIA discards the name) and
 *    `color-contrast` over a background gradient, where it declines to compute a
 *    ratio at all. The first is asserted here. The second cannot be decided by
 *    axe on this page by construction — the hero sits in a radial glow — so it
 *    is measured arithmetically from rendered pixels instead, in
 *    contrast.spec.ts, which is a gate of its own.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * axe rules whose `incomplete` findings this page cannot resolve on its own.
 *
 * Only `color-contrast` qualifies: the body carries two radial gradients and a
 * linear gradient, so axe refuses to compute a ratio for any text over them and
 * would report those nodes forever regardless of what the colours actually are.
 * contrast.spec.ts measures them arithmetically. Nothing else belongs here — an
 * incomplete result outside this list is a defect the gate has to see.
 */
const UNDECIDABLE_BY_AXE = new Set(['color-contrast']);

async function load(page: Page): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  // Emulation, not `test.use({ reducedMotion })`, and verified rather than
  // assumed: the latter is a silent no-op on Playwright 1.61.1.
  await expect
    .poll(() => page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches))
    .toBe(true);
  // bootstrap() is async — it runs a real multi-region scenario through
  // WebCrypto before the first render — so wait for painted content rather
  // than trusting `goto` to mean "there is something here to scan".
  await expect(page.locator('.cl-hero-title')).toHaveText('Envelope KMS');
  await expect(page.locator('.key-status')).toBeVisible();
  await settle(page);
}

async function toLight(page: Page): Promise<void> {
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await settle(page);
}

/** Open every <details> so collapsed content is scanned, not skipped. */
async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
  });
  await settle(page);
}

async function scan(page: Page, label: string): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const describe = (v: { id: string; impact?: string | null; help: string; nodes: unknown[] }) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: (v.nodes as { target: string[] }[]).map((n) => n.target.join(' ')).slice(0, 5),
  });

  expect(results.violations.map(describe), `violations in ${label}`).toEqual([]);
  expect(
    results.incomplete.filter((v) => !UNDECIDABLE_BY_AXE.has(v.id)).map(describe),
    `unresolved incomplete results in ${label}`,
  ).toEqual([]);
}

/* ── States worth scanning ───────────────────────────────────────────────── */

async function seal(page: Page): Promise<void> {
  await page.locator('#plaintext-input').fill('A11y gate payload');
  await page.locator('#context-input').fill('tenant=zeta');
  await page.locator('#seal-btn').click();
  await expect(page.locator('.wrap-step')).toHaveCount(4);
  await settle(page);
}

/** The success verdict: an envelope opened back to its plaintext. */
async function opened(page: Page): Promise<void> {
  await seal(page);
  await page.locator('#open-btn').click();
  await expect(page.locator('.timeline li').last()).toHaveText('Open -> A11y gate payload');
  await settle(page);
}

/** The refusal verdict: the cross-tenant open that must fail. */
async function refused(page: Page): Promise<void> {
  await seal(page);
  await page.locator('#open-evil-btn').click();
  await expect(page.locator('.cross-tenant-result .prop-badge')).toHaveText(/Refused/);
  await settle(page);
}

/** The broken-chain state, with its explainer and downstream markers. */
async function tampered(page: Page): Promise<void> {
  await seal(page);
  await page.locator('#tamper-btn').click();
  await expect(page.locator('.audit-status')).toHaveText('Broken at #1');
  await expect(page.locator('.chain-break')).toBeVisible();
  await settle(page);
}

/** All five security properties run against the weakened build. */
async function weakened(page: Page): Promise<void> {
  await page.locator('#run-all-props-weakened').click();
  await expect(page.locator('.prop-result')).toHaveCount(5);
  await settle(page);
}

const STATES: Record<string, (page: Page) => Promise<void>> = {
  'first paint': async () => {},
  'sealed envelope': seal,
  'opened envelope': opened,
  'cross-tenant refusal': refused,
  'tampered audit chain': tampered,
  'weakened security properties': weakened,
};

for (const theme of ['dark', 'light'] as const) {
  for (const [name, drive] of Object.entries(STATES)) {
    test(`no WCAG A/AA violations in ${theme} theme: ${name}`, async ({ page }) => {
      await load(page);
      if (theme === 'light') await toLight(page);
      // Reveal first: the Security Lab lives inside a <details>, so a state
      // that drives it cannot click anything until that is open.
      await revealAll(page);
      await drive(page);
      await scan(page, `${theme} / ${name}`);
    });
  }
}

/**
 * Overflow only happens at narrow widths, so a check at 1280px can never fail.
 * The hierarchy diagram has a 720px minimum width and the provider comparison
 * table switches to horizontal scrolling under 900px; at 380px with a sealed
 * envelope both are scrolling containers, and a scrolling container no keyboard
 * user can reach is a WCAG 2.1.1 trap.
 */
test('no WCAG A/AA violations at 380px with a sealed envelope', async ({ page }) => {
  await page.setViewportSize({ width: 380, height: 720 });
  await load(page);
  await revealAll(page);
  await seal(page);

  // Prove the containers really do overflow here, so this test cannot quietly
  // stop exercising the case it exists for.
  const overflowing = await page.evaluate(() =>
    [...document.querySelectorAll<HTMLElement>('.hierarchy-scroll, .comparison-table')].filter(
      (el) => el.scrollWidth > el.clientWidth + 1,
    ).length,
  );
  expect(overflowing, 'expected scrolling containers at 380px').toBeGreaterThan(0);

  await scan(page, 'dark / 380px sealed');
});
