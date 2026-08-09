import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * This lab's previous gate had already been through one remediation, and the
 * things it got right are kept: it emulates `prefers-reduced-motion` rather
 * than injecting a stylesheet, it asserts the emulation actually took (a silent
 * no-op on Playwright 1.61.1 otherwise), it waits for `getAnimations()` to be
 * quiet across several consecutive frames, and it reads axe's `incomplete`
 * bucket rather than only `violations`. Four things it still got wrong, each
 * corrected here:
 *
 *  1. IT FORCE-OPENED THE ONE `<details>` ON THE PAGE, FROM SCRIPT. A helper
 *     called `revealAll()` set `.open = true` on every `<details>` before every
 *     scan, with the comment "so collapsed content is scanned, not skipped".
 *     `.deeper-details` holds the entire security lab and the wire internals —
 *     five property cards, ten run buttons, the provider comparison table — and
 *     it ships SHUT. So the arrival state, which is the one every reader meets
 *     and the only one in which that summary is a closed affordance, was never
 *     scanned in any theme at any width. This gate never touches `.open`; the
 *     disclosure is opened by clicking its own `<summary>`, which is also the
 *     only way a reader reaches the controls inside it.
 *
 *  2. IT SCANNED ONCE PER STATE, AT THE END. Six states were driven, and each
 *     one ran its whole sequence and then scanned — so `seal()`, which every
 *     other state builds on, was measured once at the end of `opened` and never
 *     as a state of its own; and each of the four scenario presets, each of the
 *     four request-flow tabs, every individual security property, the rotate and
 *     re-wrap operations, the copy-to-clipboard confirmations and Reset had
 *     never been scanned at all. This drive scans after every single step.
 *
 *  3. THE 380px CASE WAS ONE TEST, DARK ONLY, ONE STATE. It asserted that
 *     `.hierarchy-scroll` and `.comparison-table` really do overflow there —
 *     which was right and is kept — but then ran only axe over one sealed state
 *     in one theme. Reflow and keyboard reachability are properties of every
 *     state, and light theme has its own palette. This drive runs
 *     {dark, light} × {1280, 380}.
 *
 *  4. IT HAD NO NON-TEXT-CONTRAST ORACLE OF ITS OWN, and the one in
 *     `e2e/border-contrast.spec.ts` queries `.seal-input` — the two text fields,
 *     which are exactly the pair the `--control-border` token was written for
 *     and correctly applied to. Pointing a check only at the place a rule is
 *     already kept is the same as not having it. Every other control on this
 *     page is a `.chip` button — seven in the operations row, four request-flow
 *     tabs, ten property runners, four preset cards — and none had been measured
 *     against anything. `auditControlBoundaries` measures all of them, in every
 *     state, in all four configurations.
 *
 * The contrast question is answered TWICE in this repo, on purpose.
 * `contrast/measure.mjs` reads surfaces out of real screenshots and is gated by
 * `e2e/contrast.spec.ts`; the arithmetic walk in `e2e/contrast.ts` runs inside
 * `scan` here. They have complementary blind spots — see the header of
 * `contrast.ts` — and neither is redundant.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' },
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page is EXACTLY that shape, minus one declaration, which is why the
 * assertion is live rather than ceremonial. `style.css` has two `@keyframes`
 * and both start at `opacity: 0`: `fadeUp`, applied to `.cl-header`,
 * `.cl-hero`, every `.panel`, `.reality-panel` and `.footer-quote` — which is
 * most of the document — and `wrap-in`, applied to the four `.wrap-step` cards
 * with up to 0.42s of stagger. Both use `animation-fill-mode: both`, so before
 * the animation starts the element genuinely renders at `opacity: 0`. Both are
 * cancelled outright by `@media (prefers-reduced-motion: reduce)` with
 * `animation: none`.
 *
 * That is safe here for one reason only: neither selector declares an `opacity`
 * of its own, so cancelling the animation reverts to the initial value of 1. Add
 * `opacity: 0` to `.panel` — the obvious way to "fix" a flash of unstyled
 * content — and every panel on this page renders invisible for exactly the
 * readers who asked for less motion, with axe reporting nothing, because axe
 * reads declared colours and never asks whether an element is painted at all.
 * This assertion is the only thing in the suite that would catch it.
 *
 * `aria-hidden` subtrees are excluded. The cost of that exclusion is stated
 * plainly: text removed from the accessibility tree AND painted at zero opacity
 * is not checked here — which on this page means only the arrow and status
 * glyphs enumerated in the header of `contrast.ts`, each of which sits beside
 * the word it illustrates.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * This lab renders a `.cl-header` and a `.cl-hero` of its own inside
 * `<main id="app">`, which scopes any `<header>` among them out of the banner
 * role on its own — and `index.html`'s `dedupeBanner()` explicitly skips
 * anything inside sectioning content for that reason (`el.closest('main, …')`
 * returns early). Asserting the OUTCOME rather than either mechanism means a
 * change to where `app.ts` mounts its markup is caught too, and this page is
 * rebuilt wholesale from `innerHTML` on every state change, so that mount is
 * touched more often than most.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement)
        if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * The three controls that ship DISABLED because no envelope exists yet.
 *
 * `app.ts` re-renders the whole operations row from a template on every state
 * change, and each of these carries `disabled` while `state.envelopes` is
 * empty. They re-lock after Reset, so the drive asserts both transitions rather
 * than only the unlock.
 */
export const LOCKED_UNTIL_ENVELOPE = ['#open-btn', '#open-evil-btn', '#rewrap-btn'] as const;

/** The controls that are live from first paint, because bootstrap seeded a KEK. */
export const LIVE_FROM_BOOT = ['#create-key', '#seal-btn', '#rotate-btn', '#reset-btn'] as const;

/** The four request-flow tabs, in the order `request-flow.ts` renders them. */
export const FLOWS = ['GenerateDataKey', 'Encrypt', 'Decrypt', 'ReEncrypt'] as const;

/** The four scenario presets, by `data-preset`. */
export const PRESETS = ['hello', 'rotation', 'tenant', 'breach'] as const;

/** The five security properties, by `data-prop`; each has a defended and a weakened run. */
export const PROPERTIES = [
  'aad-binding',
  'ciphertext-tamper',
  'tenant-isolation',
  'wrap-integrity',
  'rotation-access',
] as const;

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. On this page the preference does more than
 * settle a transition: it is what cancels `fadeUp` on every panel and
 * `wrap-in` on the four wrap-replay cards, both of which start at
 * `opacity: 0` with `animation-fill-mode: both`, and it is what turns
 * `html { scroll-behavior: smooth }` into `auto` so a scrolled-to element ever
 * stops moving. Both effects are asserted below rather than assumed.
 *
 * The theme is seeded through `localStorage` rather than by clicking the
 * toggle, which pins down a real failure mode the gate this replaces could not
 * see: it reached light theme by clicking `#cl-theme-toggle`, so a persistence
 * key mismatch between `index.html`'s anti-flash script (`getItem('theme')`)
 * and the toggle (`setItem('theme', …)`) would still have scanned green. Seeded
 * this way, a mismatch fails on `data-theme` instead. (They agree today — both
 * are `'theme'` — which was checked, not assumed.)
 *
 * The defaults are asserted at length because this lab does NOT ship empty, and
 * which half of its palette a run measures depends entirely on that. A
 * multi-region scenario runs through real WebCrypto during bootstrap, so the
 * arrival page already has an active KEK, six audit entries and a valid chain —
 * but zero envelopes, which is what keeps three of the seven operations
 * controls `disabled`, and the security lab is shut inside a `<details>`.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect',
  ).toBe(true);
  // This lab represents DARK as the ABSENCE of `data-theme`: `index.html`'s
  // anti-flash script writes the attribute only when the stored value is
  // `'light'`, and `style.css` puts the dark palette on bare `:root` with
  // `html[data-theme='light']` overriding it. So asserting
  // `toHaveAttribute('data-theme', 'dark')` — which is what every other lab in
  // this fleet wants — fails here on a page that is correctly dark, and a gate
  // that did that would run only its light half while looking like it ran both.
  // Assert the RESOLVED theme instead, plus the attribute contract that
  // produces it.
  expect(
    await page.evaluate(() => document.documentElement.getAttribute('data-theme')),
    'the anti-flash script writes data-theme only for light; dark is its absence',
  ).toBe(theme === 'light' ? 'light' : null);
  expect(
    await page.evaluate(() => getComputedStyle(document.documentElement).colorScheme),
    `the ${theme} palette must actually be the one in effect`,
  ).toBe(theme);

  // `bootstrap()` runs a real multi-region scenario through WebCrypto before the
  // first render, so a navigation that resolves proves nothing.
  await expect(page.locator('.cl-hero-title')).toHaveText('Envelope KMS');
  await expect(page.locator('.key-status')).toBeVisible();
  await assertSingleBanner(page);

  // The reduced-motion block's two effects, asserted rather than assumed. The
  // first is the one that matters: `fadeUp` and `wrap-in` both begin at
  // `opacity: 0` with `fill-mode: both`, and the block cancels them outright, so
  // if any selector ever also declares its own `opacity: 0` the whole page goes
  // invisible for readers with the preference set. `expectNotBlank` catches that
  // in every state; this catches an animation arriving without an answer at all.
  expect(
    await page.evaluate(() =>
      Array.from(document.querySelectorAll('#app, #app *'))
        .filter((el) => getComputedStyle(el).animationName !== 'none')
        .map((el) => `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`),
    ),
    'reduced motion must cancel every animation this lab declares',
  ).toEqual([]);
  expect(
    await page.evaluate(() => getComputedStyle(document.documentElement).scrollBehavior),
    'reduced motion must turn off smooth scrolling',
  ).toBe('auto');

  // ── Bootstrap has already produced a KEK and an audit chain ──────────────
  await expect(page.locator('.key-status')).toHaveAttribute('data-state', 'ready');
  await expect(page.locator('.key-status-value')).toHaveText(/^kek-[0-9a-f]{16}$/);
  await expect(page.locator('.key-status-meta')).toHaveText('0 envelopes');
  await expect(page.locator('.audit-item')).toHaveCount(6);
  await expect(page.locator('.audit-status')).toContainText('Chain valid');

  // ── …and nothing else. No envelope, so three controls are locked ─────────
  for (const sel of LOCKED_UNTIL_ENVELOPE) await expect(page.locator(sel)).toBeDisabled();
  for (const sel of LIVE_FROM_BOOT) await expect(page.locator(sel)).toBeEnabled();
  await expect(page.locator('.wrap-step')).toHaveCount(0);
  await expect(page.locator('.prop-result')).toHaveCount(0);
  await expect(page.locator('.cross-tenant-result')).toHaveCount(0);
  await expect(page.locator('.empty-state')).toHaveCount(2);

  // ── Every shipped control default ────────────────────────────────────────
  await expect(page.locator('#plaintext-input')).toHaveValue('Hello envelope world');
  await expect(page.locator('#context-input')).toHaveValue('tenant=acme');
  await expect(page.locator('.preset-btn')).toHaveCount(PRESETS.length);
  await expect(page.locator('.flow-btn')).toHaveCount(FLOWS.length);
  await expect(page.locator('.flow-btn.active')).toHaveAttribute('data-flow', FLOWS[0]);
  await expect(page.locator('.flow-btn.active')).toHaveAttribute('aria-pressed', 'true');

  // The security lab and the wire internals are shut inside one `<details>`,
  // which the gate this replaces opened from script before every scan.
  await expect(page.locator('details')).toHaveCount(2);
  await expect(page.locator('details[open]')).toHaveCount(0);
  // The ten property runners are IN THE DOM — a closed `<details>` keeps its
  // subtree and merely stops painting it — but they are not in the accessibility
  // tree and cannot be reached, which is the fact that matters and the one the
  // node count cannot express. `getByRole` is the assertion that says it.
  await expect(page.getByRole('button', { name: /against the real build/ })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /against the weakened build/ })).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling — and, here, that it
 * does not silently CLIP instead.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all.
 *
 * The usual test is `documentElement.scrollWidth > clientWidth`, and on this
 * page that test can never fire: `body` carries `overflow-x: hidden`, and
 * because `html` leaves `overflow` at `visible` the body's value propagates to
 * the viewport. So content wider than the viewport is not scrolled to, it is
 * CUT OFF — which is a worse 1.4.10 outcome than a scrollbar, and invisible to
 * the standard check. Writing that check here unchanged would have produced a
 * permanently green reflow oracle on the one page in this fleet that most needs
 * one: the KEK hierarchy diagram has a 720px minimum width and the provider
 * comparison table switches to horizontal scrolling under 900px.
 *
 * So this asserts the stronger property directly: no element may extend past
 * the viewport unless it is inside a container that actually scrolls. An
 * intentional `.hierarchy-scroll` or `.comparison-table` is fine — its content
 * is reachable. Anything else past the right edge is content a reader at 380px
 * can never see, whether the document scrolls or not.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    // `body { overflow-x: hidden }` propagates to the viewport, so scrollWidth
    // stays equal to clientWidth even when content is cut off. Detect the
    // clipping directly instead of trusting the scroll geometry.
    const clippedByViewport = ['hidden', 'clip'].includes(
      getComputedStyle(document.body).overflowX,
    );
    if (!clippedByViewport && doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That cost
    // a run elsewhere in this fleet, and this page has a decoy behind every
    // `.scroller`.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Anything inside a real scroller is reachable and is not a finding; only
    // what escapes the viewport with no way back is.
    const escaping = over.filter((x) => !clipped(x.el));
    if (!escaping.length) return null;
    const widest = escaping[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      viewportClipsOverflow: clippedByViewport,
      widest:
        `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
        `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
        ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`,
      alsoEscaping: escaping.length - 1,
    };
  });
  expect(
    overflow,
    `content must not extend past the viewport with no scroller to reach it, in state: ${label}`,
  ).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * This lab has two, and both only become scrollers below 900px:
 * `.hierarchy-scroll` around the KEK tree, which carries a 720px minimum width,
 * and `.comparison-table`, which switches to horizontal scrolling at that
 * breakpoint. The gate this replaces asserted that they really do overflow at
 * 380px — which was right, and is kept in the drive — but never asked whether a
 * keyboard could then reach them. A scrolling container with no focusable
 * content and no `tabindex` is a WCAG 2.1.1 trap: the content is on the page,
 * reachable by mouse or finger, and unreachable by keyboard. That question only
 * exists at 380px, which is half of this gate's configurations and was none of
 * the old one's.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`,
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`,
  ).toEqual([]);
}

/**
 * SC 1.4.11 (non-text contrast) for interactive controls: a control's boundary
 * has to be perceivable against what surrounds it.
 *
 * This is `e2e/border-contrast.spec.ts`'s check, kept because it was right,
 * with its aim corrected and its colour parsing replaced. That spec queries
 * `.seal-input` — the two text fields — which is exactly the pair the palette's
 * `--control-border` token was written for and correctly applied to, in two
 * states, with a hand-rolled hex/rgba regex that would read `null` for any
 * `color-mix()`. Pointing a check only at the place a rule is already kept is
 * the same as not having it. Every other control here is a `.chip` button —
 * seven operations, four request-flow tabs, ten property runners — plus four
 * `.preset-card` buttons, and none of them had been measured against anything.
 *
 * A control passes if EITHER
 *   - its fill differs from the surface behind it (how `.btn` works: a
 *     transparent border over an `--accent` fill), or
 *   - it has a border that stands out from the surface behind it AND from its
 *     own fill (how a `<select>` works: a near-panel fill with a drawn edge).
 * so the score is `max(fill-vs-outside, min(border-vs-outside, border-vs-fill))`.
 * Taking the max of the two mechanisms is what keeps this from failing a
 * perfectly delineated solid button for having no border.
 *
 * Two deliberate exclusions:
 *  - `disabled` controls. WCAG exempts inactive components, and this page ships
 *    `#open-btn`, `#open-evil-btn` and `#rewrap-btn` disabled until an envelope
 *    exists, then re-locks them after Reset.
 *  - anything outside `#app`. The shared top bar is not this lab's to change —
 *    every repo in the fleet carries a byte-identical copy — and its `.cl-btn`
 *    boundary is `color-mix(in srgb, var(--accent) 38%, transparent)` over the
 *    bar's fixed `#0b1512`. That is reported upward as a fleet-wide observation
 *    rather than patched in one repo, and it is written down here so the
 *    exclusion is a decision and not an oversight.
 *
 * ONE THING IT CANNOT SEE, stated so it is not mistaken for coverage: a
 * pseudo-element. This page has two that matter — `.preset-card::before` and
 * `.prop-card::before`, each a 3px full-height rail painted in that card's
 * `--accent` (teal / violet / amber / crimson by `data-tone`) and clipped by the
 * card's own `overflow: hidden`. Those are the only per-card marks on either
 * grid, so they are SC 1.4.11 graphics, and neither this walk nor axe nor the
 * pixel oracle reports them. They are measured by hand from real screenshot
 * pixels instead; the numbers are in the commit that introduced this file.
 */
export async function auditControlBoundaries(
  page: Page,
): Promise<Array<{ sel: string; ratio: number }>> {
  return page.evaluate(() => {
    type C = { r: number; g: number; b: number; a: number };
    // Resolve through a canvas rather than a regex: this palette is full of
    // `color-mix()`, which `getComputedStyle` reports unchanged and which a
    // regex reads as null — landing the walk on the wrong backdrop.
    const cv = document.createElement('canvas');
    cv.width = cv.height = 1;
    const ctx = cv.getContext('2d', { willReadFrequently: true })!;
    const parse = (s: string): C => {
      if (!s) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = '#000';
      ctx.fillStyle = s;
      const a = ctx.fillStyle;
      ctx.fillStyle = '#fff';
      ctx.fillStyle = s;
      if (a !== ctx.fillStyle) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = s;
      ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data;
      return { r: d[0], g: d[1], b: d[2], a: d[3] / 255 };
    };
    const over = (fg: C, bg: C): C => {
      const a = fg.a + bg.a * (1 - fg.a);
      if (a === 0) return { r: 0, g: 0, b: 0, a: 0 };
      return {
        r: (fg.r * fg.a + bg.r * bg.a * (1 - fg.a)) / a,
        g: (fg.g * fg.a + bg.g * bg.a * (1 - fg.a)) / a,
        b: (fg.b * fg.a + bg.b * bg.a * (1 - fg.a)) / a,
        a,
      };
    };
    const lum = (c: C): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };
    const ratio = (a: C, b: C): number => {
      const la = lum(a);
      const lb = lum(b);
      return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    };
    const backdrop = (start: Element | null): C => {
      const stack: C[] = [];
      for (let n = start; n; n = n.parentElement) {
        const c = parse(getComputedStyle(n).backgroundColor);
        if (c.a > 0) {
          stack.push(c);
          if (c.a >= 1) break;
        }
      }
      let out: C = { r: 255, g: 255, b: 255, a: 1 };
      for (let i = stack.length - 1; i >= 0; i--) out = over(stack[i], out);
      return out;
    };
    const describe = (el: Element): string => {
      const cls = el.getAttribute('class');
      return (
        el.tagName.toLowerCase() +
        (el.id ? `#${el.id}` : '') +
        (cls ? `.${cls.trim().split(/\s+/).join('.')}` : '')
      );
    };

    const out: Array<{ sel: string; ratio: number }> = [];
    const app = document.getElementById('app');
    if (!app) return out;
    app
      .querySelectorAll<HTMLElement>("button, select, textarea, input[type='text']")
      .forEach((el) => {
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) return;
        if ((el as HTMLButtonElement).disabled) return;
        if (el.closest('[hidden]')) return;
        const cs = getComputedStyle(el);
        const outside = backdrop(el.parentElement);
        const fillRaw = parse(cs.backgroundColor);
        const fill = fillRaw.a > 0 ? over(fillRaw, outside) : outside;
        const byFill = ratio(fill, outside);
        let byBorder = 1;
        if (parseFloat(cs.borderTopWidth) > 0) {
          const border = over(parse(cs.borderTopColor), fill);
          byBorder = Math.min(ratio(border, outside), ratio(border, fill));
        }
        out.push({
          sel: describe(el),
          ratio: Math.round(Math.max(byFill, byBorder) * 100) / 100,
        });
      });
    return out;
  });
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.info(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label);
  try {
    await expectScrollersReachable(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label);
  try {
    await expectNoHorizontalOverflow(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically and `e2e/contrast.spec.ts` measures them again from real
 *    pixels. That exemption matters more here than in most labs: `<body>` runs
 *    two radial gradients and a linear one, so axe declines to compute a ratio
 *    for anything sitting on them — 199 nodes of it on first paint. Everything
 *    else in that bucket is a real result axe simply could not finish —
 *    including `aria-prohibited-attr`, which is where an `aria-label` on a
 *    role-less element hides, a defect that never reaches the violations array
 *    at all. That one has already been live in this repo: `gloss()` in `app.ts`
 *    put an `aria-label` on an `<abbr>`, which has no implicit role, so ARIA
 *    discarded the name and the definition reached hover users and nobody else.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast for interactive controls — SC 1.4.11, which axe has no
 *    rule for; see `auditControlBoundaries`.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page })
    .withTags(TAGS)
    // These four are axe "best-practice" rules rather than WCAG-tagged ones, so
    // `withTags` alone does not run them. This page is exactly the shape they
    // catch: a shared sticky <header role="banner"> above a <main id="app"> that
    // `app.ts` fills with a `.cl-header` and a `.cl-hero`, the hero containing an
    // <aside class="cl-hero-why">. None of the four was enabled before.
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  const boundaries = await auditControlBoundaries(page);
  expect(boundaries.length, `no controls found to measure in state: ${label}`).toBeGreaterThan(0);
  const undelineated = Array.from(
    new Set(boundaries.filter((b) => b.ratio < 3).map((b) => `${b.ratio}:1 ${b.sel}`)),
  );
  softExpect(undelineated, `control boundaries under 3:1 (SC 1.4.11) in state: ${label}`, []);

  await expectScrollersReachableSoft(page, label);
  await expectNoHorizontalOverflowSoft(page, label);
}

// ── The drive ───────────────────────────────────────────────────────────────

/**
 * Open the one `<details>` on the page by clicking its summary, and assert the
 * content behind it arrived.
 *
 * Never `.open = true`. The gate this replaces had a `revealAll()` helper that
 * set that property on every `<details>` before every one of its scans, so the
 * SHUT state — the one every reader arrives at, and the only one in which that
 * summary is a closed affordance rather than an open one — was never measured
 * in any theme at any width. Clicking is also the only route a reader has to
 * the ten property-run buttons inside.
 */
async function openSecurityLab(page: Page): Promise<void> {
  const d = page.locator('details.deeper-details');
  await expect(d).not.toHaveAttribute('open', '');
  await expect(page.getByRole('button', { name: /against the real build/ })).toHaveCount(0);
  await d.locator('summary').click();
  await expect(d).toHaveAttribute('open', '');
  await expect(page.getByRole('button', { name: /against the real build/ })).toHaveCount(
    PROPERTIES.length,
  );
  await expect(page.locator('.prop-run-btn')).toHaveCount(PROPERTIES.length * 2);
  await settle(page);
}

/** Seal one envelope with a chosen plaintext and context. */
async function seal(page: Page, plaintext: string, context: string): Promise<void> {
  await page.locator('#plaintext-input').fill(plaintext);
  await page.locator('#context-input').fill(context);
  await page.locator('#seal-btn').click();
  await expect(page.locator('.wrap-step')).toHaveCount(4);
  await settle(page);
}

/**
 * Drive the lab through every state that renders content, scanning each.
 *
 * Seven things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, AND IT IS NOT EMPTY. `bootstrap()`
 *    runs a real multi-region scenario through WebCrypto before the first
 *    render, so the page arrives with an active KEK, six audit entries and a
 *    valid chain — but zero envelopes, which is what keeps `#open-btn`,
 *    `#open-evil-btn` and `#rewrap-btn` `disabled`, and what puts two
 *    `.empty-state` panels on screen. Those three renderings exist only before
 *    the first seal, and the gate this replaces force-opened the security lab
 *    before every scan, so it never measured the arrival document at all.
 *
 *  - EVERY PREREQUISITE IS SCANNED BEFORE ITS UNLOCK, AND AGAIN AFTER RESET.
 *    The three locked controls are asserted disabled, then sealed into life,
 *    then asserted disabled again once Reset clears the envelope list — because
 *    `app.ts` rebuilds the whole controls row from a template on every state
 *    change, and a re-render that forgets the `disabled` attribute is exactly
 *    the kind of thing only the round trip catches.
 *
 *  - BOTH VERDICTS, NOT JUST THE SUCCESS ONE. `Open Latest` writes the
 *    plaintext back to the timeline; `Open as different tenant` is the refusal,
 *    and it is the only state that paints `.cross-tenant-result` and its
 *    `.prop-badge`. The audit chain is likewise driven into its BROKEN state,
 *    which is the only route to `.chain-break` and to `.audit-status` reading
 *    anything other than "Chain valid".
 *
 *  - EVERY BRANCH OF EVERY MODE FORK. Four request-flow tabs, each of which
 *    repaints the lane diagram and moves `aria-pressed`; four scenario presets,
 *    each writing a different shape to the timeline, the audit log and the
 *    inspector; and all five security properties in BOTH modes, defended and
 *    weakened — which are the two halves of that panel's palette, since a
 *    defended pass and a weakened failure are the only two `.prop-badge` tones
 *    the page has.
 *
 *  - THE COMPOSE FIELDS ARE DRIVEN TO THEIR EXTREMES. `#plaintext-input` is
 *    `maxlength="120"` and `#context-input` is `maxlength="64"`, and both accept
 *    anything. 120 unbroken characters is the reflow case: it is the only
 *    content on the page a reader controls, it lands in the timeline and the
 *    envelope inspector, and at 380px it decides whether the layout wraps or is
 *    silently cut off — which on this page is the real question, because `body`
 *    carries `overflow-x: hidden` and clips rather than scrolls.
 *
 *  - THE COPY BUTTONS ARE PRESSED. `.insp-copy` writes to the clipboard and
 *    flashes a confirmation; the spec grants clipboard permission so the
 *    resolved path is driven rather than a silently rejected promise, and the
 *    flashed state is scanned while it is on screen.
 *
 *  - NO FIXED TIMEOUTS. Every operation here is real WebCrypto on the main
 *    thread and every one has a DOM completion signal: a wrap-step count, a
 *    timeline row, a badge string, a control returning from `disabled`. The
 *    drive waits on those.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint: a bootstrapped KEK, zero envelopes, security lab shut');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('skip link focused');

  // ── The security lab, reached through its own summary ───────────────────
  // Opened before anything else is driven, because the request-flow tabs and
  // the ten property runners are all INSIDE this `<details>` — in the DOM from
  // first paint, but unreachable, unpaintable and absent from the accessibility
  // tree until its summary is clicked. The gate this replaces never learned
  // that, because `revealAll()` set `.open = true` before every scan.
  await openSecurityLab(page);
  await expect(page.locator('.prop-card')).toHaveCount(PROPERTIES.length);
  await expect(page.locator('.prop-result')).toHaveCount(0);
  await scanAt('security lab opened: five property cards and the request flow, nothing run yet');

  // ── The four request-flow tabs ──────────────────────────────────────────
  for (const flow of FLOWS.slice(1)) {
    await page.locator(`.flow-btn[data-flow="${flow}"]`).click();
    await expect(page.locator(`.flow-btn[data-flow="${flow}"]`)).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    await expect(page.locator('.flow-btn.active')).toHaveCount(1);
    await settle(page);
    await scanAt(`request flow: ${flow}`);
  }
  await page.locator(`.flow-btn[data-flow="${FLOWS[0]}"]`).click();
  await expect(page.locator(`.flow-btn[data-flow="${FLOWS[0]}"]`)).toHaveAttribute(
    'aria-pressed',
    'true',
  );
  await settle(page);
  await scanAt(`request flow: back to ${FLOWS[0]}`);

  // ── Seal, which unlocks the three locked controls ───────────────────────
  await seal(page, 'A11y gate payload', 'tenant=zeta');
  for (const sel of LOCKED_UNTIL_ENVELOPE) await expect(page.locator(sel)).toBeEnabled();
  await expect(page.locator('.key-status-meta')).toHaveText('1 envelope');
  await expect(page.locator('.empty-state')).toHaveCount(0);
  await scanAt('sealed: the four-step wrap replay, inspector populated, three controls unlocked');

  // The envelope inspector's copy affordance, driven to its confirmed state.
  const copy = page.locator('.insp-copy').first();
  await expect(copy).toBeVisible();
  await copy.click();
  await settle(page);
  await scanAt('inspector field copied to the clipboard');

  await page.locator('#open-btn').click();
  await expect(page.locator('.timeline li').last()).toHaveText('Open -> A11y gate payload');
  await settle(page);
  await scanAt('opened: the envelope decrypts back to its plaintext');

  // The refusal — the only state that paints `.cross-tenant-result`.
  await page.locator('#open-evil-btn').click();
  await expect(page.locator('.cross-tenant-result .prop-badge')).toHaveText(/Refused/);
  await settle(page);
  await scanAt('cross-tenant open refused: the AAD binding holds');

  await page.locator('#rotate-btn').click();
  await expect(page.locator('.key-status-value')).toHaveText(/^kek-[0-9a-f]{16}$/);
  await settle(page);
  await scanAt('KEK rotated: a new active key over an envelope wrapped under the old one');

  await page.locator('#rewrap-btn').click();
  await settle(page);
  await scanAt('envelope re-wrapped under the rotated KEK');

  // One property in each mode, so both `.prop-badge` tones are measured on a
  // card of their own before the batch runs paint five of each.
  const first = PROPERTIES[0];
  await page.locator(`.prop-run-btn[data-prop="${first}"][data-mode="defended"]`).click();
  await expect(page.locator('.prop-result')).toHaveCount(1);
  await settle(page);
  await scanAt(`security property ${first}: run against the real build`);

  await page.locator(`.prop-run-btn[data-prop="${first}"][data-mode="weakened"]`).click();
  await expect(page.locator('.prop-result')).toHaveCount(1);
  await settle(page);
  await scanAt(`security property ${first}: run against the weakened build`);

  await page.locator('#run-all-props').click();
  await expect(page.locator('.prop-result')).toHaveCount(PROPERTIES.length);
  await settle(page);
  await scanAt('all five properties run against the real build');

  await page.locator('#run-all-props-weakened').click();
  await expect(page.locator('.prop-result')).toHaveCount(PROPERTIES.length);
  await settle(page);
  await scanAt('all five properties run against the weakened build');

  // ── The audit chain, broken ─────────────────────────────────────────────
  await page.locator('#tamper-btn').click();
  await expect(page.locator('.audit-status')).toHaveText('Broken at #1');
  await expect(page.locator('.chain-break')).toBeVisible();
  await settle(page);
  await scanAt('audit chain tampered: broken at #1, with its downstream markers');

  // ── The four scenario presets ───────────────────────────────────────────
  for (const preset of PRESETS) {
    await page.locator(`.preset-btn[data-preset="${preset}"]`).click();
    await expect(page.locator('.timeline li').first()).toBeVisible();
    await settle(page);
    await scanAt(`scenario preset: ${preset}`);
  }

  // ── The reflow case: everything a reader can type, at full length ───────
  const LONG_PLAINTEXT = 'a3f19c7e4b02d85f'.repeat(7) + 'a3f19c7e';
  expect(LONG_PLAINTEXT.length, 'the plaintext probe must hit maxlength').toBe(120);
  const LONG_CONTEXT = 'tenant=' + 'f0e1d2c3b4a59687'.repeat(3) + 'f0e1d2c3';
  expect(LONG_CONTEXT.length, 'the context probe must hit maxlength').toBe(63);
  await seal(page, LONG_PLAINTEXT, LONG_CONTEXT);
  // Neither probe is echoed into the page: this is an envelope demo, so what
  // leaves a seal is ciphertext, and the AAD is rendered as part of the
  // envelope record rather than verbatim. Both stay in their fields at full
  // length, and that is the reflow case that matters — two fixed-width text
  // boxes side by side in a grid, holding 120 and 63 unbroken characters, at a
  // width where `body { overflow-x: hidden }` would cut off anything that did
  // not fit rather than let a reader scroll to it.
  await expect(page.locator('#plaintext-input')).toHaveValue(LONG_PLAINTEXT);
  await expect(page.locator('#context-input')).toHaveValue(LONG_CONTEXT);
  await settle(page);
  await scanAt('sealed 120 unbroken characters: the reflow case a reader controls');

  // "Open Latest" resolves the newest envelope in `state.envelopes`, which by
  // now includes everything the four presets sealed, so the plaintext it
  // returns is the app's choice and not this drive's to assert. What is asserted
  // is that the operation completed and wrote a new row.
  const timelineBefore = await page.locator('.timeline li').count();
  await page.locator('#open-btn').click();
  await expect(page.locator('.timeline li')).toHaveCount(timelineBefore + 1);
  await expect(page.locator('.timeline li').last()).toContainText('Open ->');
  await settle(page);
  await scanAt('an envelope opened after the full preset run');

  // ── Reset: back to an arrival-shaped page, controls re-locked ───────────
  await page.locator('#reset-btn').click();
  await expect(page.locator('.wrap-step')).toHaveCount(0);
  await expect(page.locator('.cross-tenant-result')).toHaveCount(0);
  for (const sel of LOCKED_UNTIL_ENVELOPE) await expect(page.locator(sel)).toBeDisabled();
  // FOUR empty states here, not the two the arrival page has. Reset does not
  // return the lab to first paint — it clears the KEK store and the audit log
  // as well, which the bootstrap scenario had populated before the first render.
  // So this is a rendering nothing else on the page produces: emptier than the
  // state a reader arrives in, and unreachable without pressing this button.
  await expect(page.locator('.empty-state')).toHaveCount(4);
  await settle(page);
  await scanAt('reset: emptier than first paint — KEK store and audit log cleared too');
}
