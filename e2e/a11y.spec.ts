import { expect, test } from '@playwright/test';
import { boot, driveAllStates, NARROW, reportCollected, watchPageErrors } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches, and every state is scanned as
 * it is reached: the arrival page, where a bootstrapped multi-region scenario
 * has already produced a KEK and six audit entries but no envelope, so three
 * operations controls are locked and two panels are empty; the skip link
 * focused; all four request-flow tabs; a seal, its four-step wrap replay and the
 * unlock of those three controls; a field copied to the clipboard; the open
 * verdict and the cross-tenant REFUSAL; a KEK rotation and a re-wrap; the
 * security lab opened by clicking its own summary, then all five properties in
 * both the defended and the weakened build; the audit chain tampered into its
 * broken state; all four scenario presets; 120 unbroken characters typed into
 * the seal field, which is the reflow case and the only content a reader
 * controls; and Reset, which must re-lock what the seal unlocked. All of that in
 * both themes, at desktop and phone width.
 *
 * Clipboard permission is granted because `.insp-copy` calls
 * `navigator.clipboard.writeText`: without the grant the promise rejects,
 * nothing changes on screen, and the drive would be asserting against a state
 * the code never reached.
 *
 * See `gate.ts` for why the security lab is opened by click rather than by
 * setting `.open`, why the lab's defaults are asserted rather than assumed, why
 * `violations` is not the whole oracle, and why the reflow check here does not
 * measure `scrollWidth` (this page's `body` has `overflow-x: hidden`, so it
 * clips rather than scrolls, and the usual check can never fire).
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page, context }) => {
    test.setTimeout(900_000);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page, context }) => {
    test.setTimeout(900_000);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    // The two containers this width exists to exercise really must overflow
    // here, or the 2.1.1 half of the gate is asserting about nothing.
    expect(
      await page.evaluate(
        () =>
          [
            ...document.querySelectorAll<HTMLElement>('.hierarchy-scroll, .comparison-table'),
          ].filter((el) => el.scrollWidth > el.clientWidth + 1).length,
      ),
      'expected real scrolling containers at 380px',
    ).toBeGreaterThan(0);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });
}
