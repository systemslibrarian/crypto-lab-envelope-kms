import { expect, test, type Page } from '@playwright/test';

/**
 * Functional gate for the claims this lab makes on screen.
 *
 * The a11y and border-contrast specs prove the page is usable; nothing proved
 * the page is CORRECT. Every headline verdict here — the envelope byte counts,
 * the "Watch the wrap" replay, the cross-tenant refusal, the hash-chain break,
 * the five security properties and their weakened counterparts — is asserted
 * against values the page itself computed, and cross-checked between panels
 * wherever two panels render the same underlying value.
 *
 * These tests drive the real WebCrypto/AES paths, so per-test timeouts are
 * generous rather than the assertions being loosened.
 */

const PLAINTEXT = 'Envelope claims spec payload';
const CONTEXT = 'tenant=zeta';

type InspectorField = { bytes: number; b64: string; decodedLength: number; hex: string };
type Inspector = {
  fields: Record<string, InspectorField>;
  kekId: string;
  kekVersion: string;
};

type AuditRow = {
  index: number;
  operation: string;
  result: string;
  prev: string;
  hash: string;
  broken: boolean;
  downstream: boolean;
};

async function load(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('.key-status')).toBeVisible();
  await expect(page.locator('.cl-hero-title')).toHaveText('Envelope KMS');
}

/** Clear the bootstrap scenario's keys/log so a test starts from a known slate. */
async function resetAll(page: Page): Promise<void> {
  await page.locator('#reset-btn').click();
  await expect(page.locator('.key-status-value')).toHaveText('none');
  await expect(page.locator('.audit-panel .empty-title')).toHaveText('No entries yet');
}

async function createKek(page: Page): Promise<string> {
  await page.locator('#create-key').click();
  await expect(page.locator('.key-status-value')).not.toHaveText('none');
  return (await page.locator('.key-status-value').innerText()).trim();
}

async function seal(page: Page, plaintext: string, context: string): Promise<void> {
  await page.locator('#plaintext-input').fill(plaintext);
  await page.locator('#context-input').fill(context);
  await page.locator('#seal-btn').click();
  await expect(page.locator('.wrap-step')).toHaveCount(4);
}

/** The Envelope Inspector's on-the-wire fields, decoded from the page's own base64. */
async function inspector(page: Page): Promise<Inspector> {
  return page.evaluate(() => {
    const toHex = (raw: string): string => {
      let out = '';
      for (let i = 0; i < raw.length; i += 1)
        out += raw.charCodeAt(i).toString(16).padStart(2, '0');
      return out;
    };
    const fields: Record<
      string,
      { bytes: number; b64: string; decodedLength: number; hex: string }
    > = {};
    for (const field of document.querySelectorAll('.insp-grid .insp-field')) {
      const copy = field.querySelector('.insp-copy');
      if (!copy) continue;
      const name = field.querySelector('.insp-label')?.textContent?.trim() ?? '';
      const bytes = Number.parseInt(field.querySelector('.insp-meta')?.textContent ?? '', 10);
      const b64 = copy.getAttribute('data-copy') ?? '';
      const raw = atob(b64);
      fields[name] = { bytes, b64, decodedLength: raw.length, hex: toHex(raw) };
    }
    const row = document.querySelector('.insp-meta-row');
    const values = Array.from(row?.querySelectorAll('.insp-value') ?? []).map(
      (v) => v.textContent?.trim() ?? '',
    );
    return { fields, kekId: values[0] ?? '', kekVersion: values[1] ?? '' };
  });
}

/** The four "Watch the wrap" steps, with the trailing ellipsis stripped. */
async function wrapSteps(page: Page): Promise<{
  dek: string;
  ciphertext: string;
  wrapped: string;
  zeroized: string;
  step3note: string;
  step2note: string;
}> {
  return page.evaluate(() => {
    const hexAt = (selector: string): string =>
      (document.querySelector(selector)?.textContent ?? '').replace(/…$/, '');
    const noteAt = (step: number): string =>
      document
        .querySelector(`.wrap-step[data-step="${step}"] .wrap-note`)
        ?.textContent?.replace(/\s+/g, ' ')
        .trim() ?? '';
    return {
      dek: hexAt('.wrap-step[data-step="1"] .wrap-hex.dek'),
      ciphertext: hexAt('.wrap-step[data-step="2"] .wrap-hex.ct'),
      wrapped: hexAt('.wrap-step[data-step="3"] .wrap-hex.wrapped'),
      zeroized: hexAt('.wrap-step[data-step="4"] .wrap-hex.dek.zeroized'),
      step2note: noteAt(2),
      step3note: noteAt(3),
    };
  });
}

async function auditRows(page: Page): Promise<AuditRow[]> {
  return page.evaluate(() => {
    const fieldValue = (item: Element, label: string): string => {
      for (const group of item.querySelectorAll('.audit-fields > div')) {
        if (group.querySelector('dt')?.textContent?.trim() === label) {
          return group.querySelector('dd')?.textContent?.replace(/…$/, '').trim() ?? '';
        }
      }
      return '';
    };
    return Array.from(document.querySelectorAll('.audit-item')).map((item) => ({
      index: Number.parseInt(
        (item.querySelector('.audit-idx')?.textContent ?? '').replace('#', ''),
        10,
      ),
      operation: item.querySelector('.audit-op')?.textContent?.trim() ?? '',
      result: item.querySelector('.audit-result')?.textContent?.trim() ?? '',
      prev: fieldValue(item, 'prev'),
      hash: fieldValue(item, 'hash'),
      broken: item.classList.contains('broken'),
      downstream: item.classList.contains('downstream'),
    }));
  });
}

async function auditCount(page: Page): Promise<number> {
  const text = (await page.locator('.audit-count').innerText()).trim();
  return Number.parseInt(text, 10);
}

async function timeline(page: Page): Promise<string[]> {
  return page.locator('.timeline li').allInnerTexts();
}

/** Idempotently reveal the "Ready to go deeper?" disclosure. */
async function openDeeper(page: Page): Promise<void> {
  const details = page.locator('.deeper-details');
  if (!(await details.evaluate((el) => (el as HTMLDetailsElement).open))) {
    await page.locator('#deeper-summary').click();
  }
  await expect(page.locator('#run-all-props')).toBeVisible();
}

type PropCard = {
  id: string;
  title: string;
  badge: string;
  held: boolean | null;
  mode: string;
  observed: string;
  lesson: string;
};

async function propCards(page: Page): Promise<PropCard[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll('.prop-card')).map((card) => {
      const result = card.querySelector('.prop-result');
      return {
        id: card.querySelector('.prop-run-btn')?.getAttribute('data-prop') ?? '',
        title: card.querySelector('.prop-title')?.textContent?.trim() ?? '',
        badge: card.querySelector('.prop-badge')?.textContent?.trim() ?? '',
        held: result ? result.classList.contains('held') : null,
        mode: card.querySelector('.prop-mode-tag')?.textContent?.trim() ?? '',
        observed: card.querySelector('.prop-observed')?.textContent?.trim() ?? '',
        lesson: card.querySelector('.prop-lesson')?.textContent?.trim() ?? '',
      };
    }),
  );
}

/** The "N/5 run" counter the security lab prints in its lede. */
async function ranCounter(page: Page): Promise<{ ran: number; total: number }> {
  const lede = await page.locator('.security-lab .panel-lede').innerText();
  const match = /(\d+)\/(\d+) run\./.exec(lede);
  if (!match) return { ran: 0, total: 0 };
  return { ran: Number.parseInt(match[1], 10), total: Number.parseInt(match[2], 10) };
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

function toHex(value: string): string {
  return Array.from(new TextEncoder().encode(value), (b) => b.toString(16).padStart(2, '0')).join(
    '',
  );
}

test.describe('Envelope KMS — page claims', () => {
  test('bootstrap runs the RFC vectors and renders a valid hash chain', async ({ page }) => {
    const pageErrors: string[] = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));
    await load(page);

    // runRfcVectors() throws before render() if any RFC 3394 / RFC 5649 vector
    // mismatches, so a rendered hero + populated panels IS the vector verdict.
    expect(pageErrors).toEqual([]);
    await expect(page.locator('.primer')).toBeVisible();
    await expect(page.locator('.audit-status')).toHaveText(/Chain valid/);

    const rows = await auditRows(page);
    expect(rows.length).toBeGreaterThan(1);
    expect(await auditCount(page)).toBe(rows.length);

    // Newest-first rendering, contiguous indices, no gaps.
    const indices = rows.map((r) => r.index);
    expect(indices).toEqual([...indices].sort((a, b) => b - a));
    expect(indices).toEqual(Array.from({ length: rows.length }, (_, i) => rows.length - 1 - i));
    expect(rows.every((r) => r.result === 'ok')).toBe(true);

    // The chain itself: entry #0 is GENESIS-rooted and every later entry's
    // prev_hash is the previous entry's hash.
    const oldestFirst = [...rows].reverse();
    expect(oldestFirst[0].prev).toBe('GENESIS');
    for (let i = 1; i < oldestFirst.length; i += 1) {
      expect(oldestFirst[i].prev).toBe(
        oldestFirst[i - 1].hash.slice(0, oldestFirst[i].prev.length),
      );
    }
    expect(rows.every((r) => !r.broken && !r.downstream)).toBe(true);
  });

  test('the hierarchy view shows exactly one active version per KEK', async ({ page }) => {
    await load(page);
    // SVG <text> has no innerText; read textContent.
    const versions = await page.locator('.hierarchy-svg .node-subtext').allTextContents();
    expect(versions.length).toBeGreaterThan(0);
    for (const line of versions) {
      expect(line.match(/·active/g) ?? []).toHaveLength(1);
    }
  });

  test('a seal produces an envelope whose declared byte counts match its own payloads', async ({
    page,
  }) => {
    await load(page);
    await resetAll(page);
    const keyId = await createKek(page);
    await seal(page, PLAINTEXT, CONTEXT);

    const insp = await inspector(page);
    const names = Object.keys(insp.fields);
    expect(names.sort()).toEqual(['aad', 'ciphertext', 'iv', 'tag', 'wrappedDEK']);

    // Every field's base64 decodes to exactly the number of bytes it claims.
    for (const [name, field] of Object.entries(insp.fields)) {
      expect(field.bytes, `${name} declared bytes`).toBe(field.decodedLength);
    }

    // AES-GCM shape.
    expect(insp.fields.iv.bytes).toBe(12);
    expect(insp.fields.tag.bytes).toBe(16);
    // AES-GCM is length-preserving: ciphertext == plaintext byte length.
    expect(insp.fields.ciphertext.bytes).toBe(utf8Length(PLAINTEXT));
    // RFC 3394 adds the 8-byte integrity block to the 32-byte DEK.
    expect(insp.fields.wrappedDEK.bytes).toBe(40);
    // The AAD is the context, verbatim and unencrypted.
    expect(insp.fields.aad.bytes).toBe(utf8Length(CONTEXT));
    expect(atob(insp.fields.aad.b64)).toBe(CONTEXT);
    // The data really was encrypted, not merely copied.
    expect(insp.fields.ciphertext.hex).not.toBe(toHex(PLAINTEXT));

    expect(insp.kekId).toBe(keyId);
    expect(insp.kekVersion).toBe('v1');

    // Counters agree with each other.
    await expect(page.locator('.key-status-meta')).toHaveText('1 envelope');
    await expect(page.locator('.hierarchy-svg .node-dek')).toHaveCount(1);

    await page.locator('#seal-btn').click();
    await expect(page.locator('.key-status-meta')).toHaveText('2 envelopes');
    await expect(page.locator('.hierarchy-svg .node-dek')).toHaveCount(2);
  });

  test('"Watch the wrap" replays the same bytes the inspector stored', async ({ page }) => {
    await load(page);
    await resetAll(page);
    await createKek(page);
    await seal(page, PLAINTEXT, CONTEXT);

    const insp = await inspector(page);
    const steps = await wrapSteps(page);

    // Step 1 shows the first 16 bytes of the plaintext DEK.
    expect(steps.dek).toMatch(/^[0-9a-f]{32}$/);
    // Step 4 shows the SAME DEK, struck through, because it was zeroized.
    expect(steps.zeroized).toBe(steps.dek);
    await expect(page.locator('.wrap-hex.zeroized')).toHaveCount(1);

    // Steps 2 and 3 are the real ciphertext and wrappedDEK — byte-for-byte the
    // values the Envelope Inspector renders as base64.
    expect(insp.fields.ciphertext.hex.startsWith(steps.ciphertext)).toBe(true);
    expect(insp.fields.wrappedDEK.hex.startsWith(steps.wrapped)).toBe(true);
    expect(steps.wrapped).toMatch(/^[0-9a-f]{32}$/);

    // The DEK is never stored: the wrapped copy does not begin with it.
    expect(steps.wrapped).not.toBe(steps.dek);
    expect(insp.fields.wrappedDEK.hex).not.toContain(steps.dek);

    // The captions name the learner's own inputs and the wrapping KEK version.
    expect(steps.step2note).toContain(`plaintext "${PLAINTEXT}"`);
    expect(steps.step2note).toContain(`"${CONTEXT}"`);
    expect(steps.step3note).toContain(`${insp.kekId}@${insp.kekVersion}`);
    expect(steps.step3note).toContain('40B');
  });

  test('Open Latest round-trips to the exact plaintext that was typed', async ({ page }) => {
    await load(page);
    await resetAll(page);
    await createKek(page);
    await seal(page, PLAINTEXT, CONTEXT);

    const before = await auditCount(page);
    await page.locator('#open-btn').click();
    await expect(page.locator('.timeline li').last()).toHaveText(`Open -> ${PLAINTEXT}`);

    // Opening is a KMS Decrypt plus an envelope Open — two more audit entries.
    expect(await auditCount(page)).toBe(before + 2);
    const ops = (await auditRows(page)).map((r) => r.operation);
    expect(ops).toContain('Decrypt');
    expect(ops).toContain('Open');
    await expect(page.locator('.audit-status')).toHaveText(/Chain valid/);
  });

  test('the timeline renders typed text as text, not markup', async ({ page }) => {
    // Regression: timeline lines interpolated the learner's plaintext and context
    // straight into innerHTML, so `<b>x</b>` rendered as real markup.
    await load(page);
    await resetAll(page);
    await createKek(page);
    await seal(page, '<b>bold</b> payload', 'tenant=<i>evil</i>');
    await page.locator('#open-btn').click();
    await expect(page.locator('.timeline li').last()).toHaveText('Open -> <b>bold</b> payload');
    await expect(page.locator('.timeline b, .timeline i')).toHaveCount(0);
    const lines = await timeline(page);
    expect(lines.some((l) => l.includes('tenant=<i>evil</i>'))).toBe(true);
  });

  test('"Open as different tenant" is refused and names both contexts', async ({ page }) => {
    await load(page);
    await resetAll(page);
    await createKek(page);
    await seal(page, PLAINTEXT, CONTEXT);

    await page.locator('#open-evil-btn').click();
    const result = page.locator('.cross-tenant-result');
    await expect(result).toHaveClass(/held/);
    await expect(result.locator('.prop-badge')).toHaveText(/Refused/);
    const observed = await result.locator('.cross-tenant-observed').innerText();
    expect(observed).toContain('tenant=evil'); // the context that was claimed
    expect(observed).toContain(CONTEXT); // the context it was sealed for
    // The verdict states a reason, not a dangling colon.
    expect(observed).toMatch(/AES-GCM tag check rejected it: \S/);
    await expect(page.locator('.timeline li').last()).toHaveText(
      `Open-as-different-tenant -> refused (AAD "tenant=evil" ≠ "${CONTEXT}")`,
    );

    // The refusal is a real crypto failure, so the untouched envelope still opens.
    await page.locator('#open-btn').click();
    await expect(page.locator('.timeline li').last()).toHaveText(`Open -> ${PLAINTEXT}`);
  });

  test('the claimed context is chosen relative to the sealed one', async ({ page }) => {
    await load(page);
    await resetAll(page);
    await createKek(page);
    await seal(page, PLAINTEXT, 'tenant=evil');

    await page.locator('#open-evil-btn').click();
    const observed = await page.locator('.cross-tenant-observed').innerText();
    // Sealed as tenant=evil, so the mismatched claim flips to tenant=acme.
    expect(observed).toContain('Claimed context "tenant=acme"');
    expect(observed).toContain('sealed for "tenant=evil"');
    await expect(page.locator('.cross-tenant-result')).toHaveClass(/held/);
  });

  test('rotation keeps old envelopes readable and re-wrap migrates them', async ({ page }) => {
    test.setTimeout(60_000);
    await load(page);
    await resetAll(page);
    await createKek(page);
    await seal(page, PLAINTEXT, CONTEXT);
    expect((await inspector(page)).kekVersion).toBe('v1');

    await page.locator('#rotate-btn').click();
    await expect(page.locator('.timeline li').last()).toHaveText(/RotateKey -> .+@v2$/);

    // v1 goes decrypt-only, v2 becomes the single active version.
    // SVG <text> has no innerText; read textContent.
    const versions = await page.locator('.hierarchy-svg .node-subtext').allTextContents();
    expect(versions).toHaveLength(1);
    expect(versions[0]).toContain('v1·decrypt-only');
    expect(versions[0]).toContain('v2·active');
    expect(versions[0].match(/·active/g) ?? []).toHaveLength(1);

    // The envelope is still stamped v1 and still opens — no bulk re-encryption.
    expect((await inspector(page)).kekVersion).toBe('v1');
    await page.locator('#open-btn').click();
    await expect(page.locator('.timeline li').last()).toHaveText(`Open -> ${PLAINTEXT}`);

    const beforeWrapped = (await inspector(page)).fields.wrappedDEK.b64;
    await page.locator('#rewrap-btn').click();
    await expect(page.locator('.timeline li').last()).toHaveText(/Rewrap -> .+@v2$/);

    const after = await inspector(page);
    expect(after.kekVersion).toBe('v2');
    // Only the wrapped DEK changed; the bulk ciphertext was never touched.
    expect(after.fields.wrappedDEK.b64).not.toBe(beforeWrapped);
    expect(after.fields.wrappedDEK.bytes).toBe(40);
    expect(after.fields.ciphertext.bytes).toBe(utf8Length(PLAINTEXT));

    await page.locator('#open-btn').click();
    await expect(page.locator('.timeline li').last()).toHaveText(`Open -> ${PLAINTEXT}`);
    const ops = (await auditRows(page)).map((r) => r.operation);
    expect(ops).toContain('ReEncrypt');
    expect(ops).toContain('RewrapEnvelope');
    await expect(page.locator('.audit-status')).toHaveText(/Chain valid/);
  });

  test('the controls operate on the KEK the header advertises', async ({ page }) => {
    // Regression: the header read the KEK store while the handlers read
    // state.keyId, so on first load "Rotate KEK" announced success without
    // rotating and "Generate + Seal" failed with "Create a key first".
    await load(page);
    const advertised = (await page.locator('.key-status-value').innerText()).trim();
    expect(advertised).not.toBe('none');
    await expect(page.locator('#rotate-btn')).toBeEnabled();
    await expect(page.locator('#seal-btn')).toBeEnabled();

    const before = await auditCount(page);
    await page.locator('#rotate-btn').click();
    await expect(page.locator('.timeline li').last()).toHaveText(`RotateKey -> ${advertised}@v2`);
    expect(await auditCount(page)).toBe(before + 1);

    await page.locator('#seal-btn').click();
    await expect(page.locator('.key-status-meta')).toHaveText('1 envelope');
    await expect(page.locator('.toast.error')).toHaveCount(0);
    const insp = await inspector(page);
    expect(insp.kekId).toBe(advertised);
    expect(insp.kekVersion).toBe('v2');
  });

  test('tampering breaks the chain and points at the byte that changed', async ({ page }) => {
    await load(page);
    await expect(page.locator('.audit-status')).toHaveText(/Chain valid/);
    const before = await auditCount(page);

    await page.locator('#tamper-btn').click();
    await expect(page.locator('.audit-status')).toHaveText('Broken at #1');
    // Tampering rewrites an entry; it never adds one.
    expect(await auditCount(page)).toBe(before);
    expect((await auditRows(page)).length).toBe(before);

    const explainer = page.locator('.chain-break');
    await expect(explainer.locator('.chain-break-head')).toHaveText(/Broken link at entry #1/);
    await expect(explainer.locator('.chain-break-body')).toHaveText(/prev_hash committed to the/);

    const rows = await auditRows(page);
    expect(rows.filter((r) => r.broken).map((r) => r.index)).toEqual([1]);
    expect(rows.filter((r) => r.downstream).map((r) => r.index)).toEqual([2]);

    // The stored and recomputed digests diverge exactly where the page marks them.
    const digests = await page.evaluate(() => {
      const stored = document.querySelector('.chain-break .audit-hash:not(.recomputed)');
      const recomputed = document.querySelector('.chain-break .audit-hash.recomputed');
      const mark = recomputed?.querySelector('mark.hash-diff') ?? null;
      let offset = 0;
      for (const node of Array.from(recomputed?.childNodes ?? [])) {
        if (node === mark) break;
        offset += node.textContent?.length ?? 0;
      }
      return {
        stored: (stored?.textContent ?? '').replace(/…$/, ''),
        recomputed: (recomputed?.textContent ?? '').replace(/…$/, ''),
        mark: mark?.textContent ?? '',
        offset,
      };
    });
    expect(digests.stored).toHaveLength(24);
    expect(digests.recomputed).toHaveLength(24);
    expect(digests.stored).not.toBe(digests.recomputed);
    expect(digests.recomputed.slice(0, digests.offset)).toBe(
      digests.stored.slice(0, digests.offset),
    );
    expect(digests.recomputed[digests.offset]).not.toBe(digests.stored[digests.offset]);
    expect(digests.mark).toBe(digests.recomputed.slice(digests.offset, digests.offset + 2));

    // The stored digest is the one entry #1 still displays — the log was not rewritten.
    const tamperedRow = rows.find((r) => r.index === 1);
    expect(tamperedRow?.hash).toBe(digests.stored);
    // Entry #2 still commits to that stale hash, which is what exposes the edit.
    expect(rows.find((r) => r.index === 2)?.prev).toBe(
      digests.stored.slice(0, (rows.find((r) => r.index === 2)?.prev ?? '').length),
    );
  });

  test('tampering needs two entries to have a link to break', async ({ page }) => {
    await load(page);
    await resetAll(page);
    await createKek(page);
    expect(await auditCount(page)).toBe(1);

    await page.locator('#tamper-btn').click();
    await expect(page.locator('#status-region')).toHaveText('Need at least two entries to tamper');
    await expect(page.locator('.audit-status')).toHaveText(/Chain valid/);
    await expect(page.locator('.chain-break')).toHaveCount(0);
    expect(await auditCount(page)).toBe(1);
  });

  test('every security property holds against the real build', async ({ page }) => {
    test.setTimeout(60_000);
    await load(page);
    await openDeeper(page);
    const total = await page.locator('.prop-card').count();
    expect(total).toBe(5);

    await page.locator('#run-all-props').click();
    await expect(page.locator('#status-region')).toHaveText(`All ${total} properties held`);
    await expect(page.locator('.prop-result')).toHaveCount(total);

    const cards = await propCards(page);
    expect(cards.map((c) => c.id)).toEqual([
      'aad-binding',
      'ciphertext-tamper',
      'tenant-isolation',
      'wrap-integrity',
      'rotation-access',
    ]);
    // Held + broken sums to the whole grid.
    expect(cards.filter((c) => c.held === true)).toHaveLength(total);
    expect(cards.filter((c) => c.held === false)).toHaveLength(0);
    for (const card of cards) {
      expect(card.badge, card.id).toContain('Property held');
      expect(card.mode, card.id).toBe('real build');
      expect(card.lesson, card.id).toContain('Why it matters:');
      // A verdict must say WHY it held — never a dangling "Rejected:".
      expect(card.observed.trim(), card.id).not.toMatch(/Rejected:\s*$/);
      expect(card.observed.trim().length, card.id).toBeGreaterThan(20);
    }
    // Each refusal names the primitive that did the refusing.
    expect(cards[0].observed).toMatch(/^Rejected: .*authentication failed/);
    expect(cards[1].observed).toMatch(/^Rejected: .*authentication failed/);
    expect(cards[2].observed).toContain('RFC 3394 integrity check failed');
    expect(cards[3].observed).toContain('RFC 3394 integrity check failed');
    expect(cards[4].observed).toMatch(/v1 envelope still opens; new writes now use v2/);

    expect(await ranCounter(page)).toEqual({ ran: total, total });
  });

  test('every security property breaks — and explains why — in the weakened build', async ({
    page,
  }) => {
    test.setTimeout(60_000);
    await load(page);
    await openDeeper(page);
    const total = await page.locator('.prop-card').count();

    await page.locator('#run-all-props-weakened').click();
    await expect(page.locator('#status-region')).toHaveText(
      `${total} of ${total} properties BROKEN (weakened build)`,
    );
    await expect(page.locator('.prop-result')).toHaveCount(total);

    const cards = await propCards(page);
    expect(cards.filter((c) => c.held === false)).toHaveLength(total);
    expect(cards.filter((c) => c.held === true)).toHaveLength(0);
    for (const card of cards) {
      expect(card.badge, card.id).toContain('Property broken');
      expect(card.mode, card.id).toBe('weakened build');
      expect(card.lesson, card.id).toContain('Why it matters:');
    }
    // Each weakening states the specific defense that was removed.
    expect(cards[0].observed).toContain('the seal never covered the context');
    expect(cards[1].observed).toContain('there is no tag to notice');
    expect(cards[2].observed).toContain('One shared KEK');
    expect(cards[3].observed).toContain('instead of a6a6a6a6a6a6a6a6');
    expect(cards[4].observed).toContain('permanently unreadable');

    // The AES-CTR weakening is a real bit-flip: one ciphertext byte flipped, so
    // exactly one plaintext character comes back changed.
    const flipped = /came back as "([^"]+)"/.exec(cards[1].observed)?.[1] ?? '';
    const original = /complaint: "([^"]+)"/.exec(cards[1].observed)?.[1] ?? '';
    expect(original).toBe('balance: 42');
    expect(flipped).toHaveLength(original.length);
    expect(Array.from(flipped).filter((ch, i) => ch !== original[i])).toHaveLength(1);

    // The skipped RFC 3394 check hands back a key that is NOT the DEK.
    const [recovered, realDek] = Array.from(cards[3].observed.matchAll(/([0-9a-f]{32})…/g)).map(
      (m) => m[1],
    );
    expect(recovered).toMatch(/^[0-9a-f]{32}$/);
    expect(realDek).toMatch(/^[0-9a-f]{32}$/);
    expect(recovered).not.toBe(realDek);

    expect(await ranCounter(page)).toEqual({ ran: total, total });
  });

  test('the security lab counter counts the experiments actually run', async ({ page }) => {
    test.setTimeout(60_000);
    await load(page);
    await openDeeper(page);
    const total = await page.locator('.prop-card').count();
    expect(await ranCounter(page)).toEqual({ ran: 0, total: 0 }); // counter hidden until a run

    await page.locator('.prop-run-btn[data-prop="aad-binding"][data-mode="defended"]').click();
    await expect(page.locator('.prop-result')).toHaveCount(1);
    expect(await ranCounter(page)).toEqual({ ran: 1, total });

    // Re-running the same experiment does not inflate the counter.
    await openDeeper(page);
    await page.locator('.prop-run-btn[data-prop="aad-binding"][data-mode="weakened"]').click();
    await expect(page.locator('.prop-card').first().locator('.prop-mode-tag')).toHaveText(
      'weakened build',
    );
    expect(await ranCounter(page)).toEqual({ ran: 1, total });

    await openDeeper(page);
    await page.locator('.prop-run-btn[data-prop="wrap-integrity"][data-mode="defended"]').click();
    await expect(page.locator('.prop-result')).toHaveCount(2);
    expect(await ranCounter(page)).toEqual({ ran: 2, total });

    // The counter always equals the number of rendered result blocks.
    const { ran } = await ranCounter(page);
    expect(await page.locator('.prop-result').count()).toBe(ran);
    await expect(page.locator('.prop-run-btn[data-prop="aad-binding"]').first()).toHaveText(
      'Run again',
    );
  });

  test('each scenario preset runs its workflow end to end', async ({ page }) => {
    test.setTimeout(60_000);
    await load(page);
    await resetAll(page);

    await page.locator('.preset-btn[data-preset="hello"]').click();
    await expect(page.locator('.timeline li').last()).toHaveText(/^Preset Hello World -> kek-/);
    await expect(page.locator('.key-status-meta')).toHaveText('1 envelope');

    await page.locator('.preset-btn[data-preset="rotation"]').click();
    const rotationLine = await page.locator('.timeline li').last().innerText();
    const versions = /v(\d+) to v(\d+)/.exec(rotationLine);
    expect(rotationLine).toMatch(/^Preset Rotation -> kek-/);
    expect(versions).not.toBeNull();
    expect(Number(versions?.[2])).toBe(Number(versions?.[1]) + 1);

    await page.locator('.preset-btn[data-preset="tenant"]').click();
    await expect(page.locator('.timeline li').last()).toHaveText(
      /^Preset Multi-tenant -> cross-tenant unwrap rejected: Rejected: RFC 3394 integrity check failed/,
    );
    // The preset records a real property result, which the lab renders.
    await openDeeper(page);
    const isolation = (await propCards(page)).find((c) => c.id === 'tenant-isolation');
    expect(isolation?.held).toBe(true);
    expect(isolation?.mode).toBe('real build');

    await page.locator('.preset-btn[data-preset="breach"]').click();
    await expect(page.locator('.timeline li').last()).toHaveText(
      /^Preset Breach Response -> rotate to v\d+, re-wrap, schedule deletion \(7 days\)$/,
    );
    const ops = (await auditRows(page)).map((r) => r.operation);
    expect(ops).toContain('RotateKey');
    expect(ops).toContain('ReEncrypt');
    expect(ops).toContain('ScheduleKeyDeletion');
    await expect(page.locator('.audit-status')).toHaveText(/Chain valid/);
    expect(await auditCount(page)).toBe((await auditRows(page)).length);
  });

  test('the request-flow tabs switch the documented KMS call sequence', async ({ page }) => {
    await load(page);
    await openDeeper(page);
    await expect(page.locator('.flow-btn')).toHaveCount(4);
    await expect(page.locator('.flow-btn[data-flow="GenerateDataKey"]')).toHaveAttribute(
      'aria-pressed',
      'true',
    );

    await page.locator('.flow-btn[data-flow="Decrypt"]').click();
    await expect(page.locator('.flow-btn[data-flow="Decrypt"]')).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    await expect(page.locator('.flow-btn[data-flow="GenerateDataKey"]')).toHaveAttribute(
      'aria-pressed',
      'false',
    );
    await expect(page.locator('.flow-list li')).toHaveCount(4);
    await expect(page.locator('.flow-list li').first()).toContainText(
      'Client -> Storage: read envelope',
    );
  });

  test('Reset clears keys, envelopes and the audit log', async ({ page }) => {
    await load(page);
    await createKek(page);
    await seal(page, PLAINTEXT, CONTEXT);
    expect(await auditCount(page)).toBeGreaterThan(0);

    await page.locator('#reset-btn').click();
    await expect(page.locator('.key-status-value')).toHaveText('none');
    await expect(page.locator('.key-status')).toHaveAttribute('data-state', 'empty');
    await expect(page.locator('.key-status-meta')).toHaveText('0 envelopes');
    await expect(page.locator('.audit-panel .empty-title')).toHaveText('No entries yet');
    await expect(page.locator('.hierarchy-panel .empty-title')).toHaveText('No KEKs yet');
    await expect(page.locator('.wrap-viz .empty-title')).toHaveText('Nothing sealed yet');
    await expect(page.locator('.insp-grid')).toHaveCount(0);

    for (const id of ['#seal-btn', '#open-btn', '#open-evil-btn', '#rotate-btn', '#rewrap-btn']) {
      await expect(page.locator(id)).toBeDisabled();
    }
    await expect(page.locator('#create-key')).toBeEnabled();
  });
});
