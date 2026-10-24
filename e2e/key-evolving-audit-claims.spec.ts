import { createHmac } from 'node:crypto';
import { expect, test, type Locator, type Page } from '@playwright/test';

type Scheme = 'STATIC' | 'FORWARD_SECURE';

type DisplayedRecord = {
  version: number;
  scheme: Scheme;
  logId: string;
  period: number;
  kind: 'EVENT' | 'CLOSE';
  message: string;
  previousTag: string;
  tag: string;
};

const TAG_KEY_DOMAIN = Buffer.from('crypto-lab/envelope-kms/log/v1/tag-key', 'utf8');
const UPDATE_DOMAIN = Buffer.from('crypto-lab/envelope-kms/log/v1/update', 'utf8');
const RECORD_DOMAIN = Buffer.from('crypto-lab/envelope-kms/log/v1/record', 'utf8');

function u32(value: number): Buffer {
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
}

function u64(value: number): Buffer {
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(BigInt(value));
  return output;
}

/** Independent implementation of the framing rule printed by the lesson. */
function frame(fields: readonly Uint8Array[]): Buffer {
  return Buffer.concat([
    u32(fields.length),
    ...fields.flatMap((field) => {
      const bytes = Buffer.from(field);
      return [u32(bytes.length), bytes];
    }),
  ]);
}

function hmac(key: Uint8Array, message: Uint8Array): Buffer {
  return createHmac('sha256', Buffer.from(key)).update(Buffer.from(message)).digest();
}

function nextState(state: Uint8Array, scheme: Scheme, logId: string, period: number): Buffer {
  if (scheme === 'STATIC') return Buffer.from(state);
  return hmac(
    state,
    frame([
      UPDATE_DOMAIN,
      Buffer.from('FORWARD_SECURE', 'utf8'),
      Buffer.from(logId, 'utf8'),
      u64(period),
    ]),
  );
}

function stateAt(initialState: Uint8Array, scheme: Scheme, logId: string, period: number): Buffer {
  let state = Buffer.from(initialState);
  for (let index = 0; index < period; index += 1) {
    state = nextState(state, scheme, logId, index);
  }
  return state;
}

function recordTag(record: DisplayedRecord, state: Uint8Array): string {
  const tagKey = hmac(
    state,
    frame([
      TAG_KEY_DOMAIN,
      Buffer.from(record.scheme, 'utf8'),
      Buffer.from(record.logId, 'utf8'),
      u64(record.period),
    ]),
  );
  return hmac(
    tagKey,
    frame([
      RECORD_DOMAIN,
      Buffer.from([record.version]),
      Buffer.from(record.scheme, 'utf8'),
      Buffer.from(record.logId, 'utf8'),
      u64(record.period),
      Buffer.from(record.kind, 'utf8'),
      Buffer.from(record.message, 'utf8'),
      Buffer.from(record.previousTag, 'hex'),
    ]),
  ).toString('hex');
}

async function field(scope: Locator, name: string): Promise<string> {
  return ((await scope.locator(`[data-field="${name}"]`).textContent()) ?? '').trim();
}

async function displayedRecord(scope: Locator): Promise<DisplayedRecord> {
  const scheme = await field(scope, 'scheme');
  const kind = await field(scope, 'kind');
  if (scheme !== 'STATIC' && scheme !== 'FORWARD_SECURE') throw new Error(`Bad scheme: ${scheme}`);
  if (kind !== 'EVENT' && kind !== 'CLOSE') throw new Error(`Bad record kind: ${kind}`);
  return {
    version: Number.parseInt(await field(scope, 'version'), 10),
    scheme,
    logId: await field(scope, 'log-id'),
    period: Number.parseInt(await field(scope, 'period'), 10),
    kind,
    message: await field(scope, 'message'),
    previousTag: await field(scope, 'previous-tag'),
    tag: await field(scope, 'tag'),
  };
}

async function recordsAt(locator: Locator): Promise<DisplayedRecord[]> {
  const records: DisplayedRecord[] = [];
  for (let index = 0; index < (await locator.count()); index += 1) {
    records.push(await displayedRecord(locator.nth(index)));
  }
  return records;
}

async function originalRecords(page: Page, scheme: Scheme): Promise<DisplayedRecord[]> {
  return recordsAt(page.locator(`#kea-records [data-record-scheme="${scheme}"]`));
}

async function attackedRecords(
  page: Page,
  attack: 'prior-rewrite' | 'suffix-forgery' | 'truncation',
  scheme: Scheme,
): Promise<DisplayedRecord[]> {
  return recordsAt(
    page.locator(`[data-attack="${attack}"] [data-scheme="${scheme}"] [data-forged-records] > li`),
  );
}

function hex(text: string): Buffer {
  if (!/^[0-9a-f]{64}$/.test(text)) throw new Error(`Expected 32 lower-case hex bytes: ${text}`);
  return Buffer.from(text, 'hex');
}

function independentMismatches(
  records: readonly DisplayedRecord[],
  initialState: Uint8Array,
  scheme: Scheme,
): { links: number[]; tags: number[] } {
  const links: number[] = [];
  const tags: number[] = [];
  let state = Buffer.from(initialState);
  let previousTag = Buffer.alloc(32);
  for (const record of records) {
    expect(record.period).toBe(records.indexOf(record));
    expect(record.scheme).toBe(scheme);
    if (record.previousTag !== previousTag.toString('hex')) links.push(record.period);
    if (recordTag(record, state) !== record.tag) tags.push(record.period);
    previousTag = hex(record.tag);
    state = nextState(state, scheme, record.logId, record.period);
  }
  return { links, tags };
}

async function build(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('#key-evolving-audit-heading')).toBeVisible();
  await page.locator('#kea-build').click();
  await expect(page.locator('#key-evolving-audit-lab')).toHaveAttribute('data-state', 'built');
  await expect(page.locator('#kea-records > li')).toHaveCount(6);
}

async function boundary(page: Page): Promise<number> {
  return Number.parseInt(await page.locator('#kea-compromise-period').inputValue(), 10);
}

async function initialState(page: Page, scheme: Scheme): Promise<Buffer> {
  const selector = scheme === 'STATIC' ? '#kea-static-initial-state' : '#kea-forward-initial-state';
  return hex(((await page.locator(selector).textContent()) ?? '').trim());
}

async function compromisedState(page: Page, scheme: Scheme): Promise<Buffer> {
  const selector =
    scheme === 'STATIC' ? '#kea-static-compromised-state' : '#kea-forward-compromised-state';
  return hex(((await page.locator(selector).textContent()) ?? '').trim());
}

test.describe('S02 key-evolving audit-log claims', () => {
  test('[KEA-01] displayed bytes reproduce both HMAC chains and the compromise boundary', async ({
    page,
  }) => {
    await build(page);
    const compromisePeriod = await boundary(page);
    const logId = ((await page.locator('#kea-log-id').textContent()) ?? '').trim();
    await expect(page.locator('#kea-compromise-label')).toContainText(
      `Immediately before period ${compromisePeriod}`,
    );

    for (const scheme of ['STATIC', 'FORWARD_SECURE'] as const) {
      const records = await originalRecords(page, scheme);
      expect(records).toHaveLength(6);
      expect(new Set(records.map((record) => record.logId))).toEqual(new Set([logId]));
      const verifierState = await initialState(page, scheme);
      expect(independentMismatches(records, verifierState, scheme)).toEqual({
        links: [],
        tags: [],
      });
      expect(await compromisedState(page, scheme)).toEqual(
        stateAt(verifierState, scheme, logId, compromisePeriod),
      );
    }

    const construction = page.locator('#kea-construction-details');
    await expect(construction).toContainText('U32BE(fieldCount)');
    await expect(construction).toContainText('crypto-lab/envelope-kms/log/v1/tag-key');
    await expect(construction).toContainText('crypto-lab/envelope-kms/log/v1/update');
    await expect(construction).toContainText('crypto-lab/envelope-kms/log/v1/record');
  });

  test('[KEA-02] a stolen static key retags the past while erased evolving state does not', async ({
    page,
  }) => {
    await build(page);
    const target = (await boundary(page)) - 1;
    await page.locator('#kea-rewrite-prior').click();

    const staticResult = page.locator('[data-attack="prior-rewrite"] [data-scheme="STATIC"]');
    const forwardResult = page.locator(
      '[data-attack="prior-rewrite"] [data-scheme="FORWARD_SECURE"]',
    );
    await expect(staticResult).toHaveAttribute('data-verdict', 'accepted');
    await expect(forwardResult).toHaveAttribute('data-verdict', 'rejected');

    const staticRecords = await attackedRecords(page, 'prior-rewrite', 'STATIC');
    const forwardRecords = await attackedRecords(page, 'prior-rewrite', 'FORWARD_SECURE');
    expect(staticRecords[target].message).toMatch(/^FORGED:/);
    expect(forwardRecords[target].message).toBe(staticRecords[target].message);
    expect(
      independentMismatches(staticRecords, await initialState(page, 'STATIC'), 'STATIC'),
    ).toEqual({ links: [], tags: [] });
    expect(
      independentMismatches(
        forwardRecords,
        await initialState(page, 'FORWARD_SECURE'),
        'FORWARD_SECURE',
      ),
    ).toEqual({ links: [], tags: [target] });
  });

  test('[KEA-03] the displayed S_c authenticates the compromised period and later suffix', async ({
    page,
  }) => {
    await build(page);
    const compromisePeriod = await boundary(page);
    const originals = {
      STATIC: await originalRecords(page, 'STATIC'),
      FORWARD_SECURE: await originalRecords(page, 'FORWARD_SECURE'),
    };
    await page.locator('#kea-forge-suffix').click();

    for (const scheme of ['STATIC', 'FORWARD_SECURE'] as const) {
      const result = page.locator(`[data-attack="suffix-forgery"] [data-scheme="${scheme}"]`);
      await expect(result).toHaveAttribute('data-verdict', 'accepted');
      const records = await attackedRecords(page, 'suffix-forgery', scheme);
      expect(records[compromisePeriod].message).toMatch(/^FORGED:/);
      expect(records.slice(0, compromisePeriod)).toEqual(
        originals[scheme].slice(0, compromisePeriod),
      );

      let state = await compromisedState(page, scheme);
      let previousTag = hex(records[compromisePeriod - 1].tag);
      for (const record of records.slice(compromisePeriod)) {
        expect(record.previousTag).toBe(previousTag.toString('hex'));
        expect(recordTag(record, state)).toBe(record.tag);
        previousTag = hex(record.tag);
        state = nextState(state, scheme, record.logId, record.period);
      }
    }
  });

  test('[KEA-04] a retained checkpoint covers its prefix but not a forged extension', async ({
    page,
  }) => {
    await build(page);
    const compromisePeriod = await boundary(page);
    const checkpoints = {
      STATIC: ((await page.locator('#kea-static-checkpoint-tag').textContent()) ?? '').trim(),
      FORWARD_SECURE: (
        (await page.locator('#kea-forward-checkpoint-tag').textContent()) ?? ''
      ).trim(),
    };
    for (const scheme of ['STATIC', 'FORWARD_SECURE'] as const) {
      expect(checkpoints[scheme]).toBe(
        (await originalRecords(page, scheme))[compromisePeriod - 1].tag,
      );
    }

    await page.locator('#kea-rewrite-prior').click();
    await expect(page.locator('[data-property="checkpoint-consistency"]')).toHaveAttribute(
      'data-verdict',
      'mismatch',
    );
    expect(
      (await attackedRecords(page, 'prior-rewrite', 'STATIC'))[compromisePeriod - 1].tag,
    ).not.toBe(checkpoints.STATIC);

    await page.locator('#kea-forge-suffix').click();
    await expect(page.locator('[data-property="checkpoint-consistency"]')).toHaveAttribute(
      'data-verdict',
      'bounded',
    );
    for (const scheme of ['STATIC', 'FORWARD_SECURE'] as const) {
      expect(
        (await attackedRecords(page, 'suffix-forgery', scheme))[compromisePeriod - 1].tag,
      ).toBe(checkpoints[scheme]);
    }
  });

  test('[KEA-05] a valid prefix is not completeness evidence without a trusted close bound', async ({
    page,
  }) => {
    await build(page);
    await page.locator('#kea-truncate').click();
    for (const scheme of ['STATIC', 'FORWARD_SECURE'] as const) {
      await expect(
        page.locator(`[data-attack="truncation"] [data-scheme="${scheme}"]`),
      ).toHaveAttribute('data-verdict', 'valid-prefix');
      const records = await attackedRecords(page, 'truncation', scheme);
      expect(independentMismatches(records, await initialState(page, scheme), scheme)).toEqual({
        links: [],
        tags: [],
      });
    }
    await expect(page.locator('[data-property="completeness"]')).toHaveAttribute(
      'data-verdict',
      'unknown',
    );
    await expect(page.locator('[data-property="checkpoint-consistency"]')).toHaveAttribute(
      'data-verdict',
      'match',
    );

    await page.locator('#kea-completeness-input').selectOption('trusted-close');
    await page.locator('#kea-build').click();
    await page.locator('#kea-truncate').click();
    await expect(page.locator('[data-property="completeness"]')).toHaveAttribute(
      'data-verdict',
      'missing-close',
    );
    await expect(
      page.locator(
        '[data-attack="truncation"] [data-truncation-scheme="FORWARD_SECURE"] .kea-dimension-report',
      ),
    ).toContainText('TRUNCATED');
  });

  test('[KEA-06] freshness stays unknown until an outside receipt supplies a newer bound', async ({
    page,
  }) => {
    await build(page);
    await page.locator('#kea-truncate').click();
    await expect(page.locator('[data-property="freshness"]')).toHaveAttribute(
      'data-verdict',
      'unknown',
    );

    await page.locator('#kea-freshness-input').selectOption('trusted-heartbeat');
    await page.locator('#kea-build').click();
    await page.locator('#kea-truncate').click();
    await expect(page.locator('[data-property="freshness"]')).toHaveAttribute(
      'data-verdict',
      'missed-heartbeat',
    );
    await expect(
      page.locator(
        '[data-attack="truncation"] [data-truncation-scheme="FORWARD_SECURE"] .kea-dimension-report',
      ),
    ).toContainText('STALE');
  });

  test('[KEA-07] changed inputs retire evidence, reset defaults, and actions preserve focus', async ({
    page,
  }) => {
    await build(page);
    await expect(page.locator('#kea-build')).toBeFocused();
    await page.locator('#kea-rewrite-prior').click();
    await expect(page.locator('#kea-rewrite-prior')).toBeFocused();
    await expect(page.locator('#kea-attack-evidence')).not.toBeEmpty();

    await page.locator('#kea-compromise-period').selectOption('4');
    await expect(page.locator('#kea-compromise-period')).toBeFocused();
    await expect(page.locator('#key-evolving-audit-lab')).toHaveAttribute('data-state', 'ready');
    await expect(page.locator('#key-evolving-audit-lab')).toHaveAttribute('data-retired', 'true');
    await expect(page.locator('#kea-status')).toContainText('Previous results retired');
    await expect(page.locator('#kea-attack-evidence')).toBeEmpty();
    await expect(page.locator('#kea-rewrite-prior')).toBeDisabled();
    expect(
      await page
        .locator('#kea-property-results > [data-property]')
        .evaluateAll((cards) => cards.map((card) => card.getAttribute('data-verdict'))),
    ).toEqual(['not-run', 'not-run', 'not-run', 'not-run']);

    await page.locator('#kea-reset').click();
    await expect(page.locator('#kea-reset')).toBeFocused();
    await expect(page.locator('#key-evolving-audit-lab')).toHaveAttribute('data-retired', 'false');
    await expect(page.locator('#kea-compromise-period')).toHaveValue('3');
    await expect(page.locator('#kea-completeness-input')).toHaveValue('none');
    await expect(page.locator('#kea-freshness-input')).toHaveValue('none');

    await page.locator('#kea-build').click();
    await page.locator('#kea-rewrite-prior').click();
    await page.evaluate(() => {
      (window as Window & { oldKeyEvolvingPanel?: HTMLElement }).oldKeyEvolvingPanel =
        document.querySelector<HTMLElement>('#key-evolving-audit-lab') ?? undefined;
    });
    await page.locator('#reset-btn').click();
    expect(
      await page.evaluate(
        () =>
          (window as Window & { oldKeyEvolvingPanel?: HTMLElement }).oldKeyEvolvingPanel?.dataset
            .disposed,
      ),
    ).toBe('true');
    await expect(page.locator('#key-evolving-audit-lab')).toHaveAttribute('data-state', 'ready');
    await expect(page.locator('#kea-attack-evidence')).toBeEmpty();
  });

  test('[KEA-08] four independent result cards remain distinct with no aggregate secure verdict', async ({
    page,
  }) => {
    await build(page);
    const cards = page.locator('#kea-property-results > [data-property]');
    await expect(cards).toHaveCount(4);
    expect(
      await cards.evaluateAll((elements) =>
        elements.map((element) => element.getAttribute('data-property')),
      ),
    ).toEqual(['forward-integrity', 'checkpoint-consistency', 'completeness', 'freshness']);

    await page.locator('#kea-rewrite-prior').click();
    await page.locator('#kea-forge-suffix').click();
    await page.locator('#kea-truncate').click();
    await expect(page.locator('[data-property="forward-integrity"]')).toHaveAttribute(
      'data-verdict',
      'split-boundary',
    );
    await expect(page.locator('[data-property="checkpoint-consistency"]')).toHaveAttribute(
      'data-verdict',
      'bounded',
    );
    await expect(page.locator('[data-property="completeness"]')).toHaveAttribute(
      'data-verdict',
      'unknown',
    );
    await expect(page.locator('[data-property="freshness"]')).toHaveAttribute(
      'data-verdict',
      'unknown',
    );
    await expect(page.locator('#kea-limits')).toBeVisible();
    await expect(page.locator('#kea-limits > li')).toHaveCount(5);
    await expect(page.locator('#kea-limits')).toContainText(
      'Key evolution alone does not establish completeness or freshness',
    );
    await expect(page.locator('#key-evolving-audit-lab')).not.toContainText(
      /overall(?:ly)? secure|the log is secure/i,
    );
    await expect(
      page.locator('[data-overall-verdict], [data-property="secure"], .kea-overall-verdict'),
    ).toHaveCount(0);
  });
});
