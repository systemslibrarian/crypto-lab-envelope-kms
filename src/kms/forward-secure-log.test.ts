import { describe, expect, it } from 'vitest';
import { bytesToHex, encoder } from '../crypto/bytes';
import {
  AUTHENTICATED_LOG_GENESIS_TAG,
  buildAuthenticatedLog,
  compromiseBeforePeriod,
  createRetainedCheckpoint,
  deriveLogState,
  forgeSuffixFromCompromise,
  hmacSha256,
  rewriteFromCompromise,
  verifyAuthenticatedLog,
  type AuthenticatedLogRecord,
  type AuthenticatedLogScheme,
  type RetainedCheckpoint,
  type VerificationTrust,
} from './forward-secure-log';

const INITIAL_STATE = Uint8Array.from({ length: 32 }, (_, index) => index);
const LOG_ID = 'college-kms/audit/2026-10-24';
const EVENTS = ['CreateKey key-7', 'GenerateDataKey key-7', 'Decrypt object-4', 'RotateKey key-7'];

function makeLog(
  scheme: AuthenticatedLogScheme = 'FORWARD_SECURE',
  closeMessage?: string,
  events: readonly string[] = EVENTS,
): readonly AuthenticatedLogRecord[] {
  return buildAuthenticatedLog({
    scheme,
    initialState: INITIAL_STATE,
    logId: LOG_ID,
    events,
    ...(closeMessage === undefined ? {} : { closeMessage }),
  });
}

function trust(
  scheme: AuthenticatedLogScheme = 'FORWARD_SECURE',
  additions: Partial<VerificationTrust> = {},
): VerificationTrust {
  return {
    scheme,
    logId: LOG_ID,
    initialState: INITIAL_STATE,
    ...additions,
  };
}

function copies(records: readonly AuthenticatedLogRecord[]): Record<string, unknown>[] {
  return records.map((record) => ({ ...record }));
}

describe('HMAC and the two-branch period schedule', () => {
  it('matches RFC 4231 test case 1 and an independent WebCrypto computation', async () => {
    const key = new Uint8Array(20).fill(0x0b);
    const message = encoder.encode('Hi There');
    const expected = 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7';

    const nobleTag = hmacSha256(key, message);
    const webCryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const webCryptoTag = new Uint8Array(await crypto.subtle.sign('HMAC', webCryptoKey, message));

    expect(bytesToHex(nobleTag)).toBe(expected);
    expect(bytesToHex(webCryptoTag)).toBe(expected);
    expect(nobleTag).toEqual(webCryptoTag);
  });

  it('has fixed deterministic state and record vectors', () => {
    const periodThree = deriveLogState(INITIAL_STATE, LOG_ID, 3);
    const records = makeLog('FORWARD_SECURE', 'honest shutdown');

    expect(bytesToHex(periodThree)).toBe(
      'baceb7ca026f599d4b15c993711a5f4b752cd07d1069f17c9965b2269ff46a0a',
    );
    expect(records.map((record) => record.tag)).toEqual([
      '7f5c86256b6f567758b2e58102403ce10fb8045b5d2fe339676de31d874c1e1d',
      '62f687a143b84974ff7d064371d6f9200cf5a81132aed33cfb60ff4f426a7202',
      '7efbb7d8dbc736f502c947d402139dcf2924008dfcc4242db1241aabdc1b2ad4',
      'c5c7923960416898d030bcd8aeefe2c833275ed5cd4f73ec44dcdffc619f259f',
      'f5d278109c0f5259ea9e425127cf490ee7e22f7e4d7a406905e13fdb5f6e26ee',
    ]);
    expect(records[0].previousTag).toBe(AUTHENTICATED_LOG_GENESIS_TAG);
    expect(records[4]).toMatchObject({ period: 4, kind: 'CLOSE' });
  });

  it('domain-separates modes and length-prefixes variable fields', () => {
    const forward = buildAuthenticatedLog({
      scheme: 'FORWARD_SECURE',
      initialState: INITIAL_STATE,
      logId: 'ab',
      events: ['c'],
    });
    const splitDifferently = buildAuthenticatedLog({
      scheme: 'FORWARD_SECURE',
      initialState: INITIAL_STATE,
      logId: 'a',
      events: ['bc'],
    });
    const staticLog = buildAuthenticatedLog({
      scheme: 'STATIC',
      initialState: INITIAL_STATE,
      logId: 'ab',
      events: ['c'],
    });

    expect(forward[0].tag).not.toBe(splitDifferently[0].tag);
    expect(forward[0].tag).not.toBe(staticLog[0].tag);
  });

  it('keeps distinct well-formed Unicode encodings distinct', () => {
    const composed = buildAuthenticatedLog({
      scheme: 'FORWARD_SECURE',
      initialState: INITIAL_STATE,
      logId: LOG_ID,
      events: ['caf\u00e9'],
    });
    const decomposed = buildAuthenticatedLog({
      scheme: 'FORWARD_SECURE',
      initialState: INITIAL_STATE,
      logId: LOG_ID,
      events: ['cafe\u0301'],
    });
    expect(composed[0].tag).not.toBe(decomposed[0].tag);
  });

  it('does not mutate caller-owned initial state while deriving or building', () => {
    const input = INITIAL_STATE.slice();
    const before = input.slice();
    deriveLogState(input, LOG_ID, 5);
    buildAuthenticatedLog({
      scheme: 'FORWARD_SECURE',
      initialState: input,
      logId: LOG_ID,
      events: ['one'],
    });
    expect(input).toEqual(before);
  });
});

describe('verification dimensions', () => {
  it('labels an authenticated open prefix as UNKNOWN, not complete or fresh', () => {
    const report = verifyAuthenticatedLog(makeLog(), trust());
    expect(report).toEqual({
      integrity: 'VALID',
      integrityReason: null,
      firstInvalidIndex: null,
      authenticatedRecords: 4,
      consistency: 'NOT_CHECKED',
      completeness: 'UNKNOWN',
      freshness: 'UNKNOWN',
      closePeriod: null,
      trustedMinimumRecords: null,
    });
  });

  it('authenticates an honest close but does not infer completeness or freshness from it', () => {
    const records = makeLog('FORWARD_SECURE', 'honest shutdown');
    const report = verifyAuthenticatedLog(records, trust());
    expect(report.integrity).toBe('VALID');
    expect(report.completeness).toBe('UNKNOWN');
    expect(report.freshness).toBe('UNKNOWN');
    expect(report.closePeriod).toBe(4);
  });

  it('uses explicit close and record-count expectations as trusted bounds', () => {
    const records = makeLog('FORWARD_SECURE', 'honest shutdown');
    const report = verifyAuthenticatedLog(
      records,
      trust('FORWARD_SECURE', { expectedClosePeriod: 4, trustedMinimumRecords: 5 }),
    );
    expect(report.completeness).toBe('COMPLETE');
    expect(report.freshness).toBe('CURRENT_TO_TRUSTED_BOUND');
    expect(report.trustedMinimumRecords).toBe(5);
  });

  it('keeps an earlier retained checkpoint consistent with an honest extension', () => {
    const records = makeLog('FORWARD_SECURE', 'honest shutdown');
    const checkpoint = createRetainedCheckpoint(records, 2);
    const report = verifyAuthenticatedLog(records, trust('FORWARD_SECURE', { checkpoint }));
    expect(report.consistency).toBe('CONSISTENT');
    expect(report.freshness).toBe('UNKNOWN');
  });

  it('reports a mismatched, malformed, or wrong-log checkpoint as inconsistent', () => {
    const records = makeLog();
    const valid = createRetainedCheckpoint(records, 2);
    const mismatched = { ...valid, lastTag: 'ff'.repeat(32) };
    const malformed = { ...valid, recordCount: 0 } as RetainedCheckpoint;
    const wrongLog = { ...valid, logId: 'other-log' };
    expect(
      verifyAuthenticatedLog(records, trust('FORWARD_SECURE', { checkpoint: mismatched }))
        .consistency,
    ).toBe('INCONSISTENT');
    expect(
      verifyAuthenticatedLog(records, trust('FORWARD_SECURE', { checkpoint: malformed }))
        .consistency,
    ).toBe('INCONSISTENT');
    expect(
      verifyAuthenticatedLog(records, trust('FORWARD_SECURE', { checkpoint: wrongLog }))
        .consistency,
    ).toBe('INCONSISTENT');
  });

  it('distinguishes early and late close records against a trusted period', () => {
    const early = makeLog('FORWARD_SECURE', 'close', EVENTS.slice(0, 2));
    const late = makeLog('FORWARD_SECURE', 'close', [...EVENTS, 'extra event']);
    expect(
      verifyAuthenticatedLog(early, trust('FORWARD_SECURE', { expectedClosePeriod: 4 }))
        .completeness,
    ).toBe('EARLY_CLOSE');
    expect(
      verifyAuthenticatedLog(late, trust('FORWARD_SECURE', { expectedClosePeriod: 4 }))
        .completeness,
    ).toBe('LATE_CLOSE');
  });
});

describe('compromise immediately before period c', () => {
  it('cannot retag a rewrite at c-1 under forward evolution', () => {
    const records = makeLog('FORWARD_SECURE', 'honest shutdown');
    const compromise = compromiseBeforePeriod(INITIAL_STATE, LOG_ID, 3);
    const attempt = rewriteFromCompromise(records, compromise, 2, 'forged earlier event');
    const report = verifyAuthenticatedLog(attempt.records, trust());

    expect(attempt.attackerCanRetag).toBe(false);
    expect(report.integrity).toBe('INVALID');
    expect(report.integrityReason).toBe('TAG_MISMATCH');
    expect(report.firstInvalidIndex).toBe(2);
  });

  it('can retag a rewrite exactly at c and all dependent later links', () => {
    const records = makeLog('FORWARD_SECURE', 'honest shutdown');
    const compromise = compromiseBeforePeriod(INITIAL_STATE, LOG_ID, 3);
    const attempt = rewriteFromCompromise(records, compromise, 3, 'forged boundary event');
    const report = verifyAuthenticatedLog(attempt.records, trust());

    expect(attempt.attackerCanRetag).toBe(true);
    expect(report.integrity).toBe('VALID');
    expect(attempt.records[2].tag).toBe(records[2].tag);
    expect(attempt.records[3].tag).not.toBe(records[3].tag);
    expect(attempt.records[4].tag).not.toBe(records[4].tag);
  });

  it('can derive forward from S_c to rewrite a later period', () => {
    const records = makeLog('FORWARD_SECURE', 'honest shutdown');
    const compromise = compromiseBeforePeriod(INITIAL_STATE, LOG_ID, 2);
    const attempt = rewriteFromCompromise(records, compromise, 4, 'forged close');
    expect(attempt.attackerCanRetag).toBe(true);
    expect(verifyAuthenticatedLog(attempt.records, trust()).integrity).toBe('VALID');
    expect(attempt.records.slice(0, 4)).toEqual(records.slice(0, 4));
  });

  it('lets a compromised static master retag records before c', () => {
    const records = makeLog('STATIC', 'honest shutdown');
    const compromise = compromiseBeforePeriod(INITIAL_STATE, LOG_ID, 3, 'STATIC');
    const attempt = rewriteFromCompromise(records, compromise, 1, 'forged old event');
    expect(attempt.attackerCanRetag).toBe(true);
    expect(verifyAuthenticatedLog(attempt.records, trust('STATIC')).integrity).toBe('VALID');
  });

  it('shows which retained checkpoint does and does not cover a forged suffix', () => {
    const records = makeLog('FORWARD_SECURE', 'honest shutdown');
    const beforeTarget = createRetainedCheckpoint(records, 2);
    const throughTarget = createRetainedCheckpoint(records, 4);
    const compromise = compromiseBeforePeriod(INITIAL_STATE, LOG_ID, 3);
    const forged = rewriteFromCompromise(records, compromise, 3, 'forged').records;

    expect(
      verifyAuthenticatedLog(forged, trust('FORWARD_SECURE', { checkpoint: beforeTarget }))
        .consistency,
    ).toBe('CONSISTENT');
    expect(
      verifyAuthenticatedLog(forged, trust('FORWARD_SECURE', { checkpoint: throughTarget }))
        .consistency,
    ).toBe('INCONSISTENT');
  });

  it('does not make the wrong compromised state into a valid suffix', () => {
    const records = makeLog('FORWARD_SECURE', 'honest shutdown');
    const compromise = compromiseBeforePeriod(new Uint8Array(32).fill(0xa5), LOG_ID, 2);
    const forged = forgeSuffixFromCompromise(records, compromise, [
      { kind: 'EVENT', message: 'counterfeit' },
      { kind: 'CLOSE', message: 'counterfeit close' },
    ]);
    expect(verifyAuthenticatedLog(forged, trust()).integrity).toBe('INVALID');
  });
});

describe('truncation, early close, and replay', () => {
  it('treats deletion of an honest CLOSE as a valid prefix absent external context', () => {
    const complete = makeLog('FORWARD_SECURE', 'honest shutdown');
    const prefix = complete.slice(0, -1);
    const noExpectation = verifyAuthenticatedLog(prefix, trust());
    expect(noExpectation.integrity).toBe('VALID');
    expect(noExpectation.completeness).toBe('UNKNOWN');
    expect(noExpectation.freshness).toBe('UNKNOWN');
  });

  it('detects honest-close truncation when the close period is externally expected', () => {
    const complete = makeLog('FORWARD_SECURE', 'honest shutdown');
    const prefix = complete.slice(0, -1);
    const report = verifyAuthenticatedLog(
      prefix,
      trust('FORWARD_SECURE', { expectedClosePeriod: 4 }),
    );
    expect(report.integrity).toBe('VALID');
    expect(report.completeness).toBe('TRUNCATED');
    expect(report.freshness).toBe('UNKNOWN');
  });

  it('detects truncation against a retained checkpoint containing the honest close', () => {
    const complete = makeLog('FORWARD_SECURE', 'honest shutdown');
    const checkpoint = createRetainedCheckpoint(complete);
    const report = verifyAuthenticatedLog(
      complete.slice(0, -1),
      trust('FORWARD_SECURE', { checkpoint }),
    );
    expect(report.integrity).toBe('VALID');
    expect(report.consistency).toBe('INCONSISTENT');
    expect(report.freshness).toBe('UNKNOWN');
  });

  it('accepts a forged early close after pre-close compromise unless a close bound exists', () => {
    const records = makeLog('FORWARD_SECURE', 'honest shutdown');
    const compromise = compromiseBeforePeriod(INITIAL_STATE, LOG_ID, 2);
    const forgedEarlyClose = forgeSuffixFromCompromise(records, compromise, [
      { kind: 'CLOSE', message: 'attacker claims shutdown' },
    ]);

    const unbounded = verifyAuthenticatedLog(forgedEarlyClose, trust());
    expect(unbounded.integrity).toBe('VALID');
    expect(unbounded.completeness).toBe('UNKNOWN');
    expect(unbounded.freshness).toBe('UNKNOWN');

    const bounded = verifyAuthenticatedLog(
      forgedEarlyClose,
      trust('FORWARD_SECURE', { expectedClosePeriod: 4 }),
    );
    expect(bounded.completeness).toBe('EARLY_CLOSE');
    expect(bounded.freshness).toBe('UNKNOWN');
  });

  it('cannot recognize a stale but valid closed replay without trusted freshness', () => {
    const stale = makeLog('FORWARD_SECURE', 'old close', EVENTS.slice(0, 2));
    const noFreshness = verifyAuthenticatedLog(stale, trust());
    expect(noFreshness.integrity).toBe('VALID');
    expect(noFreshness.completeness).toBe('UNKNOWN');
    expect(noFreshness.freshness).toBe('UNKNOWN');

    const expectedNewer = verifyAuthenticatedLog(
      stale,
      trust('FORWARD_SECURE', { trustedMinimumRecords: 5 }),
    );
    expect(expectedNewer.freshness).toBe('STALE');
  });
});

describe('negative structure and tamper cases', () => {
  it.each([
    ['message', (records: Record<string, unknown>[]) => (records[1].message = 'tampered')],
    ['tag', (records: Record<string, unknown>[]) => (records[1].tag = 'ff'.repeat(32))],
  ])('rejects a changed %s', (_name, mutate) => {
    const records = copies(makeLog());
    mutate(records);
    const report = verifyAuthenticatedLog(records, trust());
    expect(report.integrity).toBe('INVALID');
    expect(report.integrityReason).toBe('TAG_MISMATCH');
  });

  it('rejects a changed previous tag before attempting the record MAC', () => {
    const records = copies(makeLog());
    records[2].previousTag = 'ff'.repeat(32);
    expect(verifyAuthenticatedLog(records, trust()).integrityReason).toBe('PREVIOUS_TAG_MISMATCH');
  });

  it('rejects deletion as a period gap', () => {
    const records = copies(makeLog());
    records.splice(1, 1);
    const report = verifyAuthenticatedLog(records, trust());
    expect(report.integrityReason).toBe('PERIOD_GAP');
    expect(report.firstInvalidIndex).toBe(1);
  });

  it('rejects record reordering', () => {
    const records = copies(makeLog());
    [records[1], records[2]] = [records[2], records[1]];
    expect(verifyAuthenticatedLog(records, trust()).integrityReason).toBe('PERIOD_GAP');
  });

  it('rejects malformed and noncanonical record encodings', () => {
    expect(verifyAuthenticatedLog([null], trust()).integrityReason).toBe('MALFORMED_RECORD');
    const records = copies(makeLog());
    records[0].tag = String(records[0].tag).toUpperCase();
    expect(verifyAuthenticatedLog(records, trust()).integrityReason).toBe('MALFORMED_RECORD');
  });

  it('rejects ill-formed Unicode instead of authenticating encoder replacement collisions', () => {
    expect(() =>
      buildAuthenticatedLog({
        scheme: 'FORWARD_SECURE',
        initialState: INITIAL_STATE,
        logId: LOG_ID,
        events: ['\ud800'],
      }),
    ).toThrow(/well-formed UTF-16/);
    expect(() =>
      buildAuthenticatedLog({
        scheme: 'FORWARD_SECURE',
        initialState: INITIAL_STATE,
        logId: '\ud801',
        events: ['event'],
      }),
    ).toThrow(/well-formed UTF-16/);

    const records = copies(makeLog());
    records[0].message = '\ud802';
    expect(verifyAuthenticatedLog(records, trust()).integrityReason).toBe('MALFORMED_RECORD');
  });

  it('rejects extra and inherited record fields that are not authenticated', () => {
    const extra = copies(makeLog());
    extra[0].unauthenticatedDecision = 'ALLOW';
    expect(verifyAuthenticatedLog(extra, trust()).integrityReason).toBe('MALFORMED_RECORD');

    const inherited = copies(makeLog());
    inherited[0] = Object.assign(Object.create({ unauthenticatedDecision: 'ALLOW' }), inherited[0]);
    expect(verifyAuthenticatedLog(inherited, trust()).integrityReason).toBe('MALFORMED_RECORD');
  });

  it('rejects the wrong scheme and log identifier', () => {
    const records = makeLog();
    expect(verifyAuthenticatedLog(records, trust('STATIC')).integrityReason).toBe(
      'SCHEME_MISMATCH',
    );
    expect(
      verifyAuthenticatedLog(records, { ...trust(), logId: 'unexpected-log' }).integrityReason,
    ).toBe('LOG_ID_MISMATCH');
  });

  it('rejects any record after CLOSE even before its tag is considered', () => {
    const closed = copies(makeLog('FORWARD_SECURE', 'close', ['one']));
    closed.push({
      ...closed[0],
      period: 2,
      previousTag: closed[1].tag,
      message: 'after close',
    });
    expect(verifyAuthenticatedLog(closed, trust()).integrityReason).toBe('RECORD_AFTER_CLOSE');
  });

  it('reports checkpoint consistency as unknown when record integrity already failed', () => {
    const good = makeLog();
    const checkpoint = createRetainedCheckpoint(good, 2);
    const changed = copies(good);
    changed[0].message = 'tampered';
    expect(
      verifyAuthenticatedLog(changed, trust('FORWARD_SECURE', { checkpoint })).consistency,
    ).toBe('UNKNOWN');
  });
});

describe('input and attack-helper validation', () => {
  it('rejects invalid trusted inputs', () => {
    expect(() =>
      buildAuthenticatedLog({
        scheme: 'FORWARD_SECURE',
        initialState: new Uint8Array(31),
        logId: LOG_ID,
        events: [],
      }),
    ).toThrow(/32 bytes/);
    expect(() => deriveLogState(INITIAL_STATE, '', 0)).toThrow(/non-empty/);
    expect(() => deriveLogState(INITIAL_STATE, LOG_ID, -1)).toThrow(/non-negative/);
    expect(() =>
      verifyAuthenticatedLog([], trust('FORWARD_SECURE', { trustedMinimumRecords: -1 })),
    ).toThrow(/non-negative/);
    expect(() =>
      verifyAuthenticatedLog([], trust('FORWARD_SECURE', { trustedMinimumRecords: 0 })),
    ).toThrow(/greater than zero/);
  });

  it('rejects invalid checkpoint and rewrite ranges', () => {
    const records = makeLog();
    const compromise = compromiseBeforePeriod(INITIAL_STATE, LOG_ID, 2);
    expect(() => createRetainedCheckpoint(records, 0)).toThrow(/at least one/);
    expect(() => rewriteFromCompromise(records, compromise, records.length, 'x')).toThrow(
      /identify a record/,
    );
    expect(() => rewriteFromCompromise(records, compromise, 1, '\ud800')).toThrow(
      /well-formed UTF-16/,
    );
    expect(() => forgeSuffixFromCompromise(records, { ...compromise, logId: 'other' }, [])).toThrow(
      /different identifiers/,
    );
    expect(() =>
      forgeSuffixFromCompromise(records, compromise, [
        { kind: 'CLOSE', message: 'close' },
        { kind: 'EVENT', message: 'after close' },
      ]),
    ).toThrow(/terminal/);
  });
});
