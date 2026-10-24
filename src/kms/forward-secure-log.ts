import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, encoder, equalBytes, zeroize } from '../crypto/bytes';

export const AUTHENTICATED_LOG_VERSION = 1 as const;
export const AUTHENTICATED_LOG_KEY_BYTES = 32;
export const AUTHENTICATED_LOG_TAG_BYTES = 32;
export const AUTHENTICATED_LOG_GENESIS_TAG = '00'.repeat(AUTHENTICATED_LOG_TAG_BYTES);

const TAG_KEY_DOMAIN = encoder.encode('crypto-lab/envelope-kms/log/v1/tag-key');
const UPDATE_DOMAIN = encoder.encode('crypto-lab/envelope-kms/log/v1/update');
const RECORD_DOMAIN = encoder.encode('crypto-lab/envelope-kms/log/v1/record');
const RECORD_KEYS = Object.freeze([
  'kind',
  'logId',
  'message',
  'period',
  'previousTag',
  'scheme',
  'tag',
  'version',
]);

export type AuthenticatedLogScheme = 'FORWARD_SECURE' | 'STATIC';
export type AuthenticatedLogRecordKind = 'EVENT' | 'CLOSE';

export type AuthenticatedLogRecord = Readonly<{
  version: typeof AUTHENTICATED_LOG_VERSION;
  scheme: AuthenticatedLogScheme;
  logId: string;
  period: number;
  kind: AuthenticatedLogRecordKind;
  message: string;
  previousTag: string;
  tag: string;
}>;

export type LogRecordDraft = Readonly<{
  kind: AuthenticatedLogRecordKind;
  message: string;
}>;

export type BuildAuthenticatedLogOptions = Readonly<{
  scheme: AuthenticatedLogScheme;
  initialState: Uint8Array;
  logId: string;
  events: readonly string[];
  /** When present, appends one terminal CLOSE record after all events. */
  closeMessage?: string;
}>;

/** S_c exposed immediately before the logger authenticates period c. */
export type CompromiseMaterial = Readonly<{
  scheme: AuthenticatedLogScheme;
  logId: string;
  beforePeriod: number;
  state: Uint8Array;
}>;

export type RewriteAttempt = Readonly<{
  compromisePeriod: number;
  targetPeriod: number;
  attackerCanRetag: boolean;
  records: readonly AuthenticatedLogRecord[];
}>;

export type RetainedCheckpoint = Readonly<{
  version: typeof AUTHENTICATED_LOG_VERSION;
  scheme: AuthenticatedLogScheme;
  logId: string;
  recordCount: number;
  lastTag: string;
}>;

export type VerificationTrust = Readonly<{
  scheme: AuthenticatedLogScheme;
  logId: string;
  initialState: Uint8Array;
  /** A copy retained outside the logging machine. */
  checkpoint?: RetainedCheckpoint;
  /** A trusted operational expectation, not a fact inferred from the log. */
  expectedClosePeriod?: number;
  /** A trusted external lower bound used only for the freshness result. */
  trustedMinimumRecords?: number;
}>;

export type IntegrityFailureReason =
  | 'MALFORMED_RECORD'
  | 'SCHEME_MISMATCH'
  | 'LOG_ID_MISMATCH'
  | 'PERIOD_GAP'
  | 'PREVIOUS_TAG_MISMATCH'
  | 'TAG_MISMATCH'
  | 'RECORD_AFTER_CLOSE';

export type VerificationReport = Readonly<{
  integrity: 'VALID' | 'INVALID';
  integrityReason: IntegrityFailureReason | null;
  firstInvalidIndex: number | null;
  authenticatedRecords: number;
  consistency: 'CONSISTENT' | 'INCONSISTENT' | 'NOT_CHECKED' | 'UNKNOWN';
  completeness: 'COMPLETE' | 'TRUNCATED' | 'EARLY_CLOSE' | 'LATE_CLOSE' | 'UNKNOWN';
  freshness: 'CURRENT_TO_TRUSTED_BOUND' | 'STALE' | 'UNKNOWN';
  closePeriod: number | null;
  trustedMinimumRecords: number | null;
}>;

type IntegrityCheck = {
  valid: boolean;
  reason: IntegrityFailureReason | null;
  firstInvalidIndex: number | null;
  authenticatedRecords: number;
  parsed: AuthenticatedLogRecord[];
};

function assertBytes(value: Uint8Array, name: string): void {
  if (!(value instanceof Uint8Array)) throw new TypeError(`${name} must be a Uint8Array.`);
}

function assertInitialState(value: Uint8Array): void {
  assertBytes(value, 'initialState');
  if (value.length !== AUTHENTICATED_LOG_KEY_BYTES) {
    throw new RangeError(`initialState must contain ${AUTHENTICATED_LOG_KEY_BYTES} bytes.`);
  }
}

function assertScheme(value: unknown): asserts value is AuthenticatedLogScheme {
  if (value !== 'FORWARD_SECURE' && value !== 'STATIC') {
    throw new TypeError('scheme must be FORWARD_SECURE or STATIC.');
  }
}

function isWellFormedUtf16(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function assertText(value: unknown, name: string): asserts value is string {
  if (typeof value !== 'string' || !isWellFormedUtf16(value)) {
    throw new TypeError(`${name} must be a well-formed UTF-16 string.`);
  }
}

function assertLogId(value: unknown): asserts value is string {
  assertText(value, 'logId');
  if (value.length === 0) {
    throw new TypeError('logId must be a non-empty string.');
  }
}

function assertPeriod(value: unknown, name: string): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new RangeError(`${name} must be a non-negative safe integer.`);
  }
}

function assertDraft(value: unknown): asserts value is LogRecordDraft {
  if (
    value === null ||
    typeof value !== 'object' ||
    ((value as { kind?: unknown }).kind !== 'EVENT' &&
      (value as { kind?: unknown }).kind !== 'CLOSE') ||
    typeof (value as { message?: unknown }).message !== 'string'
  ) {
    throw new TypeError('Each record draft needs an EVENT or CLOSE kind and a string message.');
  }
  assertText((value as { message: string }).message, 'record message');
}

function u32(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new RangeError('A framed field exceeds the unsigned 32-bit length limit.');
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function u64(value: number): Uint8Array {
  assertPeriod(value, 'period');
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), false);
  return out;
}

/**
 * Frames every field as uint32-be length || bytes and prefixes the field count.
 * This prevents concatenation ambiguities such as ("ab", "c") vs ("a", "bc").
 */
function frame(fields: readonly Uint8Array[]): Uint8Array {
  const framed: Uint8Array[] = [u32(fields.length)];
  for (const field of fields) {
    assertBytes(field, 'framed field');
    framed.push(u32(field.length), field);
  }
  return concatBytes(...framed);
}

function strictHexToBytes(value: string): Uint8Array {
  if (!/^[0-9a-f]+$/.test(value) || value.length % 2 !== 0) {
    throw new TypeError('Expected canonical lower-case hexadecimal bytes.');
  }
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** RFC 2104 HMAC-SHA-256, exposed so the RFC 4231 KAT can test this dependency. */
export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  assertBytes(key, 'HMAC key');
  assertBytes(message, 'HMAC message');
  return hmac(sha256, key, message);
}

function tagKeyForPeriod(
  state: Uint8Array,
  scheme: AuthenticatedLogScheme,
  logId: string,
  period: number,
): Uint8Array {
  return hmacSha256(
    state,
    frame([TAG_KEY_DOMAIN, encoder.encode(scheme), encoder.encode(logId), u64(period)]),
  );
}

function nextForwardState(state: Uint8Array, logId: string, period: number): Uint8Array {
  return hmacSha256(
    state,
    frame([UPDATE_DOMAIN, encoder.encode('FORWARD_SECURE'), encoder.encode(logId), u64(period)]),
  );
}

/**
 * Derives S_period. In the forward-secure mode, S_i and its separate tag key
 * are intended to be erased after period i; JavaScript can only model that with
 * best-effort zeroization of owned byte arrays. STATIC intentionally returns the
 * unchanged master state so compromise reveals authentication ability for every
 * period.
 */
export function deriveLogState(
  initialState: Uint8Array,
  logId: string,
  period: number,
  scheme: AuthenticatedLogScheme = 'FORWARD_SECURE',
): Uint8Array {
  assertInitialState(initialState);
  assertLogId(logId);
  assertPeriod(period, 'period');
  assertScheme(scheme);
  let state: Uint8Array = initialState.slice();
  if (scheme === 'STATIC') return state;
  for (let i = 0; i < period; i += 1) {
    const next = nextForwardState(state, logId, i);
    zeroize(state);
    state = next;
  }
  return state;
}

function recordMacInput(
  scheme: AuthenticatedLogScheme,
  logId: string,
  period: number,
  kind: AuthenticatedLogRecordKind,
  message: string,
  previousTag: Uint8Array,
): Uint8Array {
  return frame([
    RECORD_DOMAIN,
    new Uint8Array([AUTHENTICATED_LOG_VERSION]),
    encoder.encode(scheme),
    encoder.encode(logId),
    u64(period),
    encoder.encode(kind),
    encoder.encode(message),
    previousTag,
  ]);
}

function makeRecord(
  state: Uint8Array,
  scheme: AuthenticatedLogScheme,
  logId: string,
  period: number,
  draft: LogRecordDraft,
  previousTag: Uint8Array,
): AuthenticatedLogRecord {
  const tagKey = tagKeyForPeriod(state, scheme, logId, period);
  try {
    const tag = hmacSha256(
      tagKey,
      recordMacInput(scheme, logId, period, draft.kind, draft.message, previousTag),
    );
    return Object.freeze({
      version: AUTHENTICATED_LOG_VERSION,
      scheme,
      logId,
      period,
      kind: draft.kind,
      message: draft.message,
      previousTag: bytesToHex(previousTag),
      tag: bytesToHex(tag),
    });
  } finally {
    zeroize(tagKey);
  }
}

function advanceOwnedState(
  state: Uint8Array,
  scheme: AuthenticatedLogScheme,
  logId: string,
  period: number,
): Uint8Array {
  if (scheme === 'STATIC') return state;
  const next = nextForwardState(state, logId, period);
  zeroize(state);
  return next;
}

function buildFromDrafts(
  scheme: AuthenticatedLogScheme,
  logId: string,
  stateAtFirstPeriod: Uint8Array,
  firstPeriod: number,
  previousTag: Uint8Array,
  prefix: readonly AuthenticatedLogRecord[],
  drafts: readonly LogRecordDraft[],
): readonly AuthenticatedLogRecord[] {
  let state: Uint8Array = stateAtFirstPeriod.slice();
  let previous: Uint8Array = previousTag.slice();
  const out = prefix.map((record) => Object.freeze({ ...record }));
  let closed = out.some((record) => record.kind === 'CLOSE');
  try {
    for (let offset = 0; offset < drafts.length; offset += 1) {
      const draft = drafts[offset];
      assertDraft(draft);
      if (closed) throw new Error('A CLOSE record must be terminal.');
      const period = firstPeriod + offset;
      const record = makeRecord(state, scheme, logId, period, draft, previous);
      out.push(record);
      zeroize(previous);
      previous = strictHexToBytes(record.tag);
      closed = draft.kind === 'CLOSE';
      state = advanceOwnedState(state, scheme, logId, period);
    }
    return Object.freeze(out);
  } finally {
    zeroize(state);
    zeroize(previous);
  }
}

export function buildAuthenticatedLog(
  options: BuildAuthenticatedLogOptions,
): readonly AuthenticatedLogRecord[] {
  assertScheme(options.scheme);
  assertInitialState(options.initialState);
  assertLogId(options.logId);
  if (!Array.isArray(options.events) || options.events.some((event) => typeof event !== 'string')) {
    throw new TypeError('events must be an array of strings.');
  }
  if (options.closeMessage !== undefined && typeof options.closeMessage !== 'string') {
    throw new TypeError('closeMessage must be a string when present.');
  }
  const drafts: LogRecordDraft[] = options.events.map((message) => ({ kind: 'EVENT', message }));
  if (options.closeMessage !== undefined) {
    drafts.push({ kind: 'CLOSE', message: options.closeMessage });
  }
  return buildFromDrafts(
    options.scheme,
    options.logId,
    options.initialState,
    0,
    new Uint8Array(AUTHENTICATED_LOG_TAG_BYTES),
    [],
    drafts,
  );
}

export function compromiseBeforePeriod(
  initialState: Uint8Array,
  logId: string,
  beforePeriod: number,
  scheme: AuthenticatedLogScheme = 'FORWARD_SECURE',
): CompromiseMaterial {
  return Object.freeze({
    scheme,
    logId,
    beforePeriod,
    state: deriveLogState(initialState, logId, beforePeriod, scheme),
  });
}

function isRecord(value: unknown): value is AuthenticatedLogRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== RECORD_KEYS.length ||
    ownKeys.some((key) => typeof key !== 'string' || !RECORD_KEYS.includes(key))
  ) {
    return false;
  }
  const record = value as Partial<AuthenticatedLogRecord>;
  return (
    record.version === AUTHENTICATED_LOG_VERSION &&
    (record.scheme === 'FORWARD_SECURE' || record.scheme === 'STATIC') &&
    typeof record.logId === 'string' &&
    record.logId.length > 0 &&
    isWellFormedUtf16(record.logId) &&
    Number.isSafeInteger(record.period) &&
    (record.period as number) >= 0 &&
    (record.kind === 'EVENT' || record.kind === 'CLOSE') &&
    typeof record.message === 'string' &&
    isWellFormedUtf16(record.message) &&
    typeof record.previousTag === 'string' &&
    /^[0-9a-f]{64}$/.test(record.previousTag) &&
    typeof record.tag === 'string' &&
    /^[0-9a-f]{64}$/.test(record.tag)
  );
}

function assertAttackInputs(
  records: readonly AuthenticatedLogRecord[],
  compromise: CompromiseMaterial,
): void {
  if (!Array.isArray(records)) throw new TypeError('records must be an array.');
  assertScheme(compromise.scheme);
  assertLogId(compromise.logId);
  assertPeriod(compromise.beforePeriod, 'beforePeriod');
  assertInitialState(compromise.state);
  if (compromise.beforePeriod > records.length) {
    throw new RangeError('The compromise period cannot be after the supplied log.');
  }
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (!isRecord(record)) throw new TypeError(`Record ${index} is malformed.`);
    if (record.scheme !== compromise.scheme || record.logId !== compromise.logId) {
      throw new Error('The compromise material and log use different identifiers or schemes.');
    }
    if (record.period !== index) throw new Error('Attack helpers require a contiguous source log.');
  }
}

/** Replaces the entire suffix beginning exactly at the compromise boundary. */
export function forgeSuffixFromCompromise(
  records: readonly AuthenticatedLogRecord[],
  compromise: CompromiseMaterial,
  suffix: readonly LogRecordDraft[],
): readonly AuthenticatedLogRecord[] {
  assertAttackInputs(records, compromise);
  if (!Array.isArray(suffix)) throw new TypeError('suffix must be an array.');
  const prefix = records.slice(0, compromise.beforePeriod);
  const previousTag =
    prefix.length === 0
      ? new Uint8Array(AUTHENTICATED_LOG_TAG_BYTES)
      : strictHexToBytes(prefix[prefix.length - 1].tag);
  return buildFromDrafts(
    compromise.scheme,
    compromise.logId,
    compromise.state,
    compromise.beforePeriod,
    previousTag,
    prefix,
    suffix,
  );
}

/**
 * Attempts one rewrite using only S_c exposed immediately before period c.
 * A forward-secure target before c is changed without a usable replacement tag,
 * so verification will reject it. A target at/after c can be retagged. In the
 * STATIC comparison, the compromised state authenticates every period.
 */
export function rewriteFromCompromise(
  records: readonly AuthenticatedLogRecord[],
  compromise: CompromiseMaterial,
  targetPeriod: number,
  replacementMessage: string,
): RewriteAttempt {
  assertAttackInputs(records, compromise);
  assertPeriod(targetPeriod, 'targetPeriod');
  if (targetPeriod >= records.length) throw new RangeError('targetPeriod must identify a record.');
  assertText(replacementMessage, 'replacementMessage');

  const canRetag = compromise.scheme === 'STATIC' || targetPeriod >= compromise.beforePeriod;
  if (!canRetag) {
    const changed = records.map((record, index) =>
      Object.freeze(
        index === targetPeriod ? { ...record, message: replacementMessage } : { ...record },
      ),
    );
    return Object.freeze({
      compromisePeriod: compromise.beforePeriod,
      targetPeriod,
      attackerCanRetag: false,
      records: Object.freeze(changed),
    });
  }

  let state: Uint8Array = compromise.state.slice();
  if (compromise.scheme === 'FORWARD_SECURE') {
    for (let period = compromise.beforePeriod; period < targetPeriod; period += 1) {
      const next = nextForwardState(state, compromise.logId, period);
      zeroize(state);
      state = next;
    }
  }
  const prefix = records.slice(0, targetPeriod);
  const previousTag: Uint8Array =
    prefix.length === 0
      ? new Uint8Array(AUTHENTICATED_LOG_TAG_BYTES)
      : strictHexToBytes(prefix[prefix.length - 1].tag);
  const suffix = records.slice(targetPeriod).map((record, index) => ({
    kind: record.kind,
    message: index === 0 ? replacementMessage : record.message,
  }));
  try {
    const forged = buildFromDrafts(
      compromise.scheme,
      compromise.logId,
      state,
      targetPeriod,
      previousTag,
      prefix,
      suffix,
    );
    return Object.freeze({
      compromisePeriod: compromise.beforePeriod,
      targetPeriod,
      attackerCanRetag: true,
      records: forged,
    });
  } finally {
    zeroize(state);
    zeroize(previousTag);
  }
}

export function createRetainedCheckpoint(
  records: readonly AuthenticatedLogRecord[],
  recordCount = records.length,
): RetainedCheckpoint {
  if (!Array.isArray(records)) throw new TypeError('records must be an array.');
  assertPeriod(recordCount, 'recordCount');
  if (recordCount === 0 || recordCount > records.length) {
    throw new RangeError('recordCount must select at least one supplied record.');
  }
  const selected = records[recordCount - 1];
  if (!isRecord(selected) || selected.period !== recordCount - 1) {
    throw new TypeError('The selected checkpoint record is malformed or out of sequence.');
  }
  return Object.freeze({
    version: AUTHENTICATED_LOG_VERSION,
    scheme: selected.scheme,
    logId: selected.logId,
    recordCount,
    lastTag: selected.tag,
  });
}

function verifyIntegrity(records: readonly unknown[], trust: VerificationTrust): IntegrityCheck {
  let state: Uint8Array = trust.initialState.slice();
  let previous: Uint8Array = new Uint8Array(AUTHENTICATED_LOG_TAG_BYTES);
  const parsed: AuthenticatedLogRecord[] = [];
  let authenticatedRecords = 0;
  let sawClose = false;
  try {
    for (let index = 0; index < records.length; index += 1) {
      const value = records[index];
      if (!isRecord(value)) {
        return {
          valid: false,
          reason: 'MALFORMED_RECORD',
          firstInvalidIndex: index,
          authenticatedRecords,
          parsed,
        };
      }
      const record = value;
      if (record.scheme !== trust.scheme) {
        return {
          valid: false,
          reason: 'SCHEME_MISMATCH',
          firstInvalidIndex: index,
          authenticatedRecords,
          parsed,
        };
      }
      if (record.logId !== trust.logId) {
        return {
          valid: false,
          reason: 'LOG_ID_MISMATCH',
          firstInvalidIndex: index,
          authenticatedRecords,
          parsed,
        };
      }
      if (record.period !== index) {
        return {
          valid: false,
          reason: 'PERIOD_GAP',
          firstInvalidIndex: index,
          authenticatedRecords,
          parsed,
        };
      }
      if (sawClose) {
        return {
          valid: false,
          reason: 'RECORD_AFTER_CLOSE',
          firstInvalidIndex: index,
          authenticatedRecords,
          parsed,
        };
      }
      const storedPrevious = strictHexToBytes(record.previousTag);
      if (!equalBytes(storedPrevious, previous)) {
        zeroize(storedPrevious);
        return {
          valid: false,
          reason: 'PREVIOUS_TAG_MISMATCH',
          firstInvalidIndex: index,
          authenticatedRecords,
          parsed,
        };
      }
      zeroize(storedPrevious);
      const tagKey = tagKeyForPeriod(state, trust.scheme, trust.logId, index);
      let expected: Uint8Array;
      try {
        expected = hmacSha256(
          tagKey,
          recordMacInput(
            record.scheme,
            record.logId,
            record.period,
            record.kind,
            record.message,
            previous,
          ),
        );
      } finally {
        zeroize(tagKey);
      }
      const stored = strictHexToBytes(record.tag);
      const tagMatches = equalBytes(expected, stored);
      zeroize(stored);
      if (!tagMatches) {
        zeroize(expected);
        return {
          valid: false,
          reason: 'TAG_MISMATCH',
          firstInvalidIndex: index,
          authenticatedRecords,
          parsed,
        };
      }
      zeroize(previous);
      previous = expected;
      parsed.push(record);
      authenticatedRecords += 1;
      sawClose = record.kind === 'CLOSE';
      state = advanceOwnedState(state, trust.scheme, trust.logId, index);
    }
    return {
      valid: true,
      reason: null,
      firstInvalidIndex: null,
      authenticatedRecords,
      parsed,
    };
  } finally {
    zeroize(state);
    zeroize(previous);
  }
}

function isCheckpoint(value: unknown): value is RetainedCheckpoint {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const checkpoint = value as Partial<RetainedCheckpoint>;
  return (
    checkpoint.version === AUTHENTICATED_LOG_VERSION &&
    (checkpoint.scheme === 'FORWARD_SECURE' || checkpoint.scheme === 'STATIC') &&
    typeof checkpoint.logId === 'string' &&
    Number.isSafeInteger(checkpoint.recordCount) &&
    (checkpoint.recordCount as number) > 0 &&
    typeof checkpoint.lastTag === 'string' &&
    /^[0-9a-f]{64}$/.test(checkpoint.lastTag)
  );
}

export function verifyAuthenticatedLog(
  records: readonly unknown[],
  trust: VerificationTrust,
): VerificationReport {
  if (!Array.isArray(records)) throw new TypeError('records must be an array.');
  assertScheme(trust.scheme);
  assertLogId(trust.logId);
  assertInitialState(trust.initialState);
  if (trust.expectedClosePeriod !== undefined) {
    assertPeriod(trust.expectedClosePeriod, 'expectedClosePeriod');
  }
  if (trust.trustedMinimumRecords !== undefined) {
    assertPeriod(trust.trustedMinimumRecords, 'trustedMinimumRecords');
    if (trust.trustedMinimumRecords === 0) {
      throw new RangeError('trustedMinimumRecords must be greater than zero when present.');
    }
  }

  const checked = verifyIntegrity(records, trust);
  const close = checked.parsed.find((record) => record.kind === 'CLOSE') ?? null;

  let consistency: VerificationReport['consistency'] = 'NOT_CHECKED';
  if (trust.checkpoint !== undefined) {
    if (!checked.valid) {
      consistency = 'UNKNOWN';
    } else if (
      !isCheckpoint(trust.checkpoint) ||
      trust.checkpoint.scheme !== trust.scheme ||
      trust.checkpoint.logId !== trust.logId ||
      records.length < trust.checkpoint.recordCount ||
      checked.parsed[trust.checkpoint.recordCount - 1]?.tag !== trust.checkpoint.lastTag
    ) {
      consistency = 'INCONSISTENT';
    } else {
      consistency = 'CONSISTENT';
    }
  }

  let completeness: VerificationReport['completeness'] = 'UNKNOWN';
  if (checked.valid) {
    if (trust.expectedClosePeriod === undefined) {
      // A logger-only CLOSE is not a trusted completeness claim: an attacker
      // holding S_c can create an authenticated early CLOSE at period c.
      completeness = 'UNKNOWN';
    } else if (!close) {
      completeness = 'TRUNCATED';
    } else if (close.period < trust.expectedClosePeriod) {
      completeness = 'EARLY_CLOSE';
    } else if (close.period > trust.expectedClosePeriod) {
      completeness = 'LATE_CLOSE';
    } else {
      completeness = 'COMPLETE';
    }
  }

  // Neither a retained checkpoint nor an expected CLOSE establishes recency.
  // Freshness needs its own trusted heartbeat/receipt-derived lower bound.
  const minimumRecords = trust.trustedMinimumRecords ?? null;
  let freshness: VerificationReport['freshness'] = 'UNKNOWN';
  if (minimumRecords !== null) {
    if (records.length < minimumRecords) {
      freshness = 'STALE';
    } else if (checked.valid) {
      freshness = 'CURRENT_TO_TRUSTED_BOUND';
    }
  }

  return Object.freeze({
    integrity: checked.valid ? 'VALID' : 'INVALID',
    integrityReason: checked.reason,
    firstInvalidIndex: checked.firstInvalidIndex,
    authenticatedRecords: checked.authenticatedRecords,
    consistency,
    completeness,
    freshness,
    closePeriod: close?.period ?? null,
    trustedMinimumRecords: minimumRecords,
  });
}
