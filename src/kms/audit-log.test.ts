import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AuditLog } from './audit-log';

beforeEach(() => {
  // Use a fresh in-memory localStorage for each test
  const store = new Map<string, string>();
  (globalThis as { localStorage?: Storage }).localStorage = {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
    clear: () => store.clear(),
    key: (i: number) => Array.from(store.keys())[i] ?? null,
    get length() {
      return store.size;
    },
  } as Storage;
});

afterEach(() => {
  delete (globalThis as { localStorage?: Storage }).localStorage;
});

describe('AuditLog', () => {
  it('starts with GENESIS prev_hash and chains entries', () => {
    const log = new AuditLog();
    log.clear();
    const a = log.append({ operation: 'CreateKey', principal: 'test', success: true });
    const b = log.append({ operation: 'GenerateDataKey', principal: 'test', success: true });
    expect(a.prev_hash).toBe('GENESIS');
    expect(b.prev_hash).toBe(a.hash);
    expect(log.verify()).toEqual({ ok: true, brokenIndex: null });
  });

  it('verify() detects tampered details', () => {
    const log = new AuditLog();
    log.clear();
    log.append({ operation: 'CreateKey', principal: 'test', success: true });
    log.append({ operation: 'GenerateDataKey', principal: 'test', success: true });
    log.tamper(0, 'forged');
    const result = log.verify();
    expect(result.ok).toBe(false);
    expect(result.brokenIndex).toBe(0);
  });

  it('clear() empties the log', () => {
    const log = new AuditLog();
    log.append({ operation: 'CreateKey', principal: 'test', success: true });
    log.clear();
    expect(log.list()).toEqual([]);
    expect(log.verify()).toEqual({ ok: true, brokenIndex: null });
  });

  it('list() returns defensive copies', () => {
    const log = new AuditLog();
    log.clear();
    log.append({ operation: 'CreateKey', principal: 'test', success: true });
    const snapshot = log.list();
    snapshot[0].operation = 'Decrypt';
    expect(log.list()[0].operation).toBe('CreateKey');
  });

  it('survives a missing localStorage (Node environment)', () => {
    delete (globalThis as { localStorage?: Storage }).localStorage;
    const log = new AuditLog();
    expect(() => log.append({ operation: 'CreateKey', principal: 'x', success: true })).not.toThrow();
    expect(log.list().length).toBeGreaterThan(0);
    expect(log.verify().ok).toBe(true);
  });
});
