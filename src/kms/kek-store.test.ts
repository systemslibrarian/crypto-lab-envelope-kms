import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { KekStore } from './kek-store';

let store: KekStore;

beforeEach(() => {
  store = new KekStore();
});

afterEach(() => {
  store.clear();
});

describe('KekStore', () => {
  it('creates a key with version 1 active', () => {
    const { keyId, version } = store.createKey();
    expect(version).toBe(1);
    expect(store.getCurrentVersion(keyId)).toBe(1);
    const meta = store.exportMetadata().find((k) => k.keyId === keyId)!;
    expect(meta.versions[0].status).toBe('active');
  });

  it('rotate marks the old version decrypt-only and adds a new active version', () => {
    const { keyId } = store.createKey();
    const r = store.rotateKey(keyId);
    expect(r.version).toBe(2);
    const meta = store.exportMetadata().find((k) => k.keyId === keyId)!;
    expect(meta.versions[0].status).toBe('decrypt-only');
    expect(meta.versions[1].status).toBe('active');
  });

  it('getMaterialForUnwrap on an old version still works while in grace', () => {
    const { keyId } = store.createKey();
    const v1 = store.getMaterialForWrap(keyId).material;
    store.rotateKey(keyId);
    const v1Again = store.getMaterialForUnwrap(keyId, 1);
    expect(Array.from(v1)).toEqual(Array.from(v1Again));
  });

  it('returned material is a defensive copy (mutation does not affect store)', () => {
    const { keyId } = store.createKey();
    const m1 = store.getMaterialForWrap(keyId).material;
    m1.fill(0xff);
    const m2 = store.getMaterialForWrap(keyId).material;
    expect(m2.some((b) => b !== 0xff)).toBe(true);
  });

  it('schedule deletion sets all versions to decrypt-only with notAfter', () => {
    const { keyId } = store.createKey();
    store.rotateKey(keyId);
    store.scheduleDeletion(keyId, 7);
    const meta = store.exportMetadata().find((k) => k.keyId === keyId)!;
    expect(meta.scheduledDeletionAt).toBeDefined();
    expect(meta.versions.every((v) => v.status === 'decrypt-only')).toBe(true);
    expect(() => store.getCurrentVersion(keyId)).toThrow();
  });

  it('throws on unknown key', () => {
    expect(() => store.getCurrentVersion('does-not-exist')).toThrow();
    expect(() => store.getMaterialForUnwrap('does-not-exist', 1)).toThrow();
  });

  it('throws on unknown version', () => {
    const { keyId } = store.createKey();
    expect(() => store.getMaterialForUnwrap(keyId, 99)).toThrow();
  });
});
