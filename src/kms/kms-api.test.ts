import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { decoder, encoder } from '../crypto/bytes';
import { auditLog } from './audit-log';
import { kekStore } from './kek-store';
import { kmsApi } from './kms-api';

beforeEach(() => {
  auditLog.clear();
  kekStore.clear();
});

afterEach(() => {
  auditLog.clear();
  kekStore.clear();
});

describe('KmsApi', () => {
  it('GenerateDataKey returns a 32-byte plaintext DEK and a 40-byte wrapped DEK', async () => {
    const { keyId, version } = await kmsApi.CreateKey('AES256', 'test');
    const dk = await kmsApi.GenerateDataKey(keyId, 32, 'test');
    expect(dk.plaintextDEK.length).toBe(32);
    // RFC 3394 wraps a 32B key into 40B (extra 64-bit integrity block).
    expect(dk.wrappedDEK.length).toBe(40);
    expect(dk.kekId).toBe(keyId);
    expect(dk.kekVersion).toBe(version);
  });

  it('GenerateDataKey rejects non-256-bit key lengths and audits the failure', async () => {
    const { keyId } = await kmsApi.CreateKey('AES256', 'test');
    await expect(kmsApi.GenerateDataKey(keyId, 16, 'test')).rejects.toThrow(/256-bit/);
    const failed = auditLog.list().find((e) => e.operation === 'GenerateDataKey' && !e.success);
    expect(failed).toBeTruthy();
  });

  it('Encrypt then DecryptEnvelope round-trips the plaintext', async () => {
    const { keyId } = await kmsApi.CreateKey('AES256', 'test');
    const aad = encoder.encode('ctx=demo');
    const enc = await kmsApi.Encrypt(
      { plaintext: encoder.encode('round trip me'), keyId, aad },
      'test',
    );
    expect(enc.iv.length).toBe(12);
    expect(enc.tag.length).toBe(16);
    const opened = await kmsApi.DecryptEnvelope({ ...enc }, 'test');
    expect(decoder.decode(opened)).toBe('round trip me');
  });

  it('Decrypt returns the same DEK that GenerateDataKey produced', async () => {
    const { keyId } = await kmsApi.CreateKey('AES256', 'test');
    const dk = await kmsApi.GenerateDataKey(keyId, 32, 'test');
    const expected = dk.plaintextDEK.slice();
    const recovered = await kmsApi.Decrypt(
      { wrappedDEK: dk.wrappedDEK, kekId: dk.kekId, kekVersion: dk.kekVersion },
      'test',
    );
    expect(Array.from(recovered)).toEqual(Array.from(expected));
  });

  it('Decrypt rejects a wrappedDEK from a different KEK', async () => {
    const a = await kmsApi.CreateKey('AES256', 'tenant-a');
    const b = await kmsApi.CreateKey('AES256', 'tenant-b');
    const dk = await kmsApi.GenerateDataKey(a.keyId, 32, 'test');
    await expect(
      kmsApi.Decrypt(
        { wrappedDEK: dk.wrappedDEK, kekId: b.keyId, kekVersion: dk.kekVersion },
        'test',
      ),
    ).rejects.toThrow();
  });

  it('ReEncrypt moves a wrapped DEK from a source KEK to a destination KEK', async () => {
    const src = await kmsApi.CreateKey('AES256', 'src');
    const dst = await kmsApi.CreateKey('AES256', 'dst');
    const dk = await kmsApi.GenerateDataKey(src.keyId, 32, 'test');
    const expected = dk.plaintextDEK.slice();
    const moved = await kmsApi.ReEncrypt(
      {
        wrappedDEK: dk.wrappedDEK,
        sourceKek: { wrappedDEK: dk.wrappedDEK, kekId: src.keyId, kekVersion: dk.kekVersion },
        destKek: { keyId: dst.keyId },
      },
      'test',
    );
    expect(moved.kekId).toBe(dst.keyId);
    // Unwrapping under the destination yields the original DEK bytes.
    const recovered = await kmsApi.Decrypt(moved, 'test');
    expect(Array.from(recovered)).toEqual(Array.from(expected));
  });

  it('RotateKey advances the active version and audits it', async () => {
    const { keyId, version } = await kmsApi.CreateKey('AES256', 'test');
    const rotated = await kmsApi.RotateKey(keyId, 'test');
    expect(rotated.version).toBe(version + 1);
    expect(kekStore.getCurrentVersion(keyId)).toBe(version + 1);
    expect(auditLog.list().some((e) => e.operation === 'RotateKey' && e.success)).toBe(true);
  });

  it('RotateKey on a missing key audits the failure and throws', async () => {
    await expect(kmsApi.RotateKey('does-not-exist', 'test')).rejects.toThrow();
    expect(auditLog.list().some((e) => e.operation === 'RotateKey' && !e.success)).toBe(true);
  });

  it('ScheduleKeyDeletion succeeds for a real key and fails for a missing one', async () => {
    const { keyId } = await kmsApi.CreateKey('AES256', 'test');
    await expect(kmsApi.ScheduleKeyDeletion(keyId, 7, 'test')).resolves.toBeUndefined();
    expect(auditLog.list().some((e) => e.operation === 'ScheduleKeyDeletion' && e.success)).toBe(
      true,
    );
    await expect(kmsApi.ScheduleKeyDeletion('nope', 7, 'test')).rejects.toThrow();
  });
});
