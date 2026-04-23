import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { encoder, decoder } from '../crypto/bytes';
import { open } from './open';
import { rewrapEnvelope } from './rotate';
import { seal } from './seal';
import { auditLog } from '../kms/audit-log';
import { kekStore } from '../kms/kek-store';
import { kmsApi } from '../kms/kms-api';

beforeEach(() => {
  auditLog.clear();
  kekStore.clear();
});

afterEach(() => {
  auditLog.clear();
  kekStore.clear();
});

describe('envelope round-trip', () => {
  it('seals and opens under the same KEK', async () => {
    const { keyId } = await kmsApi.CreateKey('AES256', 'test');
    const env = await seal(encoder.encode('top secret'), keyId, encoder.encode('aad=v1'));
    expect(env.iv.length).toBe(12);
    expect(env.tag.length).toBe(16);
    expect(env.wrappedDEK.length).toBe(40); // 32B DEK + 8B integrity
    const opened = await open(env);
    expect(decoder.decode(opened)).toBe('top secret');
  });

  it('decryption fails with wrong AAD', async () => {
    const { keyId } = await kmsApi.CreateKey('AES256', 'test');
    const env = await seal(encoder.encode('top secret'), keyId, encoder.encode('aad=v1'));
    const tampered = { ...env, aad: encoder.encode('aad=v2') };
    await expect(open(tampered)).rejects.toThrow();
  });

  it('old envelopes still decrypt after KEK rotation (decrypt-only versions)', async () => {
    const { keyId } = await kmsApi.CreateKey('AES256', 'test');
    const env = await seal(encoder.encode('pre-rotation'), keyId, encoder.encode('aad=v1'));
    const beforeVersion = env.kekVersion;
    await kmsApi.RotateKey(keyId, 'test');
    expect(kekStore.getCurrentVersion(keyId)).toBe(beforeVersion + 1);

    // The original envelope still references the old version and must open.
    const opened = await open(env);
    expect(decoder.decode(opened)).toBe('pre-rotation');
  });

  it('re-wrap migrates an envelope to the new active KEK version', async () => {
    const { keyId } = await kmsApi.CreateKey('AES256', 'test');
    const env = await seal(encoder.encode('migrate me'), keyId, encoder.encode('aad=v1'));
    await kmsApi.RotateKey(keyId, 'test');
    const rewrapped = await rewrapEnvelope(env, keyId);
    expect(rewrapped.kekVersion).toBe(env.kekVersion + 1);
    expect(decoder.decode(await open(rewrapped))).toBe('migrate me');
  });

  it('cross-KEK isolation: a DEK wrapped under tenant A cannot be unwrapped by tenant B', async () => {
    const a = await kmsApi.CreateKey('AES256', 'tenant-a');
    const b = await kmsApi.CreateKey('AES256', 'tenant-b');
    const env = await seal(encoder.encode('tenant-a payload'), a.keyId, encoder.encode('t=a'));

    const tampered = { ...env, kekId: b.keyId };
    await expect(open(tampered)).rejects.toThrow();
  });
});
