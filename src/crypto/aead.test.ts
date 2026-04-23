import { describe, expect, it } from 'vitest';
import { aeadOpen, aeadSeal } from './aead';

describe('AES-256-GCM AEAD', () => {
  const key = new Uint8Array(32).fill(0x42);
  const aad = new TextEncoder().encode('ctx=test');
  const plaintext = new TextEncoder().encode('hello envelope world');

  it('round-trips', async () => {
    const sealed = await aeadSeal(plaintext, key, aad);
    expect(sealed.iv.length).toBe(12);
    expect(sealed.tag.length).toBe(16);
    const opened = await aeadOpen(sealed.ciphertext, sealed.iv, sealed.tag, key, aad);
    expect(new TextDecoder().decode(opened)).toBe('hello envelope world');
  });

  it('uses a fresh random IV per call', async () => {
    const a = await aeadSeal(plaintext, key, aad);
    const b = await aeadSeal(plaintext, key, aad);
    expect(Array.from(a.iv)).not.toEqual(Array.from(b.iv));
  });

  it('fails on tag tamper', async () => {
    const sealed = await aeadSeal(plaintext, key, aad);
    sealed.tag[0] ^= 0x01;
    await expect(aeadOpen(sealed.ciphertext, sealed.iv, sealed.tag, key, aad)).rejects.toThrow();
  });

  it('fails on AAD mismatch', async () => {
    const sealed = await aeadSeal(plaintext, key, aad);
    const wrongAad = new TextEncoder().encode('ctx=other');
    await expect(
      aeadOpen(sealed.ciphertext, sealed.iv, sealed.tag, key, wrongAad),
    ).rejects.toThrow();
  });

  it('fails with wrong key', async () => {
    const sealed = await aeadSeal(plaintext, key, aad);
    const wrongKey = new Uint8Array(32).fill(0x55);
    await expect(
      aeadOpen(sealed.ciphertext, sealed.iv, sealed.tag, wrongKey, aad),
    ).rejects.toThrow();
  });
});
